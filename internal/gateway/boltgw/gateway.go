// Package boltgw is Countersign as a Neo4j gateway: drivers connect to it over Bolt, as to
// the database.
//
//   - Protect and block: each Cypher query is judged by the gateway policy (injection signs,
//     dynamic Cypher, file and network access, work split into separate transactions,
//     privileges, database administration, tampering with capture); each transaction is
//     judged again inside its commit, on what it actually changed.
//   - Undo: every transaction through the gateway carries a key in its metadata. An APOC
//     trigger the gateway installs runs inside the commit and sends the transaction's
//     changes, keyed, to the gateway, which stores them in the vault on a quorum and only
//     then answers. A refusal, or no quorum, fails the trigger, and the transaction does not
//     commit. Until the gateway has seen its trigger work, it refuses writes.
//
// Needs Neo4j 5 with APOC (apoc.trigger.enabled=true), and Bolt 5.1 or later.
package boltgw

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	n4 "undolayer/internal/connectors/neo4j"
	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

//go:embed policy.toml
var defaultPolicy string

// Route is one Neo4j gateway listener.
type Route struct {
	Name   string `toml:"name"`
	Listen string `toml:"listen"`
	// URI of the server with the gateway's own credentials: bolt://countersign:pw@db:7687
	URI      string `toml:"uri"`
	Database string `toml:"database"` // default neo4j
	// Callback: where the gateway listens for its trigger, and CallbackURL how the database
	// reaches it (e.g. http://gateway-host:7475/capture).
	Callback    string            `toml:"callback"`
	CallbackURL string            `toml:"callback_url"`
	Advertise   string            `toml:"advertise"` // the address drivers are routed to (default: listen)
	Mode        string            `toml:"mode"`
	Users       map[string]string `toml:"users"`
	Trust       bool              `toml:"trust"`
	Policy      string            `toml:"policy"`
}

type Gateway struct {
	R    Route
	M    *tx.Manager
	Conn *n4.Connector
	pol  *policy.Policy
	addr string
	user string
	pass string
	qc   qcache

	pending sync.Map // key -> *capture
	selfKey string
	healthy atomic.Bool
	selfOK  chan struct{}

	admin   neo4j.DriverWithContext
	httpSrv *http.Server
	closed  atomic.Bool
	stop    chan struct{}

	sizeMu sync.Mutex
	size   float64
	sizeAt time.Time

	stats struct{ queries, refused, commits atomic.Int64 }
}

// capture is one transaction through the gateway, as its trigger reported it.
type capture struct {
	mu      sync.Mutex
	user    string
	queries []string
	got     bool
	id      string
	batch   string
	refused string
}

func New(r Route, m *tx.Manager) (*Gateway, error) {
	if r.Name == "" || r.Listen == "" || r.URI == "" || r.Callback == "" || r.CallbackURL == "" {
		return nil, errors.New("[[neo4j_gateway]] needs name, listen, uri, callback and callback_url")
	}
	if r.Mode == "" {
		r.Mode = "enforce"
	}
	if r.Mode != "enforce" && r.Mode != "watch" {
		return nil, fmt.Errorf("[[neo4j_gateway]] %s: mode is enforce or watch", r.Name)
	}
	if r.Database == "" {
		r.Database = "neo4j"
	}
	if r.Advertise == "" {
		r.Advertise = r.Listen
	}
	u, err := url.Parse(r.URI)
	if err != nil || (u.Scheme != "bolt" && u.Scheme != "neo4j") || u.Host == "" {
		return nil, fmt.Errorf("[[neo4j_gateway]] %s: uri is bolt://user:password@host:7687", r.Name)
	}
	g := &Gateway{R: r, M: m, addr: u.Host, qc: qcache{m: map[string]*queryInfo{}}, stop: make(chan struct{}), selfOK: make(chan struct{}, 1)}
	if !strings.Contains(g.addr, ":") {
		g.addr += ":7687"
	}
	if u.User != nil {
		g.user = u.User.Username()
		g.pass, _ = u.User.Password()
	}
	if r.Trust {
		host, _, _ := net.SplitHostPort(r.Listen)
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("[[neo4j_gateway]] %s: trust is allowed only on a loopback address", r.Name)
		}
	} else if len(r.Users) == 0 {
		return nil, fmt.Errorf("[[neo4j_gateway]] %s: list users, or set trust on a loopback address", r.Name)
	}
	pol, err := policy.Parse(defaultPolicy)
	if err != nil {
		return nil, err
	}
	if r.Policy != "" {
		if pol, err = policy.Load(r.Policy); err != nil {
			return nil, err
		}
	}
	g.pol = pol
	g.selfKey = randKey()
	g.Conn = n4.New("gw-"+r.Name, "bolt://"+g.addr, g.user, g.pass)
	return g, nil
}

func randKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------- capture

// Install puts the trigger in place and waits until it has been seen to work.
func (g *Gateway) Install(wait time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), wait+30*time.Second)
	defer cancel()
	if g.admin == nil {
		d, err := neo4j.NewDriverWithContext("bolt://"+g.addr, neo4j.BasicAuth(g.user, g.pass, ""))
		if err != nil {
			return err
		}
		g.admin = d
	}
	_, err := neo4j.ExecuteQuery(ctx, g.admin, "CALL apoc.trigger.install($db, 'countersign', $stmt, {phase: 'before'})",
		map[string]any{"db": g.R.Database, "stmt": n4.TriggerStatement(g.R.CallbackURL)}, neo4j.EagerResultTransformer,
		neo4j.ExecuteQueryWithDatabase("system"))
	if err != nil {
		return fmt.Errorf("installing the capture trigger (is APOC installed, with apoc.trigger.enabled=true?): %v", err)
	}
	return g.selfTest(wait)
}

// selfTest commits a transaction that changes nothing in the end, and waits for its trigger
// to call back (APOC takes up to apoc.trigger.refresh to pick up a new trigger).
func (g *Gateway) selfTest(wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		sess := g.admin.NewSession(ctx, neo4j.SessionConfig{DatabaseName: g.R.Database})
		_, err := sess.ExecuteWrite(ctx, func(t neo4j.ManagedTransaction) (any, error) {
			r, err := t.Run(ctx, "CREATE (n:CountersignHealth) DELETE n", nil)
			if err != nil {
				return nil, err
			}
			return r.Consume(ctx)
		}, neo4j.WithTxMetadata(map[string]any{"countersign_key": g.selfKey}))
		sess.Close(ctx)
		cancel()
		if err == nil {
			select {
			case <-g.selfOK:
				g.healthy.Store(true)
				return nil
			case <-time.After(200 * time.Millisecond):
			}
		}
		if time.Now().After(deadline) {
			g.healthy.Store(false)
			if err != nil {
				return fmt.Errorf("the capture trigger did not work: %v", err)
			}
			return errors.New("the capture trigger did not call back (check apoc.trigger.enabled, and that the database reaches callback_url)")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (g *Gateway) graphSize() float64 {
	g.sizeMu.Lock()
	defer g.sizeMu.Unlock()
	if time.Since(g.sizeAt) < time.Minute {
		return g.size
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := neo4j.ExecuteQuery(ctx, g.admin, "MATCH (n) RETURN count(n)", nil, neo4j.EagerResultTransformer,
		neo4j.ExecuteQueryWithDatabase(g.R.Database), neo4j.ExecuteQueryWithReadersRouting())
	if err == nil && len(r.Records) > 0 {
		n, _ := r.Records[0].Values[0].(int64)
		g.size, g.sizeAt = float64(n), time.Now()
	}
	return g.size
}

// ServeHTTP is the trigger's callback: inside the commit, before it completes.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("X-Countersign-Key")
	body, err := io.ReadAll(io.LimitReader(r.Body, 512<<20))
	if err != nil {
		http.Error(w, "read", 400)
		return
	}
	if key != "" && subtle.ConstantTimeCompare([]byte(key), []byte(g.selfKey)) == 1 {
		select {
		case g.selfOK <- struct{}{}:
		default:
		}
		w.Write([]byte(`{"ok":true}`))
		return
	}
	v, ok := g.pending.Load(key)
	if !ok || key == "" {
		http.Error(w, `{"refused":"unknown transaction"}`, 403)
		return
	}
	c := v.(*capture)
	var p n4.Payload
	if err := json.Unmarshal(body, &p); err != nil {
		g.refuse(w, c, "the change could not be read: "+err.Error())
		return
	}
	changes := p.Changes()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = true
	if len(changes) == 0 {
		w.Write([]byte(`{"ok":true}`))
		return
	}
	nodesDel, relsDel, nodesNew := 0, 0, 0
	for _, e := range changes {
		switch {
		case !e.Rel && e.After == nil:
			nodesDel++
		case e.Rel && e.After == nil:
			relsDel++
		case !e.Rel && e.Before == nil:
			nodesNew++
		}
	}
	frac := 0.0
	if size := g.graphSize(); size >= 20 {
		frac = float64(nodesDel) / size
	}
	f := model.Facts{"entities_affected": len(changes), "nodes_deleted": nodesDel, "relationships_deleted": relsDel,
		"nodes_created": nodesNew, "graph_fraction_deleted": frac, "requester": c.user, "gateway": g.R.Name}
	if why := g.judge(c.user, &model.Action{Connector: "graph", Operation: "commit", Effect: model.Reversible, Facts: f}, "COMMIT"); why != "" {
		g.refuseLocked(w, c, why)
		return
	}
	if g.M.Vault == nil {
		g.refuseLocked(w, c, "the vault is disabled, so no before state can be kept")
		return
	}
	raw, _ := json.Marshal(n4.UndoRecord{DB: g.R.Database, Entities: changes})
	rows, _ := g.Conn.DescribeRows(raw)
	id := "gwn_" + randKey()[:12]
	rc, err := g.M.Vault.Append(vault.Entry{Tx: id, Task: clip("gateway "+g.R.Name+": "+strings.Join(c.queries, "; "), 500),
		Requester: c.user, Connector: g.Conn.Name(), Phase: "intent", Rows: rows, Undo: raw})
	if err != nil {
		g.refuseLocked(w, c, "the vault could not store the before state: "+err.Error())
		return
	}
	c.id, c.batch = id, rc.Batch
	w.Write([]byte(`{"ok":true}`))
}

func (g *Gateway) refuse(w http.ResponseWriter, c *capture, why string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g.refuseLocked(w, c, why)
}

func (g *Gateway) refuseLocked(w http.ResponseWriter, c *capture, why string) {
	c.got, c.refused = true, why
	b, _ := json.Marshal(map[string]string{"refused": why})
	http.Error(w, string(b), 403)
}

func (g *Gateway) judge(user string, a *model.Action, what string) string {
	g.pol.Evaluate(a)
	if a.Decision != model.Deny && a.Decision != model.RequireApproval {
		return ""
	}
	reason := strings.Join(a.Reasons, "; ")
	g.M.Audit.Note("gateway_refused", map[string]any{"gateway": g.R.Name, "user": user, "query": clip(what, 2000),
		"reason": reason, "mode": g.R.Mode})
	if g.R.Mode == "watch" {
		return ""
	}
	g.stats.refused.Add(1)
	return reason
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// settle records how a captured transaction ended.
func (g *Gateway) settle(c *capture, committed, wrote bool) {
	c.mu.Lock()
	id, batch, got := c.id, c.batch, c.got
	c.mu.Unlock()
	if committed && wrote && !got {
		// committed with changes and no call from the trigger: capture is broken
		g.healthy.Store(false)
		g.M.Audit.Note("gateway_uncaptured_commit", map[string]any{"gateway": g.R.Name, "user": c.user,
			"queries": c.queries, "reason": "the capture trigger did not run; writes are refused until it works again"})
		go func() { _ = g.Install(60 * time.Second) }()
	}
	if batch == "" {
		return
	}
	phase := "committed"
	if !committed {
		phase = "failed"
	}
	g.stats.commits.Add(1)
	g.M.Audit.Note("gateway_commit", map[string]any{"tx": id, "gateway": g.R.Name, "user": c.user, "outcome": phase})
	g.M.Vault.AppendLater(vault.Entry{Tx: id, Requester: c.user, Connector: g.Conn.Name(), Phase: phase, Ref: batch})
}

// ---------------------------------------------------------------- serving

// Serve starts the callback listener, installs capture, then accepts connections.
func (g *Gateway) Serve(l net.Listener) error {
	hl, err := net.Listen("tcp", g.R.Callback)
	if err != nil {
		return fmt.Errorf("callback: %v", err)
	}
	g.httpSrv = &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = g.httpSrv.Serve(hl) }()
	if err := g.Install(90 * time.Second); err != nil {
		if g.R.Mode != "watch" {
			g.M.Audit.Note("gateway_capture_failed", map[string]any{"gateway": g.R.Name, "error": err.Error()})
		}
	}
	go func() { // capture is checked again every half minute
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-g.stop:
				return
			case <-t.C:
				if err := g.selfTest(5 * time.Second); err != nil {
					_ = g.Install(60 * time.Second)
				}
			}
		}
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if g.closed.Load() {
				return nil
			}
			return err
		}
		go g.handle(c)
	}
}

func (g *Gateway) Close() {
	if g.closed.CompareAndSwap(false, true) {
		close(g.stop)
		if g.httpSrv != nil {
			_ = g.httpSrv.Close()
		}
		if g.admin != nil {
			_ = g.admin.Close(context.Background())
		}
	}
	if g.M.Vault != nil {
		_ = g.M.Vault.Flush()
	}
}

// Bolt message tags
const (
	mHello, mGoodbye, mReset, mRun, mBegin, mCommit, mRollback = 0x01, 0x02, 0x0F, 0x10, 0x11, 0x12, 0x13
	mDiscard, mPull, mTelemetry, mRoute, mLogon, mLogoff       = 0x2F, 0x3F, 0x54, 0x66, 0x6A, 0x6B
	rSuccess, rRecord, rIgnored, rFailure                      = 0x70, 0x71, 0x7E, 0x7F
)

type session struct {
	g      *Gateway
	c      net.Conn
	cw     *bufio.Writer
	up     net.Conn
	user   string
	authed bool
	failed bool // the gateway refused something: everything is ignored until RESET

	inTx  bool
	tx    *capture
	txKey string
	wrote bool
	auto  *capture // an auto-commit query, until its results are consumed
	autoK string
}

func (g *Gateway) handle(c net.Conn) {
	defer c.Close()
	var hs [20]byte
	if _, err := io.ReadFull(c, hs[:]); err != nil || binary.BigEndian.Uint32(hs[:4]) != 0x6060B017 {
		return
	}
	// only Bolt 5.1 and later (credentials in LOGON), never the manifest negotiation
	var out [20]byte
	copy(out[:4], hs[:4])
	k := 4
	for i := 0; i < 4; i++ {
		p := hs[4+4*i : 8+4*i]
		if p[3] == 5 && p[2] >= 1 {
			rng := p[1]
			if rng > p[2]-1 {
				rng = p[2] - 1 // not down to 5.0
			}
			copy(out[k:], []byte{0, rng, p[2], 5})
			k += 4
		}
	}
	up, err := net.DialTimeout("tcp", g.addr, 15*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(out[:]); err != nil {
		return
	}
	var ver [4]byte
	if _, err := io.ReadFull(up, ver[:]); err != nil {
		return
	}
	if ver[3] != 5 || ver[2] < 1 {
		_, _ = c.Write([]byte{0, 0, 0, 0})
		return
	}
	if _, err := c.Write(ver[:]); err != nil {
		return
	}
	s := &session{g: g, c: c, cw: bufio.NewWriterSize(c, 64<<10), up: up}
	if g.R.Trust {
		s.user = "trusted"
	}
	for {
		msg, err := readMessage(c)
		if err != nil {
			return
		}
		if err := s.serve(msg); err != nil {
			return
		}
	}
}

func (s *session) toClient(msg []byte) error {
	_, err := s.cw.Write(frame(msg))
	return err
}

func (s *session) flush() error { return s.cw.Flush() }

func (s *session) toUp(v any) error {
	_, err := s.up.Write(frame(encode(v)))
	return err
}

func failure(code, msg string) []byte {
	return encode(&Struct{Tag: rFailure, Fields: []any{map[string]any{"code": code, "message": msg}}})
}

// relay passes the server's records to the client and returns its summary, unsent.
func (s *session) relay() ([]byte, error) {
	for {
		m, err := readMessage(s.up)
		if err != nil {
			return nil, err
		}
		if tagOf(m) == rRecord {
			if err := s.toClient(m); err != nil {
				return nil, err
			}
			continue
		}
		return m, nil
	}
}

func (s *session) forward(st *Struct) ([]byte, error) {
	if err := s.toUp(st); err != nil {
		return nil, err
	}
	return s.relay()
}

func (s *session) send(m []byte) error {
	if err := s.toClient(m); err != nil {
		return err
	}
	return s.flush()
}

func (s *session) refused(why string) error {
	s.failed = true
	return s.send(failure("Neo.ClientError.Security.Forbidden", "refused by Countersign: "+why))
}

func summaryMap(m []byte) map[string]any {
	v, err := decode(m)
	if err != nil {
		return nil
	}
	st, ok := v.(*Struct)
	if !ok || len(st.Fields) == 0 {
		return nil
	}
	mm, _ := st.Fields[0].(map[string]any)
	return mm
}

func wroteIn(m []byte) bool {
	sm := summaryMap(m)
	stats, _ := sm["stats"].(map[string]any)
	if b, ok := stats["contains-updates"].(bool); ok && b {
		return true
	}
	for k, v := range stats {
		if n, ok := v.(int64); ok && n > 0 && k != "contains-system-updates" && k != "system-updates" {
			return true
		}
	}
	return false
}

func (s *session) serve(msg []byte) error {
	v, err := decode(msg)
	if err != nil {
		return err
	}
	st, ok := v.(*Struct)
	if !ok {
		return errors.New("not a message")
	}
	if s.failed && st.Tag != mReset && st.Tag != mGoodbye {
		return s.send(encode(&Struct{Tag: rIgnored}))
	}
	g := s.g
	switch st.Tag {
	case mHello:
		if len(st.Fields) > 0 {
			if m, ok := st.Fields[0].(map[string]any); ok {
				delete(m, "scheme")
				delete(m, "principal")
				delete(m, "credentials")
			}
		}
		r, err := s.forward(st)
		if err != nil {
			return err
		}
		return s.send(r)
	case mLogon:
		m, _ := st.Fields[0].(map[string]any)
		user, _ := m["principal"].(string)
		pass, _ := m["credentials"].(string)
		if !g.R.Trust && !g.checkUser(user, pass) {
			g.M.Audit.Note("gateway_auth_failed", map[string]any{"gateway": g.R.Name, "user": user})
			_ = s.send(failure("Neo.ClientError.Security.Unauthorized", "The client is unauthorized due to authentication failure."))
			return errors.New("authentication failed")
		}
		if !g.R.Trust {
			s.user = user
		}
		r, err := s.forward(&Struct{Tag: mLogon, Fields: []any{map[string]any{"scheme": "basic", "principal": g.user, "credentials": g.pass}}})
		if err != nil {
			return err
		}
		if tagOf(r) == rSuccess {
			s.authed = true
		}
		return s.send(r)
	case mLogoff:
		s.authed = false
	case mGoodbye:
		_ = s.toUp(st)
		return io.EOF
	case mReset:
		s.failed = false
		s.endTx()
		s.endAuto(false, false)
	}
	if !s.authed && st.Tag != mReset && st.Tag != mLogoff && st.Tag != mTelemetry {
		return s.send(failure("Neo.ClientError.Security.Unauthorized", "log in first"))
	}
	switch st.Tag {
	case mRoute:
		db := g.R.Database
		if len(st.Fields) > 2 {
			if ex, ok := st.Fields[2].(map[string]any); ok {
				if d, ok := ex["db"].(string); ok && d != "" {
					db = d
				}
			}
		}
		addr := []any{g.R.Advertise}
		rt := map[string]any{"ttl": int64(300), "db": db, "servers": []any{
			map[string]any{"addresses": addr, "role": "WRITE"}, map[string]any{"addresses": addr, "role": "READ"},
			map[string]any{"addresses": addr, "role": "ROUTE"}}}
		return s.send(encode(&Struct{Tag: rSuccess, Fields: []any{map[string]any{"rt": rt}}}))
	case mBegin:
		extra := map[string]any{}
		if len(st.Fields) > 0 {
			if m, ok := st.Fields[0].(map[string]any); ok {
				extra = m
			}
		}
		if why := s.checkExtra(extra); why != "" {
			return s.refused(why)
		}
		key := randKey()
		s.tagTx(extra, key)
		c := &capture{user: s.user}
		g.pending.Store(key, c)
		r, err := s.forward(&Struct{Tag: mBegin, Fields: []any{extra}})
		if err != nil {
			g.pending.Delete(key)
			return err
		}
		if tagOf(r) == rSuccess {
			s.inTx, s.tx, s.txKey, s.wrote = true, c, key, false
		} else {
			g.pending.Delete(key)
		}
		return s.send(r)
	case mRun:
		q, _ := st.Fields[0].(string)
		qi := g.qc.get(q)
		g.stats.queries.Add(1)
		if why := s.decide(qi); why != "" {
			return s.refused(why)
		}
		if qi.write && !g.healthy.Load() && g.R.Mode != "watch" {
			return s.refused("capture is not working yet, so writes cannot be recorded (see the gateway's audit log)")
		}
		if s.inTx {
			s.tx.mu.Lock()
			s.tx.queries = append(s.tx.queries, clip(q, 4000))
			s.tx.mu.Unlock()
			r, err := s.forward(st)
			if err != nil {
				return err
			}
			return s.send(r)
		}
		// auto-commit: the gateway's key goes with it; it commits when its results are consumed
		extra := map[string]any{}
		if len(st.Fields) > 2 {
			if m, ok := st.Fields[2].(map[string]any); ok {
				extra = m
			}
		}
		if why := s.checkExtra(extra); why != "" {
			return s.refused(why)
		}
		key := randKey()
		s.tagTx(extra, key)
		c := &capture{user: s.user, queries: []string{clip(q, 4000)}}
		g.pending.Store(key, c)
		fields := append([]any{}, st.Fields...)
		for len(fields) < 3 {
			fields = append(fields, map[string]any{})
		}
		fields[2] = extra
		r, err := s.forward(&Struct{Tag: mRun, Fields: fields})
		if err != nil {
			g.pending.Delete(key)
			return err
		}
		if tagOf(r) == rSuccess {
			s.auto, s.autoK, s.wrote = c, key, false
		} else {
			g.pending.Delete(key)
		}
		return s.send(r)
	case mPull, mDiscard:
		r, err := s.forward(st)
		if err != nil {
			return err
		}
		if wroteIn(r) {
			s.wrote = true
		}
		if s.auto != nil {
			sm := summaryMap(r)
			more, _ := sm["has_more"].(bool)
			switch {
			case tagOf(r) == rFailure:
				r = s.rewrite(r, s.auto)
				s.endAuto(false, s.wrote)
			case !more:
				s.endAuto(true, s.wrote)
			}
		}
		return s.send(r)
	case mCommit:
		r, err := s.forward(st)
		if err != nil {
			return err
		}
		if s.tx != nil {
			ok := tagOf(r) == rSuccess
			if !ok {
				r = s.rewrite(r, s.tx)
			}
			g.settle(s.tx, ok, s.wrote)
		}
		s.endTx()
		return s.send(r)
	case mRollback:
		r, err := s.forward(st)
		if err != nil {
			return err
		}
		s.endTx()
		return s.send(r)
	}
	r, err := s.forward(st)
	if err != nil {
		return err
	}
	return s.send(r)
}

// rewrite gives the client the gateway's reason when it refused the commit.
func (s *session) rewrite(r []byte, c *capture) []byte {
	c.mu.Lock()
	why := c.refused
	c.mu.Unlock()
	if why == "" {
		return r
	}
	return failure("Neo.ClientError.Security.Forbidden", "refused by Countersign: "+why+"; the transaction was rolled back")
}

func (s *session) endTx() {
	if s.txKey != "" {
		s.g.pending.Delete(s.txKey)
	}
	s.inTx, s.tx, s.txKey, s.wrote = false, nil, "", false
}

func (s *session) endAuto(committed, wrote bool) {
	if s.auto != nil {
		s.g.settle(s.auto, committed, wrote)
		s.g.pending.Delete(s.autoK)
	}
	s.auto, s.autoK = nil, ""
}

// tagTx puts the gateway's key in the transaction's metadata (replacing anything a client
// put there under the same name).
func (s *session) tagTx(extra map[string]any, key string) {
	md, _ := extra["tx_metadata"].(map[string]any)
	if md == nil {
		md = map[string]any{}
	}
	md["countersign_key"] = key
	extra["tx_metadata"] = md
}

func (s *session) checkExtra(extra map[string]any) string {
	if u, ok := extra["imp_user"].(string); ok && u != "" {
		return "impersonating another user is not done through this gateway"
	}
	if d, ok := extra["db"].(string); ok && d != "" && !strings.EqualFold(d, s.g.R.Database) {
		return "only the " + s.g.R.Database + " database is captured through this gateway"
	}
	return ""
}

func (s *session) decide(qi *queryInfo) string {
	f := model.Facts{}
	for k, v := range qi.facts {
		f[k] = v
	}
	f["requester"], f["gateway"] = s.user, s.g.R.Name
	eff, op := model.Read, "query"
	if qi.write {
		eff, op = model.Reversible, "execute"
	}
	return s.g.judge(s.user, &model.Action{Connector: "graph", Operation: op, Effect: eff, Facts: f}, qi.text)
}

func (g *Gateway) checkUser(user, pass string) bool {
	want, ok := g.R.Users[user]
	a, b := sha256.Sum256([]byte(pass)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1 && ok
}
