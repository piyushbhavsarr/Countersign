// Package pggw is Countersign as a PostgreSQL gateway: it speaks the PostgreSQL protocol,
// so applications and agents connect to it as to the database, and every statement passes
// through it.
//
//   - Protect: each statement is classified from PostgreSQL's own parse tree (cached by
//     text, so a repeated statement costs a map lookup), with its injection signs and
//     shape; which server a session uses (the main database or a replica, by role and
//     lag) is the gateway's choice, and it follows a failover.
//   - Block: a refused statement is answered by the database itself raising the error
//     (undolayer.refuse), so the client sees exactly the protocol and transaction state
//     of any failed statement. A transaction that changed too much is refused at its
//     COMMIT, after the change was measured and before anything was kept.
//   - Undo: rows are captured by the capture triggers (undolayer pg install) as the
//     statements run. Before COMMIT is passed on, the before state of every row is
//     stored in the vault on a quorum of replicas; no quorum, no commit. undo, restore and
//     revert then work on gateway transactions as on any other.
//
// Reads pay none of this: they are relayed message by message, with the decision cached
// per statement. Writes pay one extra round trip at COMMIT and one vault write (shared with
// every other commit in flight).
package pggw

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"undolayer/internal/connectors/postgres"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

//go:embed policy.toml
var defaultPolicy string

// Route is one gateway listener in front of one database.
type Route struct {
	Name    string `toml:"name"`
	Listen  string `toml:"listen"`  // e.g. 127.0.0.1:6432
	Primary string `toml:"primary"` // DSN of the main database, with the gateway's own credentials
	// Replicas: DSNs of read replicas. Sessions of ReadOnlyUsers go to the least lagging
	// healthy one; if the main database fails over to one of them, writes follow it.
	Replicas      []string `toml:"replicas"`
	ReadOnlyUsers []string `toml:"read_only_users"`
	MaxReplicaLag string   `toml:"max_replica_lag"` // default 10s
	// Mode: enforce (default) refuses what policy refuses; watch refuses nothing and
	// audits what it would have refused (to learn an application's traffic first).
	Mode string `toml:"mode"`
	// Users: who may connect, and their passwords (SCRAM-SHA-256). Trust lets anyone in
	// as any user without a password; allowed only on a loopback address.
	Users map[string]string `toml:"users"`
	Trust bool              `toml:"trust"`
	// TLS for clients.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
	// Policy: a policy file for this gateway's traffic (default: the built-in gateway policy).
	Policy string `toml:"policy"`
	// MaxCaptureRows: a transaction changing more rows than this is refused at COMMIT, since
	// its before state would not fit the vault in one go (default 1,000,000).
	MaxCaptureRows int `toml:"max_capture_rows"`
	// PoolSize: idle server connections kept per server for reuse (default 16).
	PoolSize int `toml:"pool_size"`
}

// Gateway serves one route.
type Gateway struct {
	R      Route
	M      *tx.Manager
	Conn   *postgres.Connector // the hidden connector undo and restore use
	pol    *policy.Policy
	tlsCfg *tls.Config
	users  map[string]*scramVerifier
	maxLag time.Duration

	topo  *topology
	pools sync.Map // dsn -> *pool

	sessMu   sync.Mutex
	sessions map[uint32]*session

	analyze *stmtCache
	pk      *pkCache
	shapes  shapeSet
	bg      sync.WaitGroup // background vault writes
	stats   gwStats
	closed  atomic.Bool
}

type gwStats struct {
	sessions, statements, refused, commits, captured atomic.Int64
}

// New prepares a gateway; the database must have capture installed (undolayer pg install).
func New(r Route, m *tx.Manager) (*Gateway, error) {
	if r.Name == "" || r.Listen == "" || r.Primary == "" {
		return nil, errors.New("[[pg_gateway]] needs name, listen and primary")
	}
	if r.Mode == "" {
		r.Mode = "enforce"
	}
	if r.Mode != "enforce" && r.Mode != "watch" {
		return nil, fmt.Errorf("[[pg_gateway]] %s: mode is enforce or watch", r.Name)
	}
	if r.MaxCaptureRows <= 0 {
		r.MaxCaptureRows = 1_000_000
	}
	if r.PoolSize <= 0 {
		r.PoolSize = 16
	}
	g := &Gateway{R: r, M: m, sessions: map[uint32]*session{}, users: map[string]*scramVerifier{},
		analyze: &stmtCache{m: map[string]*stmtInfo{}}, pk: &pkCache{m: map[string]pkEntry{}}, maxLag: 10 * time.Second,
		shapes: shapeSet{m: map[string]bool{}}}
	if r.MaxReplicaLag != "" {
		d, err := time.ParseDuration(r.MaxReplicaLag)
		if err != nil {
			return nil, fmt.Errorf("max_replica_lag: %v", err)
		}
		g.maxLag = d
	}
	if r.Trust {
		host, _, _ := net.SplitHostPort(r.Listen)
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("[[pg_gateway]] %s: trust is allowed only on a loopback address", r.Name)
		}
	} else if len(r.Users) == 0 {
		return nil, fmt.Errorf("[[pg_gateway]] %s: list users (and passwords), or set trust on a loopback address", r.Name)
	}
	for u, p := range r.Users {
		v, err := newVerifier(p)
		if err != nil {
			return nil, err
		}
		g.users[u] = v
	}
	if r.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(r.TLSCert, r.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("[[pg_gateway]] %s tls: %v", r.Name, err)
		}
		g.tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
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
	g.Conn = postgres.New(r.Primary)
	g.Conn.ConnName, g.Conn.Hide = "gw-"+r.Name, true
	if err := g.checkInstalled(); err != nil {
		return nil, err
	}
	g.topo = newTopology(g, r.Primary, r.Replicas)
	return g, nil
}

func (g *Gateway) checkInstalled() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := pgx.Connect(ctx, g.R.Primary)
	if err != nil {
		return fmt.Errorf("[[pg_gateway]] %s: %v", g.R.Name, err)
	}
	defer c.Close(ctx)
	var ok bool
	if err := c.QueryRow(ctx, `SELECT to_regprocedure('undolayer.refuse(text,text)') IS NOT NULL AND
		to_regprocedure('undolayer.capture()') IS NOT NULL`).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("[[pg_gateway]] %s: capture is not installed in that database: run undolayer pg install", g.R.Name)
	}
	return nil
}

// Serve accepts connections until l is closed.
func (g *Gateway) Serve(l net.Listener) error {
	go g.topo.run()
	defer g.topo.stop()
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

// Close stops accepting (sessions in progress finish on their own) and waits for the
// background vault writes.
func (g *Gateway) Close() {
	g.closed.Store(true)
	g.bg.Wait()
	if g.M.Vault != nil {
		_ = g.M.Vault.Flush()
	}
}

func randKey() (uint32, []byte) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return binary.BigEndian.Uint32(b[:4]) &^ (1 << 31), b[4:]
}

func (g *Gateway) handle(c net.Conn) {
	defer c.Close()
	var conn net.Conn = c
	be := pgproto3.NewBackend(conn, conn)
	var startup *pgproto3.StartupMessage
	for startup == nil {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest:
			if g.tlsCfg == nil {
				_, _ = conn.Write([]byte("N"))
				continue
			}
			if _, err := conn.Write([]byte("S")); err != nil {
				return
			}
			tc := tls.Server(c, g.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn = tc
			be = pgproto3.NewBackend(conn, conn)
		case *pgproto3.GSSEncRequest:
			_, _ = conn.Write([]byte("N"))
		case *pgproto3.CancelRequest:
			g.cancel(m.ProcessID, m.SecretKey)
			return
		case *pgproto3.StartupMessage:
			startup = m
		default:
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})
	user := startup.Parameters["user"]
	fail := func(code, msg string) {
		be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: msg})
		_ = be.Flush()
	}
	if err := g.authenticate(be, user); err != nil {
		fail("28P01", err.Error())
		return
	}
	if db := startup.Parameters["database"]; db != "" && db != g.dbName() {
		fail("3D000", fmt.Sprintf("this gateway serves database %q", g.dbName()))
		return
	}
	readOnly := contains(g.R.ReadOnlyUsers, user)
	target, err := g.topo.target(readOnly)
	if err != nil {
		fail("57P03", err.Error())
		return
	}
	up, err := g.pool(target).get()
	if err != nil {
		fail("08006", "the gateway could not reach the database: "+err.Error())
		return
	}
	s := newSession(g, conn, be, up, user, readOnly, target)
	if err := s.start(startup.Parameters); err != nil {
		up.close()
		fail("08006", err.Error())
		return
	}
	g.stats.sessions.Add(1)
	s.run()
}

func (g *Gateway) dbName() string {
	cfg, err := pgconn.ParseConfig(g.R.Primary)
	if err != nil {
		return ""
	}
	return cfg.Database
}

func (g *Gateway) authenticate(be *pgproto3.Backend, user string) error {
	if user == "" {
		return errors.New("no user given")
	}
	if g.R.Trust {
		be.Send(&pgproto3.AuthenticationOk{})
		return nil
	}
	v := g.users[user]
	if v == nil { // run the exchange anyway, so a missing user looks like a wrong password
		v, _ = newVerifier(string(randBytes(16)))
	}
	be.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
	if err := be.Flush(); err != nil {
		return err
	}
	if err := be.SetAuthType(pgproto3.AuthTypeSASL); err != nil {
		return err
	}
	msg, err := be.Receive()
	if err != nil {
		return err
	}
	init, ok := msg.(*pgproto3.SASLInitialResponse)
	if !ok || init.AuthMechanism != "SCRAM-SHA-256" {
		return errors.New("expected SCRAM-SHA-256")
	}
	ss := &scramServer{v: v}
	sf, err := ss.first(string(init.Data))
	if err != nil {
		return err
	}
	be.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(sf)})
	if err := be.Flush(); err != nil {
		return err
	}
	if err := be.SetAuthType(pgproto3.AuthTypeSASLContinue); err != nil {
		return err
	}
	msg, err = be.Receive()
	if err != nil {
		return err
	}
	resp, ok := msg.(*pgproto3.SASLResponse)
	if !ok {
		return errors.New("expected a SASL response")
	}
	fin, err := ss.final(string(resp.Data))
	if err != nil || g.users[user] == nil {
		return errors.New("password authentication failed for user " + user)
	}
	be.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte(fin)})
	be.Send(&pgproto3.AuthenticationOk{})
	return nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// cancel forwards a client's cancel request to the server running its query.
func (g *Gateway) cancel(pid uint32, key []byte) {
	g.sessMu.Lock()
	s := g.sessions[pid]
	g.sessMu.Unlock()
	if s == nil || string(s.key) != string(key) {
		return
	}
	s.up.cancel()
}

// ---------------------------------------------------------------- server connections

// upstream is one server connection the gateway speaks the protocol on directly.
type upstream struct {
	dsn    string
	conn   net.Conn
	fe     *pgproto3.Frontend
	pid    uint32
	key    []byte
	params map[string]string
	cfg    *pgconn.Config
	// one reader for the connection's whole life (sessions come and go; the pool reuses
	// it): each message is handed over on in and the next is read only after ack
	in  chan upMsg
	ack chan struct{}
}

func (u *upstream) startReader() {
	u.in, u.ack = make(chan upMsg), make(chan struct{})
	go func() {
		for {
			m, err := u.fe.Receive()
			u.in <- upMsg{m, err}
			if err != nil {
				close(u.in)
				return
			}
			<-u.ack
		}
	}()
}

// recv takes the next message (and acks it: the caller must be done with it before the
// next recv; messages are reused).
func (u *upstream) recv() (pgproto3.BackendMessage, error) {
	um, ok := <-u.in
	if !ok {
		return nil, errors.New("server connection closed")
	}
	if um.err != nil {
		return nil, um.err
	}
	return um.msg, nil
}

func (u *upstream) done() { u.ack <- struct{}{} }

func dial(dsn string) (*upstream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pc, err := pgconn.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	// capture: every row this session changes is logged, in a table that empties itself
	// at each commit; refused statements are raised by the server
	if err := pc.Exec(ctx, captureSetup).Close(); err != nil {
		pc.Close(ctx)
		return nil, err
	}
	h, err := pc.Hijack()
	if err != nil {
		return nil, err
	}
	u := &upstream{dsn: dsn, conn: h.Conn, fe: pgproto3.NewFrontend(h.Conn, h.Conn), pid: h.PID, key: h.SecretKey,
		params: h.ParameterStatuses, cfg: h.Config}
	u.startReader()
	return u, nil
}

// captureSetup makes a session capture. It is run when the connection is made and again
// before each transaction that writes (DISCARD ALL or RESET by a client would undo it).
const captureSetup = `CREATE TEMP TABLE IF NOT EXISTS undolayer_log(seq bigserial PRIMARY KEY, tbl text, op text,
  old_row jsonb, new_row jsonb) ON COMMIT DELETE ROWS; SELECT set_config('undolayer.tx', 'gateway', false)`

func (u *upstream) close() { _ = u.conn.Close() }

// cancel sends PostgreSQL's cancel request for this connection's running query.
func (u *upstream) cancel() {
	if u.cfg == nil {
		return
	}
	addr := net.JoinHostPort(u.cfg.Host, fmt.Sprint(u.cfg.Port))
	if strings.HasPrefix(u.cfg.Host, "/") {
		addr = fmt.Sprintf("%s/.s.PGSQL.%d", u.cfg.Host, u.cfg.Port)
	}
	network := "tcp"
	if strings.HasPrefix(addr, "/") {
		network = "unix"
	}
	c, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	b, _ := (&pgproto3.CancelRequest{ProcessID: u.pid, SecretKey: u.key}).Encode(nil)
	_, _ = c.Write(b)
	_, _ = io.Copy(io.Discard, c)
}

type pool struct {
	dsn  string
	size int
	mu   sync.Mutex
	idle []*upstream
}

func (g *Gateway) pool(dsn string) *pool {
	if p, ok := g.pools.Load(dsn); ok {
		return p.(*pool)
	}
	p, _ := g.pools.LoadOrStore(dsn, &pool{dsn: dsn, size: g.R.PoolSize})
	return p.(*pool)
}

func (p *pool) get() (*upstream, error) {
	p.mu.Lock()
	if n := len(p.idle); n > 0 {
		u := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return u, nil
	}
	p.mu.Unlock()
	return dial(p.dsn)
}

// put returns a connection reset to a clean session (DISCARD ALL, capture set up again).
func (p *pool) put(u *upstream, clean bool) {
	if !clean {
		u.close()
		return
	}
	u.fe.Send(&pgproto3.Query{String: "DISCARD ALL; " + captureSetup})
	if err := u.fe.Flush(); err != nil {
		u.close()
		return
	}
	for {
		msg, err := u.recv()
		if err != nil {
			u.close()
			return
		}
		_, bad := msg.(*pgproto3.ErrorResponse)
		r, rfq := msg.(*pgproto3.ReadyForQuery)
		idle := rfq && r.TxStatus == 'I'
		u.done()
		if bad {
			u.close()
			return
		}
		if rfq {
			if !idle {
				u.close()
				return
			}
			break
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.idle) >= p.size {
		u.close()
		return
	}
	p.idle = append(p.idle, u)
}

// ---------------------------------------------------------------- topology

// topology knows which server is the main database and how far each replica lags,
// checked every two seconds (and at once when a session finds the main one read-only).
type topology struct {
	g       *Gateway
	hosts   []string
	mu      sync.Mutex
	primary string
	split   bool
	lag     map[string]time.Duration
	healthy map[string]bool
	rr      int
	stopCh  chan struct{}
	checked bool
}

func newTopology(g *Gateway, primary string, replicas []string) *topology {
	t := &topology{g: g, hosts: append([]string{primary}, replicas...), primary: primary,
		lag: map[string]time.Duration{}, healthy: map[string]bool{}, stopCh: make(chan struct{})}
	t.check()
	return t
}

func (t *topology) run() {
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-tk.C:
			t.check()
		}
	}
}

func (t *topology) stop() {
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
}

func (t *topology) check() {
	type res struct {
		dsn      string
		ok       bool
		recovery bool
		lag      time.Duration
	}
	out := make([]res, len(t.hosts))
	var wg sync.WaitGroup
	for i, h := range t.hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			r := res{dsn: h}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := pgx.Connect(ctx, h)
			if err != nil {
				out[i] = r
				return
			}
			defer c.Close(ctx)
			var lagSec *float64
			if err := c.QueryRow(ctx, `SELECT pg_is_in_recovery(),
				CASE WHEN pg_is_in_recovery() THEN extract(epoch FROM now() - pg_last_xact_replay_timestamp()) END`).Scan(&r.recovery, &lagSec); err != nil {
				out[i] = r
				return
			}
			r.ok = true
			if lagSec != nil {
				r.lag = time.Duration(*lagSec * float64(time.Second))
			}
			out[i] = r
		}(i, h)
	}
	wg.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.checked = true
	var primaries []string
	for _, r := range out {
		t.healthy[r.dsn] = r.ok
		t.lag[r.dsn] = r.lag
		if r.ok && !r.recovery {
			primaries = append(primaries, r.dsn)
		}
	}
	switch len(primaries) {
	case 1:
		t.primary, t.split = primaries[0], false
	case 0:
		t.primary, t.split = "", false
	default: // two servers both accept writes: neither is used for writes
		t.primary, t.split = "", true
	}
}

// target picks the server for a new session.
func (t *topology) target(readOnly bool) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if readOnly {
		var best []string
		for _, h := range t.hosts[1:] {
			if t.healthy[h] && t.lag[h] <= t.g.maxLag {
				best = append(best, h)
			}
		}
		if len(best) > 0 {
			t.rr++
			return best[t.rr%len(best)], nil
		}
		if t.primary != "" { // no replica fit to read from: the main database serves reads too
			return t.primary, nil
		}
	}
	switch {
	case t.split:
		return "", errors.New("two servers both claim to be the main database (split brain); writes are refused until it is resolved")
	case t.primary == "":
		return "", errors.New("no main database is reachable (failover in progress?); try again shortly")
	}
	return t.primary, nil
}

func (t *topology) isPrimary(dsn string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return dsn == t.primary
}

// waitBG waits for the background vault writes (tests, shutdown).
func (g *Gateway) waitBG() error {
	g.bg.Wait()
	if g.M.Vault != nil {
		return g.M.Vault.Flush()
	}
	return nil
}
