package pggw

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/jackc/pgx/v5/pgproto3"

	"undolayer/internal/connectors/postgres"
	"undolayer/internal/model"
)

// ---------------------------------------------------------------- statements

// kinds of statement, as far as the gateway's handling goes
const (
	kRead     = "read"
	kWrite    = "write"
	kBegin    = "begin"
	kCommit   = "commit"
	kRollback = "rollback"
	kTxOther  = "tx_other"  // SAVEPOINT, RELEASE, ROLLBACK TO: inside a transaction
	kNoTx     = "no_tx"     // cannot run inside a transaction block (VACUUM, CREATE INDEX CONCURRENTLY, ...)
	kTwoPhase = "two_phase" // PREPARE TRANSACTION / COMMIT PREPARED: refused
)

type stmtInfo struct {
	text   string
	kind   string
	resets bool     // DISCARD or RESET ALL: the capture setup must be made again
	parts  []string // a multi-statement query, split
	kinds  []string
	facts  model.Facts
	err    string // the text does not parse: the server will say why
}

type stmtCache struct {
	mu sync.RWMutex
	m  map[string]*stmtInfo
}

const stmtCacheSize = 16384

func (c *stmtCache) get(text string) *stmtInfo {
	c.mu.RLock()
	if si := c.m[text]; si != nil {
		c.mu.RUnlock()
		return si
	}
	c.mu.RUnlock()
	si := classify(text)
	c.mu.Lock()
	if len(c.m) >= stmtCacheSize {
		c.m = map[string]*stmtInfo{}
	}
	c.m[text] = si
	c.mu.Unlock()
	return si
}

func kindOf(stmt map[string]any) string {
	for top, v := range stmt {
		n, _ := v.(map[string]any)
		switch top {
		case "TransactionStmt":
			switch n["kind"] {
			case "TRANS_STMT_BEGIN", "TRANS_STMT_START":
				return kBegin
			case "TRANS_STMT_COMMIT":
				return kCommit
			case "TRANS_STMT_ROLLBACK":
				return kRollback
			case "TRANS_STMT_PREPARE", "TRANS_STMT_COMMIT_PREPARED", "TRANS_STMT_ROLLBACK_PREPARED":
				return kTwoPhase
			}
			return kTxOther
		case "VacuumStmt", "CreatedbStmt", "DropdbStmt", "AlterSystemStmt", "CreateTableSpaceStmt", "DropTableSpaceStmt":
			return kNoTx
		case "IndexStmt":
			if n["concurrent"] == true {
				return kNoTx
			}
		case "ReindexStmt":
			if b, _ := json.Marshal(n); strings.Contains(string(b), `"concurrently"`) {
				return kNoTx
			}
		}
	}
	return ""
}

func classify(text string) *stmtInfo {
	si := &stmtInfo{text: text}
	js, err := pg_query.ParseToJSON(text)
	if err != nil {
		si.err = err.Error()
		si.kind = kRead // the server rejects it; nothing runs
		return si
	}
	var tree struct {
		Stmts []struct {
			Stmt map[string]any `json:"stmt"`
		} `json:"stmts"`
	}
	_ = json.Unmarshal([]byte(js), &tree)
	if len(tree.Stmts) > 1 {
		parts, err := pg_query.SplitWithParser(text, true)
		if err == nil && len(parts) == len(tree.Stmts) {
			si.parts = parts
		}
	}
	f, err := postgres.Analyze(text)
	if err != nil {
		f = model.Facts{}
	}
	if f["statement_type"] == "CopyStmt" && f["copy_external"] != true {
		// COPY FROM STDIN writes rows (each captured by the triggers like any insert);
		// COPY TO STDOUT reads them
		tw, _ := f["tables_written"].([]string)
		f["schema_unsupported"], f["schema_change"], f["is_write"] = false, false, len(tw) > 0
	}
	si.facts = f
	write := f["is_write"] == true
	kinds := []string{}
	for _, st := range tree.Stmts {
		k := kindOf(st.Stmt)
		if k == "" {
			k = kRead
			if len(tree.Stmts) == 1 && write {
				k = kWrite
			}
		}
		kinds = append(kinds, k)
	}
	if len(tree.Stmts) > 1 { // each part's own kind
		for i, p := range si.parts {
			if kinds[i] == kRead {
				if pf, err := postgres.Analyze(p); err == nil && pf["is_write"] == true {
					kinds[i] = kWrite
				}
			}
		}
	}
	si.kinds = kinds
	for _, st := range tree.Stmts {
		if _, ok := st.Stmt["DiscardStmt"]; ok {
			si.resets = true
		}
		if v, ok := st.Stmt["VariableSetStmt"].(map[string]any); ok && v["kind"] == "VAR_RESET_ALL" {
			si.resets = true
		}
	}
	switch {
	case len(kinds) == 0:
		si.kind = kRead
	case len(kinds) == 1:
		si.kind = kinds[0]
	default:
		si.kind = kRead
		for _, k := range kinds {
			if k != kRead && k != kWrite {
				si.kind = "multi_tx" // transaction control inside: run part by part
				break
			}
			if k == kWrite {
				si.kind = kWrite
			}
		}
	}
	return si
}

// ---------------------------------------------------------------- the response queue

// pending is one message sent to the server whose responses are not all in yet.
type pending struct {
	kind     byte // P B D E C S Q H (flush, no response) X (a refusal made here)
	describe int  // Describe: messages still expected
	internal bool // the gateway's own: its responses do not go to the client
	errOut   bool // internal, but an error it raises is the client's (a refusal, a failed commit)
	toMain   bool // a Sync or Query whose ReadyForQuery goes to the session, not the client
	rows     [][][]byte
	err      *pgproto3.ErrorResponse
	status   byte
	done     chan struct{}
	synth    *pgproto3.ErrorResponse // kind X: send this to the client when it is reached
	skipped  bool                    // the server skipped it (an error came before it)
	copyIn   chan struct{}           // closed when the server asks the client for COPY data
}

type session struct {
	g        *Gateway
	conn     net.Conn
	cl       *pgproto3.Backend
	up       *upstream
	user     string
	readOnly bool
	target   string
	pid      uint32
	key      []byte

	clMu sync.Mutex // writes to the client

	qMu   sync.Mutex
	queue []*pending
	wake  chan struct{}

	// what the session knows, kept by the client loop
	stmts   map[string]*stmtInfo
	portals map[string]*stmtInfo
	inTx    bool // an explicit transaction is open (as predicted from what was sent)
	wrapped bool // the gateway opened the current transaction around an autocommit write
	writes  bool // the current transaction ran something that writes
	sqlSeen []string
	// rollbackAtSync: the transaction ended in a refusal; at Sync it is rolled back and
	// the client told it is idle, as after a COMMIT that failed
	rollbackAtSync bool
	pendingSettle  []settleRef
	batchErr       bool // an error came back since the last ReadyForQuery (guarded by qMu)
	internalErr    *pgproto3.ErrorResponse
	// captureReady: the session's capture table and setting are known to be in place;
	// setupPending: they were made inside the current transaction (they hold if it commits)
	captureReady bool
	// strict: the open transaction takes the strict lane at COMMIT
	strict       bool
	strictMemo   map[*stmtInfo]bool
	newShape     map[*stmtInfo]bool
	decided      map[*stmtInfo]string // this session's decisions on statements it ran before (\"\" = allowed)
	setupPending bool
	internalSent bool                  // the gateway sent steps of its own in this batch
	broken       atomic.Pointer[error] // the server connection was lost
	upStatus     byte                  // last ReadyForQuery status from the server
	clean        bool
}

func newSession(g *Gateway, conn net.Conn, be *pgproto3.Backend, up *upstream, user string, readOnly bool, target string) *session {
	pid, key := randKey()
	return &session{g: g, conn: conn, cl: be, up: up, user: user, readOnly: readOnly, target: target, pid: pid, key: key,
		wake: make(chan struct{}, 1), stmts: map[string]*stmtInfo{}, portals: map[string]*stmtInfo{}, upStatus: 'I',
		captureReady: true, decided: map[*stmtInfo]string{}, strictMemo: map[*stmtInfo]bool{}, newShape: map[*stmtInfo]bool{}} // every connection is set up when made, and again when pooled
}

func (s *session) sendClient(msgs ...pgproto3.BackendMessage) error {
	s.clMu.Lock()
	defer s.clMu.Unlock()
	for _, m := range msgs {
		s.cl.Send(m)
	}
	return s.cl.Flush()
}

// start finishes the client's startup: its session parameters are applied on the server,
// and it is told the server's parameters and the gateway's own cancel key.
func (s *session) start(params map[string]string) error {
	// who the client is and the commit budget, for the fast lane's outbox and its guard
	sets := []string{fmt.Sprintf("SELECT set_config('undolayer.user', %s, false), set_config('undolayer.max_rows', '%d', false), "+
		"set_config('undolayer.max_fraction', '%g', false), set_config('undolayer.guard', %s, false)", lit(s.user), s.g.R.MaxRows, s.g.R.MaxFraction, lit(s.g.R.Mode))}
	for k, v := range params {
		switch k {
		case "user", "database", "replication":
			continue
		}
		sets = append(sets, fmt.Sprintf("SELECT set_config(%s, %s, false)", lit(k), lit(v)))
	}
	statuses := map[string]string{}
	for k, v := range s.up.params {
		statuses[k] = v
	}
	if len(sets) > 0 {
		s.up.fe.Send(&pgproto3.Query{String: strings.Join(sets, "; ")})
		if err := s.up.fe.Flush(); err != nil {
			return err
		}
		var failed error
		for {
			msg, err := s.up.recv()
			if err != nil {
				return err
			}
			_, rfq := msg.(*pgproto3.ReadyForQuery)
			switch m := msg.(type) {
			case *pgproto3.ErrorResponse:
				failed = errors.New(m.Message)
			case *pgproto3.ParameterStatus:
				statuses[m.Name] = m.Value
			}
			s.up.done()
			if rfq {
				break
			}
		}
		if failed != nil {
			return failed
		}
	}
	var out []pgproto3.BackendMessage
	for k, v := range statuses {
		out = append(out, &pgproto3.ParameterStatus{Name: k, Value: v})
	}
	out = append(out, &pgproto3.BackendKeyData{ProcessID: s.pid, SecretKey: s.key}, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	s.g.sessMu.Lock()
	s.g.sessions[s.pid] = s
	s.g.sessMu.Unlock()
	return s.sendClient(out...)
}

func lit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// push adds entries to the queue (in the order their messages are sent).
func (s *session) push(es ...*pending) {
	s.qMu.Lock()
	for _, e := range es {
		if e.done == nil {
			e.done = make(chan struct{})
		}
		s.queue = append(s.queue, e)
	}
	s.qMu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *session) head() *pending {
	s.qMu.Lock()
	defer s.qMu.Unlock()
	if len(s.queue) == 0 {
		return nil
	}
	return s.queue[0]
}

func (s *session) pop() {
	s.qMu.Lock()
	e := s.queue[0]
	s.queue = s.queue[1:]
	s.qMu.Unlock()
	close(e.done)
}

// drain waits until every entry sent so far is answered.
func (s *session) drain() {
	s.qMu.Lock()
	var last *pending
	if n := len(s.queue); n > 0 {
		last = s.queue[n-1]
	}
	s.qMu.Unlock()
	if last != nil {
		<-last.done
	}
}

// ---------------------------------------------------------------- server -> client

type upMsg struct {
	msg pgproto3.BackendMessage
	err error
}

// relayWith hands each message from the server to whoever the queue says it is for.
func (s *session) relayWith(stop chan struct{}, finished chan struct{}) {
	defer close(finished)
	for {
		s.instant()
		select {
		case <-stop:
			return
		case <-s.wake:
		case um, ok := <-s.up.in:
			if !ok || um.err != nil {
				s.setBroken(errors.New("the server connection was lost"))
				if ok {
					s.setBroken(um.err)
				}
				s.qMu.Lock()
				q := s.queue
				s.queue = nil
				s.qMu.Unlock()
				for _, e := range q {
					close(e.done)
				}
				_ = s.conn.Close()
				return
			}
			s.handle(um.msg)
			s.up.done()
		}
	}
}

// instant resolves entries that need no server response (a client Flush, a refusal made
// by the gateway) when they reach the head of the queue.
func (s *session) instant() {
	for {
		e := s.head()
		if e == nil {
			return
		}
		switch e.kind {
		case 'H':
			s.clMu.Lock()
			_ = s.cl.Flush()
			s.clMu.Unlock()
			s.pop()
		case 'X':
			_ = s.sendClient(e.synth)
			s.pop()
		default:
			return
		}
	}
}

func (s *session) toClient(m pgproto3.BackendMessage, flush bool) {
	s.clMu.Lock()
	s.cl.Send(m)
	if flush {
		_ = s.cl.Flush()
	}
	s.clMu.Unlock()
}

func copyRow(d *pgproto3.DataRow) [][]byte {
	out := make([][]byte, len(d.Values))
	for i, v := range d.Values {
		if v != nil {
			out[i] = append([]byte{}, v...)
		}
	}
	return out
}

func copyErr(e *pgproto3.ErrorResponse) *pgproto3.ErrorResponse {
	c := *e
	return &c
}

func (s *session) handle(msg pgproto3.BackendMessage) {
	switch msg.(type) {
	case *pgproto3.NoticeResponse, *pgproto3.ParameterStatus, *pgproto3.NotificationResponse:
		e := s.head()
		if e == nil || !e.internal || e.errOut {
			s.toClient(msg, e == nil)
		}
		return
	}
	e := s.head()
	if e == nil { // nothing was asked: pass it on
		s.toClient(msg, true)
		return
	}
	out := !e.internal
	switch m := msg.(type) {
	case *pgproto3.ErrorResponse:
		e.err = copyErr(m)
		if !e.internal || e.errOut {
			s.toClient(m, true)
		}
		s.qMu.Lock()
		s.batchErr = true
		if e.internal && !e.errOut && e.kind != 'Q' && s.internalErr == nil {
			s.internalErr = e.err // the gateway's own step failed: the client is told at Sync
		}
		s.qMu.Unlock()
		if e.kind == 'Q' {
			return // a simple query ends at ReadyForQuery
		}
		// extended protocol: the server skips everything up to the next Sync
		s.pop()
		s.skipUntilSync()
	case *pgproto3.ReadyForQuery:
		// entries still ahead of the Sync this answers were skipped by the server (after
		// an error, including ones sent after the error arrived)
		s.skipUntilSync()
		if e = s.head(); e == nil {
			s.toClient(m, true)
			return
		}
		s.qMu.Lock()
		s.upStatus, s.batchErr = m.TxStatus, false
		s.qMu.Unlock()
		e.status = m.TxStatus
		if !e.internal && !e.toMain {
			s.toClient(m, true)
		}
		s.pop()
	case *pgproto3.ParseComplete, *pgproto3.BindComplete, *pgproto3.CloseComplete:
		if out {
			s.toClient(msg, false)
		}
		s.pop()
	case *pgproto3.ParameterDescription:
		if out {
			s.toClient(msg, false)
		}
		e.describe--
		if e.describe <= 0 {
			s.pop()
		}
	case *pgproto3.RowDescription, *pgproto3.NoData:
		if out {
			s.toClient(msg, false)
		}
		if e.kind == 'D' {
			e.describe--
			if e.describe <= 0 {
				s.pop()
			}
		}
	case *pgproto3.DataRow:
		if e.internal {
			e.rows = append(e.rows, copyRow(m))
		} else {
			s.toClient(msg, false)
		}
	case *pgproto3.CommandComplete, *pgproto3.EmptyQueryResponse, *pgproto3.PortalSuspended:
		if out {
			s.toClient(msg, true)
		}
		if e.kind == 'E' {
			s.pop()
		}
	case *pgproto3.CopyInResponse, *pgproto3.CopyOutResponse, *pgproto3.CopyBothResponse, *pgproto3.CopyData, *pgproto3.CopyDone:
		if _, in := msg.(*pgproto3.CopyInResponse); in && e.copyIn != nil {
			defer close(e.copyIn)
		}
		if out {
			_, flush := msg.(*pgproto3.CopyData)
			s.toClient(msg, !flush)
		}
	default:
		if out {
			s.toClient(msg, true)
		}
	}
}

// skipUntilSync resolves, as skipped, the entries before the next Sync or Query.
func (s *session) skipUntilSync() {
	for {
		s.instant()
		n := s.head()
		if n == nil || n.kind == 'S' || n.kind == 'Q' {
			return
		}
		n.skipped = true
		s.pop()
	}
}

// ---------------------------------------------------------------- client -> server

func (s *session) run() {
	stop, finished := make(chan struct{}), make(chan struct{})
	go s.relayWith(stop, finished)
	defer func() {
		close(stop)
		<-finished
		s.g.sessMu.Lock()
		delete(s.g.sessions, s.pid)
		s.g.sessMu.Unlock()
		clean := !s.isBroken() && s.upStatus == 'I' && len(s.queue) == 0 && s.clean
		s.g.pool(s.target).put(s.up, clean)
	}()
	for {
		msg, err := s.cl.Receive()
		if err != nil {
			s.abandon()
			return
		}
		if s.isBroken() {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Terminate:
			s.drain()
			if s.inTx || s.wrapped {
				s.abandon()
				return
			}
			s.clean = true
			return
		case *pgproto3.Query:
			s.query(m.String)
		case *pgproto3.Parse:
			s.parse(m)
		case *pgproto3.Bind:
			s.portals[m.DestinationPortal] = s.stmts[m.PreparedStatement]
			s.forward(m, &pending{kind: 'B'})
		case *pgproto3.Describe:
			n := 1
			if m.ObjectType == 'S' {
				n = 2
			}
			s.forward(m, &pending{kind: 'D', describe: n})
		case *pgproto3.Execute:
			s.execute(m)
		case *pgproto3.Close:
			if m.ObjectType == 'S' {
				delete(s.stmts, m.Name)
			} else {
				delete(s.portals, m.Name)
			}
			s.forward(m, &pending{kind: 'C'})
		case *pgproto3.Sync:
			s.sync()
		case *pgproto3.Flush:
			s.up.fe.Send(m)
			_ = s.up.fe.Flush()
			s.push(&pending{kind: 'H'})
		case *pgproto3.CopyData, *pgproto3.CopyDone, *pgproto3.CopyFail:
			s.up.fe.Send(m)
			_ = s.up.fe.Flush()
		case *pgproto3.FunctionCall:
			// the fast-path call runs any function by its OID, out of the classifier's sight
			_ = s.sendClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "0A000",
				Message: "the function-call protocol is not supported through the Countersign gateway; call the function in a query"},
				&pgproto3.ReadyForQuery{TxStatus: s.upStatus})
		default:
			s.up.fe.Send(m)
			_ = s.up.fe.Flush()
		}
	}
}

// abandon: the client went away. An open transaction is rolled back by closing.
func (s *session) abandon() { s.clean = false }

func (s *session) forward(m pgproto3.FrontendMessage, e *pending) {
	s.push(e)
	s.up.fe.Send(m)
	_ = s.up.fe.Flush()
}

// internal sends the gateway's own messages and returns their entries.
func (s *session) takeInternalErr() *pgproto3.ErrorResponse {
	s.qMu.Lock()
	defer s.qMu.Unlock()
	e := s.internalErr
	s.internalErr = nil
	return e
}

func gatewayErr(e *pgproto3.ErrorResponse) *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{Severity: "ERROR", Code: "58000", Message: "Countersign gateway: " + e.Message}
}

func (s *session) internal(msgs []pgproto3.FrontendMessage, es []*pending) {
	s.internalSent = true
	for _, e := range es {
		e.internal = true
	}
	s.push(es...)
	for _, m := range msgs {
		s.up.fe.Send(m)
	}
	_ = s.up.fe.Flush()
}

// iquery runs one simple query of the gateway's own and waits for it.
func (s *session) iquery(sql string) (*pending, error) {
	e := &pending{kind: 'Q', toMain: true}
	s.internal([]pgproto3.FrontendMessage{&pgproto3.Query{String: sql}}, []*pending{e})
	<-e.done
	if s.isBroken() {
		return e, s.brokenErr()
	}
	if e.err != nil {
		return e, errors.New(e.err.Message)
	}
	return e, nil
}

// iextended runs one statement of the gateway's own in the extended protocol, followed by
// a Flush (not a Sync: it stays inside the client's transaction), and waits for it.
func (s *session) iextended(sql string, errOut bool) *pending {
	ex := &pending{kind: 'E', errOut: errOut}
	s.istmt("__cs_q", sql, ex, true)
	return ex
}

// refusal: the statement the client asked for is answered by the server raising this
// error, so its transaction fails exactly as for any other error.
func refuseSQL(reason string) string {
	return fmt.Sprintf("SELECT undolayer.refuse(%s, '42501')", lit("refused by Countersign: "+reason))
}

// waitQuery waits for a client query the session forwarded and must see the end of. If it
// is a COPY FROM STDIN, the client's data is passed on until it is done.
func (s *session) waitQuery(e *pending) {
	select {
	case <-e.done:
		return
	case <-e.copyIn:
	}
	for {
		msg, err := s.cl.Receive()
		if err != nil {
			s.setBroken(err)
			_ = s.up.conn.Close()
			<-e.done
			return
		}
		s.up.fe.Send(msg)
		_ = s.up.fe.Flush()
		switch msg.(type) {
		case *pgproto3.CopyDone, *pgproto3.CopyFail:
			<-e.done
			return
		}
	}
}

func (s *session) isBroken() bool { return s.broken.Load() != nil }

func (s *session) brokenErr() error {
	if p := s.broken.Load(); p != nil {
		return *p
	}
	return nil
}

func (s *session) setBroken(err error) {
	if err == nil {
		err = errors.New("the server connection was lost")
	}
	s.broken.CompareAndSwap(nil, &err)
}
