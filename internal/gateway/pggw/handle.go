package pggw

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"undolayer/internal/connectors/postgres"
	"undolayer/internal/model"
	"undolayer/internal/vault"
)

// ---------------------------------------------------------------- deciding

// decide says whether a statement may run. In watch mode nothing is refused; what would
// have been is audited.
func (s *session) decide(si *stmtInfo) (refuse bool, reason string) {
	s.g.stats.statements.Add(1)
	// the same statement again in this session: the same facts, the same decision (its
	// shape is not new any more, and the session's user and server have not changed)
	if why, ok := s.decided[si]; ok {
		if why == "" {
			return false, ""
		}
		s.g.stats.refused.Add(1)
		return true, why
	}
	refuse, reason = s.decideFresh(si)
	if len(s.decided) < 4096 {
		s.decided[si] = reason
		if !refuse {
			s.decided[si] = ""
		}
	}
	return refuse, reason
}

func (s *session) decideFresh(si *stmtInfo) (refuse bool, reason string) {
	writes := si.kind == kWrite || si.facts["is_write"] == true
	switch {
	case si.kind == kTwoPhase:
		reason = "two-phase commit (PREPARE TRANSACTION) is not supported through the gateway"
	case writes && (s.readOnly || !s.g.topo.isPrimary(s.target)):
		reason = "this session is on a read replica (or the main database moved); it cannot write"
	}
	if reason == "" && si.err == "" {
		f := model.Facts{}
		for k, v := range si.facts {
			f[k] = v
		}
		f["requester"], f["gateway"] = s.user, s.g.R.Name
		if sh, _ := f["query_shape"].(string); sh != "" {
			f["shape_new"] = s.g.shapes.learn(s.user, sh, si.text, s.g)
			s.newShape[si] = f["shape_new"] == true
		}
		eff, op := model.Read, "query"
		if writes {
			eff, op = model.Reversible, "execute"
		}
		a := &model.Action{Connector: "sql", Operation: op, Effect: eff, Facts: f}
		s.g.pol.Evaluate(a)
		if a.Decision == model.Deny || a.Decision == model.RequireApproval {
			reason = strings.Join(a.Reasons, "; ")
		}
	}
	if reason == "" {
		return false, ""
	}
	s.g.M.Audit.Note("gateway_refused", map[string]any{"gateway": s.g.R.Name, "user": s.user, "sql": redactSQL(si.text),
		"reason": reason, "mode": s.g.R.Mode})
	if s.g.R.Mode == "watch" {
		return false, ""
	}
	s.g.stats.refused.Add(1)
	return true, reason
}

// redactSQL is a statement as the audit log keeps it: its values taken out (the log is
// not encrypted; the full text, with its values, is only in the vault, sealed).
func redactSQL(sql string) string {
	n, err := pg_query.Normalize(sql)
	if err != nil {
		return "(statement not shown: it does not parse)"
	}
	return clip(n, 2000)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// shapes: the query shapes each user has run through this gateway (in memory); a new one
// is audited once.
type shapeSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (ss *shapeSet) learn(user, shape, text string, g *Gateway) bool {
	k := user + "\x00" + shape
	ss.mu.Lock()
	seen := ss.m[k]
	if !seen {
		if len(ss.m) > 1_000_000 {
			ss.m = map[string]bool{}
		}
		ss.m[k] = true
	}
	ss.mu.Unlock()
	if !seen {
		g.M.Audit.Note("gateway_shape", map[string]any{"gateway": g.R.Name, "user": user, "shape": shape, "sql": redactSQL(text)})
	}
	return !seen
}

// ---------------------------------------------------------------- simple query protocol

func (s *session) query(text string) {
	si := s.g.analyze.get(text)
	if si.resets {
		s.captureReady = false
	}
	if refuse, why := s.decide(si); refuse {
		s.forward(&pgproto3.Query{String: refuseSQL(why)}, &pending{kind: 'Q'})
		return
	}
	switch si.kind {
	case "multi_tx":
		s.queryParts(si)
	case kBegin:
		s.inTx, s.writes, s.sqlSeen = true, false, nil
		s.strict = false
		s.forward(&pgproto3.Query{String: text}, &pending{kind: 'Q'})
	case kCommit:
		if s.inTx && s.writes && s.strict {
			s.commitSimple(text)
		} else {
			s.forward(&pgproto3.Query{String: text}, &pending{kind: 'Q'})
		}
		s.inTx, s.writes = false, false
		s.strict = false
	case kRollback:
		s.inTx, s.writes = false, false
		s.strict = false
		s.forward(&pgproto3.Query{String: text}, &pending{kind: 'Q'})
	case kWrite:
		s.sqlSeen = append(s.sqlSeen, clip(text, 4000))
		if s.inTx {
			if !s.writes && !s.captureReady {
				if _, err := s.iquery(s.setupSQL()); err != nil {
					s.fail(err)
					return
				}
				s.setupPending = true // it holds once this transaction commits
			}
			s.writes = true
			if s.isStrict(si) {
				s.strict = true
			}
			s.forward(&pgproto3.Query{String: text}, &pending{kind: 'Q'})
			return
		}
		if s.isStrict(si) {
			s.autocommitSimple(text)
			return
		}
		// the fast lane: the write runs as it is; its before state goes to the outbox in
		// its own (implicit) transaction, and to the vault in the background
		s.sqlSeen = nil
		s.forward(&pgproto3.Query{String: text}, &pending{kind: 'Q'})
	default:
		s.forward(&pgproto3.Query{String: text}, &pending{kind: 'Q'})
	}
}

// fail reports a gateway failure to the client as an error and ends the request.
func (s *session) fail(err error) {
	_ = s.sendClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "58000", Message: "Countersign gateway: " + err.Error()},
		&pgproto3.ReadyForQuery{TxStatus: s.status()})
}

func (s *session) status() byte {
	s.qMu.Lock()
	defer s.qMu.Unlock()
	return s.upStatus
}

// autocommitSimple: a write outside a transaction runs inside one the gateway opens, so
// its before state can be stored before it commits.
func (s *session) autocommitSimple(text string) {
	setup := "BEGIN"
	if !s.captureReady {
		setup = s.setupSQL() + "; BEGIN" // outside the transaction: it stays even if this one rolls back
	}
	if _, err := s.iquery(setup); err != nil {
		s.fail(err)
		return
	}
	s.captureReady = true
	e := &pending{kind: 'Q', toMain: true, copyIn: make(chan struct{})} // its results go to the client, its ReadyForQuery to us
	s.forward(&pgproto3.Query{String: text}, e)
	s.waitQuery(e)
	if s.isBroken() {
		return
	}
	if e.status != 'T' { // it failed: the client already has the error
		_, _ = s.iquery("ROLLBACK")
		s.toClient(&pgproto3.ReadyForQuery{TxStatus: 'I'}, true)
		s.sqlSeen = nil
		return
	}
	ok, why, batch, id := s.capture(false)
	if !ok {
		_, _ = s.iquery("ROLLBACK")
		_ = s.sendClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "refused by Countersign: " + why},
			&pgproto3.ReadyForQuery{TxStatus: 'I'})
		s.sqlSeen = nil
		return
	}
	ce, err := s.iquery("COMMIT")
	s.settle(id, batch, err == nil && ce.err == nil)
	if err != nil {
		_ = s.sendClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "40000", Message: err.Error()},
			&pgproto3.ReadyForQuery{TxStatus: s.status()})
	} else {
		s.toClient(&pgproto3.ReadyForQuery{TxStatus: 'I'}, true)
	}
	s.sqlSeen = nil
}

// commitSimple: the client's COMMIT of a transaction that wrote.
func (s *session) commitSimple(text string) {
	if s.status() == 'E' { // the transaction failed: COMMIT rolls it back
		s.forward(&pgproto3.Query{String: text}, &pending{kind: 'Q'})
		return
	}
	ok, why, batch, id := s.capture(false)
	if !ok && why == txFailed {
		s.forward(&pgproto3.Query{String: text}, &pending{kind: 'Q'})
		return
	}
	if !ok {
		_, _ = s.iquery("ROLLBACK")
		_ = s.sendClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "refused by Countersign: " + why},
			&pgproto3.ReadyForQuery{TxStatus: 'I'})
		s.sqlSeen = nil
		return
	}
	e := &pending{kind: 'Q', errOut: true}
	s.push(e)
	s.up.fe.Send(&pgproto3.Query{String: text})
	_ = s.up.fe.Flush()
	<-e.done
	s.settle(id, batch, e.err == nil && !s.isBroken())
	s.sqlSeen = nil
}

// queryParts runs a multi-statement query that controls transactions one statement at a
// time, so each COMMIT can be preceded by storing what its transaction changed. As in
// PostgreSQL, the statements after one that fails are not run.
func (s *session) queryParts(si *stmtInfo) {
	for i, part := range si.parts {
		psi := s.g.analyze.get(part)
		if refuse, why := s.decide(psi); refuse {
			part, psi = refuseSQL(why), &stmtInfo{kind: kRead}
		}
		last := i == len(si.parts)-1
		before := s.status()
		e := &pending{kind: 'Q', toMain: !last, copyIn: make(chan struct{})}
		switch psi.kind {
		case kBegin:
			s.inTx, s.writes = true, false
			s.strict = false
		case kCommit:
			if s.inTx && s.writes && s.strict && s.status() != 'E' {
				ok, why, batch, id := s.capture(false)
				if !ok {
					_, _ = s.iquery("ROLLBACK")
					_ = s.sendClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "refused by Countersign: " + why},
						&pgproto3.ReadyForQuery{TxStatus: 'I'})
					s.inTx, s.writes, s.sqlSeen = false, false, nil
					s.strict = false
					return
				}
				defer s.settleAfter(id, batch)
			}
			s.inTx, s.writes = false, false
			s.strict = false
		case kRollback:
			s.inTx, s.writes = false, false
			s.strict = false
		case kWrite:
			s.sqlSeen = append(s.sqlSeen, clip(part, 4000))
			if !s.inTx && !s.isStrict(psi) {
				s.sqlSeen = nil
				break // the fast lane: it runs as it is
			}
			if !s.inTx { // a write outside a transaction: as autocommitSimple, but quietly
				if last {
					s.autocommitSimple(part)
					return
				}
				if _, err := s.iquery("BEGIN; " + s.setupSQL()); err != nil {
					s.fail(err)
					return
				}
				s.forward(&pgproto3.Query{String: part}, e)
				s.waitQuery(e)
				if e.status != 'T' {
					_, _ = s.iquery("ROLLBACK")
					s.toClient(&pgproto3.ReadyForQuery{TxStatus: 'I'}, true)
					return
				}
				ok, why, batch, id := s.capture(false)
				if !ok {
					_, _ = s.iquery("ROLLBACK")
					_ = s.sendClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "refused by Countersign: " + why},
						&pgproto3.ReadyForQuery{TxStatus: 'I'})
					return
				}
				ce, err := s.iquery("COMMIT")
				s.settle(id, batch, err == nil && ce.err == nil)
				s.sqlSeen = nil
				continue
			}
			if !s.writes {
				if _, err := s.iquery(s.setupSQL()); err != nil {
					s.fail(err)
					return
				}
			}
			s.writes = true
			if s.isStrict(psi) {
				s.strict = true
			}
		}
		_ = before
		s.forward(&pgproto3.Query{String: part}, e)
		if last {
			return
		}
		s.waitQuery(e)
		if e.err != nil || s.isBroken() {
			if !s.isBroken() {
				s.toClient(&pgproto3.ReadyForQuery{TxStatus: e.status}, true)
			}
			return
		}
	}
}

// ---------------------------------------------------------------- extended protocol

func (s *session) parse(m *pgproto3.Parse) {
	si := s.g.analyze.get(m.Query)
	if refuse, why := s.decide(si); refuse {
		delete(s.stmts, m.Name)
		ex := &pending{kind: 'E', errOut: true}
		s.istmt("__cs_r", refuseSQL(why), ex, false)
		return
	}
	s.stmts[m.Name] = si
	s.forward(m, &pending{kind: 'P'})
}

func (s *session) execute(m *pgproto3.Execute) {
	si := s.portals[m.Portal]
	if si == nil {
		s.forward(m, &pending{kind: 'E'})
		return
	}
	if si.resets {
		s.captureReady = false
	}
	switch si.kind {
	case kBegin:
		s.inTx, s.writes, s.sqlSeen = true, false, nil
		s.strict = false
	case kCommit:
		if s.wrapped || (s.inTx && s.writes && s.strict) {
			s.commitExtended(m)
			s.inTx, s.writes, s.wrapped = false, false, false
			s.strict = false
			return
		}
		s.inTx, s.writes = false, false
		s.strict = false
	case kRollback:
		s.inTx, s.writes, s.wrapped = false, false, false
		s.strict = false
	case kWrite:
		s.sqlSeen = append(s.sqlSeen, clip(si.text, 4000))
		strict := s.isStrict(si)
		if !s.inTx && !s.wrapped && !strict {
			s.sqlSeen = nil
			break // the fast lane: it runs as it is, in its own implicit transaction
		}
		if !s.inTx && !s.wrapped { // a strict autocommit write: the gateway opens the transaction
			s.iexecAsync("BEGIN")
			s.wrapped = true
		}
		if !s.writes && !s.captureReady {
			s.iexecAsync(s.setupSQL())
			s.setupPending = true
		}
		s.writes = true
		if strict {
			s.strict = true
		}
	}
	s.forward(m, &pending{kind: 'E'})
}

// iexecAsync queues one statement of the gateway's own, without waiting.
func (s *session) iexecAsync(sql string) {
	s.istmt("__cs_a", sql, &pending{kind: 'E'}, false)
}

// flushAndDrain makes the server send what it holds and waits for every answer so far.
func (s *session) flushAndDrain() {
	s.up.fe.Send(&pgproto3.Flush{})
	_ = s.up.fe.Flush()
	s.drain()
}

func (s *session) batchFailed() bool {
	s.qMu.Lock()
	defer s.qMu.Unlock()
	return s.upStatus == 'E' || s.batchErr
}

// commitExtended: the client's COMMIT (or the end of a transaction the gateway opened).
func (s *session) commitExtended(m *pgproto3.Execute) {
	ok, why, batch, id := s.capture(true)
	if s.isBroken() {
		return
	}
	if !ok && why == txFailed { // COMMIT of a failed transaction rolls it back, as always
		s.forward(m, &pending{kind: 'E'})
		return
	}
	if !ok {
		s.istmt("__cs_r", refuseSQL(why), &pending{kind: 'E', errOut: true}, false)
		s.rollbackAtSync = true // as a COMMIT that fails: the transaction is over
		s.sqlSeen = nil
		return
	}
	e := &pending{kind: 'E'}
	s.forward(m, e)
	s.pendingSettle = append(s.pendingSettle, settleRef{id, batch, e})
	s.sqlSeen = nil
}

func (s *session) sync() {
	if s.wrapped {
		// the capture read goes after the client's statements: once it is answered, so is
		// everything before it (and if one of them failed, the server skipped it)
		{
			ok, why, batch, id := s.capture(true)
			if s.isBroken() {
				return
			}
			if !ok && why == txFailed {
				s.rollbackAtSync = true
			} else if !ok {
				s.istmt("__cs_r", refuseSQL(why), &pending{kind: 'E', errOut: true}, false)
				s.rollbackAtSync = true
			} else {
				ce := &pending{kind: 'E', errOut: true}
				s.istmt("__cs_c", "COMMIT", ce, false)
				s.pendingSettle = append(s.pendingSettle, settleRef{id, batch, ce})
			}
		}
		s.wrapped, s.writes, s.sqlSeen = false, false, nil
	}
	if s.internalSent && !s.rollbackAtSync {
		s.flushAndDrain() // a step of the gateway's own in this batch: did it go through?
	}
	s.internalSent = false
	if ie := s.takeInternalErr(); ie != nil {
		s.push(&pending{kind: 'X', synth: gatewayErr(ie)})
		if s.wrapped || s.status() == 'I' {
			s.rollbackAtSync = true
		}
	}
	if !s.rollbackAtSync {
		e := &pending{kind: 'S'}
		s.forward(&pgproto3.Sync{}, e)
		s.afterSync(e)
		return
	}
	s.rollbackAtSync = false
	e := &pending{kind: 'S', toMain: true}
	s.forward(&pgproto3.Sync{}, e)
	<-e.done
	if s.isBroken() {
		return
	}
	if e.status != 'I' {
		_, _ = s.iquery("ROLLBACK")
	}
	s.inTx, s.writes = false, false
	s.strict = false
	s.settleAll()
	s.toClient(&pgproto3.ReadyForQuery{TxStatus: 'I'}, true)
}

// afterSync settles the commits of this batch once the server has answered them.
func (s *session) afterSync(e *pending) {
	if len(s.pendingSettle) == 0 {
		return
	}
	refs := s.pendingSettle
	s.pendingSettle = nil
	s.g.bg.Add(1) // shutdown waits for this too
	go func() {
		defer s.g.bg.Done()
		<-e.done
		for _, r := range refs {
			<-r.e.done
			s.settle(r.id, r.batch, r.e.err == nil && !r.e.skipped && !s.isBroken())
		}
	}()
}

func (s *session) settleAll() {
	for _, r := range s.pendingSettle {
		<-r.e.done
		s.settle(r.id, r.batch, r.e.err == nil && !r.e.skipped && !s.isBroken())
	}
	s.pendingSettle = nil
}

type settleRef struct {
	id, batch string
	e         *pending
}

// ---------------------------------------------------------------- keeping the before state

// captureSelect: a first row saying whether capture is on in this transaction (and its
// XID), then the captured rows in order. A transaction that wrote with capture off (if a
// client found a way to turn it off) cannot commit: nothing would have kept its way back.
const captureSelect = `WITH d AS (DELETE FROM undolayer.outbox WHERE xid = txid_current() RETURNING seq, tbl, op, old_row, new_row)
SELECT 0, 0::bigint, current_setting('undolayer.tx', true), txid_current()::text, NULL::text, NULL::text
UNION ALL SELECT 1, seq, tbl, op, old_row::text, new_row::text FROM d ORDER BY 1, 2 LIMIT `

// capture reads what the transaction changed (captured row by row as it ran), measures it
// against policy, and stores its before state in the vault, before the COMMIT goes on. It
// returns false (and why) if the commit must not happen.
// capture's result when the transaction had already failed (an error earlier in the
// batch, so the server skipped the read; or an aborted transaction): the client has
// its error already, and the transaction is rolled back.
const txFailed = "\x00failed"

func (s *session) capture(extended bool) (ok bool, why, batch, id string) {
	run := func(sql string) (*pending, error) {
		if extended {
			e := s.iextended(sql, false)
			<-e.done
			if s.isBroken() {
				return e, s.brokenErr()
			}
			if e.err != nil || e.skipped {
				msg := "skipped"
				if e.err != nil {
					msg = e.err.Message
				}
				return e, fmt.Errorf("%s", msg)
			}
			return e, nil
		}
		return s.iquery(sql)
	}
	limit := s.g.R.MaxCaptureRows
	e, err := run(captureSelect + strconv.Itoa(limit+2))
	if err != nil {
		if e != nil && (e.skipped || (e.err != nil && e.err.Code == "25P02")) {
			s.takeInternalErr() // not a failure of the gateway's: the transaction had failed
			return false, txFailed, "", ""
		}
		s.takeInternalErr()
		s.captureReady = false // made again before the next write
		return false, "the changed rows could not be read: " + err.Error(), "", ""
	}
	if len(e.rows) == 0 || string(e.rows[0][0]) != "0" {
		return false, "the capture check returned nothing", "", ""
	}
	marker, data := e.rows[0], e.rows[1:]
	if string(marker[2]) != "gateway" {
		s.captureReady = false
		return false, "row capture is not active in this transaction, so its before state cannot be kept", "", ""
	}
	s.captureReady, s.setupPending = true, false // confirmed on (if this commit fails, the next check says so)
	if len(data) == 0 {
		return true, "", "", "" // nothing changed
	}
	if len(data) > limit {
		return false, fmt.Sprintf("the transaction changes more than %d rows, too many to keep a way back for; split it", limit), "", ""
	}
	xid, _ := strconv.ParseInt(string(marker[3]), 10, 64)
	tables := map[string]bool{}
	for _, r := range data {
		tables[string(r[2])] = true
	}
	pks, sizes, err := s.g.pk.lookup(tables, run)
	if err != nil {
		return false, "primary keys could not be read: " + err.Error(), "", ""
	}
	var events []postgres.Event
	var noPK []string
	for t := range tables {
		if len(pks[t]) == 0 {
			noPK = append(noPK, t)
		}
	}
	for _, r := range data {
		t, op := string(r[2]), string(r[3])
		pk := pks[t]
		ev := postgres.Event{T: t}
		old, nw := string(r[4]), string(r[5])
		switch op {
		case "INSERT":
			ev.Op, ev.New, ev.KN = "I", nw, postgres.KeyOf(nw, pk)
		case "UPDATE":
			ev.Op, ev.Old, ev.New, ev.KO, ev.KN = "U", old, nw, postgres.KeyOf(old, pk), postgres.KeyOf(nw, pk)
		case "DELETE":
			ev.Op, ev.Old, ev.KO = "D", old, postgres.KeyOf(old, pk)
		}
		events = append(events, ev)
	}
	rec := &postgres.UndoRecord{DSN: s.g.Conn.RecordDSN(), XID: xid,
		Changes: []*postgres.Change{{ActionID: "gateway", SQL: strings.Join(s.sqlSeen, ";\n"), Events: events}}}
	raw, _ := json.Marshal(rec)
	rows, err := s.g.Conn.DescribeRows(raw)
	if err != nil {
		return false, err.Error(), "", ""
	}
	// measured, then judged: what this transaction actually changed
	per := map[string]int{}
	deleted := 0
	for _, r := range rows {
		per[r.Table]++
		if r.Op == "delete" {
			deleted++
		}
	}
	frac := 0.0
	touched := []string{}
	for t, n := range per {
		touched = append(touched, t)
		total := sizes[t]
		if float64(n) > total {
			total = float64(n)
		}
		if total >= 20 && float64(n)/total > frac {
			frac = float64(n) / total
		}
	}
	f := model.Facts{"rows_affected": len(rows), "rows_deleted": deleted, "tables_touched": touched,
		"table_fraction_changed": frac, "no_primary_key": noPK, "undoable": len(noPK) == 0,
		"requester": s.user, "gateway": s.g.R.Name}
	a := &model.Action{Connector: "sql", Operation: "commit", Effect: model.Reversible, Facts: f}
	s.g.pol.Evaluate(a)
	if a.Decision == model.Deny || a.Decision == model.RequireApproval {
		reason := strings.Join(a.Reasons, "; ")
		s.g.M.Audit.Note("gateway_refused", map[string]any{"gateway": s.g.R.Name, "user": s.user, "at": "commit",
			"rows": len(rows), "reason": reason, "mode": s.g.R.Mode})
		if s.g.R.Mode != "watch" {
			s.g.stats.refused.Add(1)
			return false, reason, "", ""
		}
	}
	if s.g.M.Vault == nil {
		return false, "the vault is disabled, so no before state can be kept", "", ""
	}
	id = newID()
	rc, err := s.g.M.Vault.Append(vault.Entry{Tx: id, Task: clip("gateway "+s.g.R.Name+": "+strings.Join(s.sqlSeen, "; "), 500),
		Requester: s.user, Connector: s.g.Conn.Name(), Phase: "intent", Rows: rows, Undo: raw})
	if err != nil {
		return false, "the vault could not store the before state: " + err.Error(), "", ""
	}
	s.g.stats.captured.Add(int64(len(rows)))
	return true, "", rc.Batch, id
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "gw_" + hex.EncodeToString(b)
}

// settle records how a commit whose before state is in the vault ended (in the background:
// the intent already holds the way back, and its XID tells the rest).
func (s *session) settle(id, batch string, committed bool) {
	if batch == "" {
		return
	}
	s.g.stats.commits.Add(1)
	phase := "committed"
	if !committed {
		phase = "failed"
	}
	s.g.M.Audit.Note("gateway_commit", map[string]any{"tx": id, "gateway": s.g.R.Name, "user": s.user, "outcome": phase})
	s.g.M.Vault.AppendLater(vault.Entry{Tx: id, Requester: s.user, Connector: s.g.Conn.Name(), Phase: phase, Ref: batch})
}

func (s *session) settleAfter(id, batch string) {
	s.settle(id, batch, true) // within a part-by-part query; the COMMIT result is checked by the client's error, if any
}

// ---------------------------------------------------------------- primary keys and sizes

type pkEntry struct {
	cols []string
	size float64
	at   time.Time
}

type pkCache struct {
	mu sync.Mutex
	m  map[string]pkEntry
}

func (c *pkCache) lookup(tables map[string]bool, run func(string) (*pending, error)) (map[string][]string, map[string]float64, error) {
	pks, sizes := map[string][]string{}, map[string]float64{}
	var missing []string
	c.mu.Lock()
	for t := range tables {
		if e, ok := c.m[t]; ok && time.Since(e.at) < time.Minute {
			pks[t], sizes[t] = e.cols, e.size
		} else {
			missing = append(missing, t)
		}
	}
	c.mu.Unlock()
	if len(missing) == 0 {
		return pks, sizes, nil
	}
	var lits []string
	for _, t := range missing {
		lits = append(lits, lit(t)+"::regclass")
	}
	in := strings.Join(lits, ", ")
	e, err := run(`SELECT c.oid::regclass::text, 'size', c.reltuples::text FROM pg_class c WHERE c.oid IN (` + in + `)
		UNION ALL SELECT c.oid::regclass::text, 'pk', a.attname FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
		WHERE i.indisprimary AND c.oid IN (` + in + `)`)
	if err != nil {
		return nil, nil, err
	}
	// regclass text omits public.; captured names carry it: map both
	canon := map[string]string{}
	for _, t := range missing {
		canon[t] = t
		canon[strings.TrimPrefix(t, "public.")] = t
	}
	got := map[string]*pkEntry{}
	order := map[string][]string{}
	for _, r := range e.rows {
		t := canon[string(r[0])]
		if t == "" {
			t = string(r[0])
		}
		if got[t] == nil {
			got[t] = &pkEntry{at: time.Now()}
		}
		switch string(r[1]) {
		case "size":
			got[t].size, _ = strconv.ParseFloat(string(r[2]), 64)
		case "pk":
			order[t] = append(order[t], string(r[2]))
		}
	}
	// key column order: as PostgreSQL's index lists them
	if len(order) > 0 {
		var ol []string
		for t := range order {
			ol = append(ol, lit(t)+"::regclass")
		}
		oe, err := run(`SELECT c.oid::regclass::text, a.attname FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
			JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
			WHERE i.indisprimary AND c.oid IN (` + strings.Join(ol, ", ") + `) ORDER BY 1, array_position(i.indkey, a.attnum)`)
		if err != nil {
			return nil, nil, err
		}
		order = map[string][]string{}
		for _, r := range oe.rows {
			t := canon[string(r[0])]
			if t == "" {
				t = string(r[0])
			}
			order[t] = append(order[t], string(r[1]))
		}
	}
	c.mu.Lock()
	for _, t := range missing {
		e := got[t]
		if e == nil {
			e = &pkEntry{at: time.Now()}
		}
		e.cols = order[t]
		c.m[t] = *e
		pks[t], sizes[t] = e.cols, e.size
	}
	c.mu.Unlock()
	return pks, sizes, nil
}

// istmt sends one statement of the gateway's own in the extended protocol: a fresh prepared
// statement and portal of its own name (closed again at once, so nothing is left behind and
// nothing of the client's is touched), optionally followed by a Flush.
func (s *session) istmt(name, sql string, ex *pending, flush bool) {
	msgs := []pgproto3.FrontendMessage{
		&pgproto3.Close{ObjectType: 'S', Name: name},
		&pgproto3.Parse{Name: name, Query: sql},
		&pgproto3.Bind{DestinationPortal: name, PreparedStatement: name},
		&pgproto3.Execute{Portal: name},
		&pgproto3.Close{ObjectType: 'P', Name: name},
	}
	if flush {
		msgs = append(msgs, &pgproto3.Flush{})
	}
	s.internal(msgs, []*pending{{kind: 'C'}, {kind: 'P'}, {kind: 'B'}, ex, {kind: 'C'}})
}

// setupSQL turns capture on for this session: the outbox, who the client is, and the
// commit budget the database holds.
func (s *session) setupSQL() string {
	return fmt.Sprintf("SELECT set_config('undolayer.tx', 'gateway', false), set_config('undolayer.user', %s, false), "+
		"set_config('undolayer.max_rows', '%d', false), set_config('undolayer.max_fraction', '%g', false), set_config('undolayer.guard', %s, false)",
		lit(s.user), s.g.R.MaxRows, s.g.R.MaxFraction, lit(s.g.R.Mode))
}

// isStrict: whether a write takes the strict lane (its before state in the vault before
// COMMIT, judged on what it changed). Ordinary writes take the fast lane; a statement
// with anything unusual about it does not: a shape its user never ran before, a sign of
// injection, a call into user code, a write through a query, COPY from outside, a schema
// change; and nothing does while capture is not confirmed on in this session.
func (s *session) isStrict(si *stmtInfo) bool {
	if s.g.R.Lane == "strict" || !s.captureReady {
		return true
	}
	if s.newShape[si] { // the first time its user runs this shape: once, strict
		delete(s.newShape, si)
		return true
	}
	if v, ok := s.strictMemo[si]; ok {
		return v
	}
	f := si.facts
	strict := false
	if sig, _ := f["sql_injection_signals"].([]string); len(sig) > 0 {
		strict = true
	}
	if uf, _ := f["user_functions"].([]string); len(uf) > 0 {
		strict = true
	}
	for _, k := range []string{"write_via_query", "copy_external", "schema_change", "opaque_code", "multi_statement"} {
		if b, _ := f[k].(bool); b {
			strict = true
		}
	}
	if len(s.strictMemo) < 4096 {
		s.strictMemo[si] = strict
	}
	return strict
}
