package mysqlgw

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/go-mysql-org/go-mysql/client"
	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"

	"undolayer/internal/connectors/mysql"
	"undolayer/internal/model"
	"undolayer/internal/vault"
)

type session struct {
	g    *Gateway
	up   *client.Conn
	mc   *server.Conn
	user string

	inTx, writes bool
	autocommit   bool
	failed       string // a write nothing recorded: the transaction cannot commit
	sqlSeen      []string
	logs         map[string]bool // databases whose capture table this session has
	temps        map[string]bool // the session's own temporary tables
	lastSeq      int64
	decided      map[*stmtInfo]string
}

type pstmt struct {
	st *client.Stmt
	si *stmtInfo
}

func (g *Gateway) handle(c net.Conn) {
	defer c.Close()
	up, err := mysql.Dial(g.A, "")
	if err != nil {
		g.M.Audit.Note("gateway_upstream_failed", map[string]any{"gateway": g.R.Name, "error": err.Error()})
		return
	}
	defer up.Close()
	s := &session{g: g, up: up, autocommit: true, logs: map[string]bool{}, temps: map[string]bool{}, decided: map[*stmtInfo]string{}}
	if err := s.setup(); err != nil {
		g.M.Audit.Note("gateway_upstream_failed", map[string]any{"gateway": g.R.Name, "error": err.Error()})
		return
	}
	mc, err := g.srv.NewCustomizedConn(c, g.auth, s)
	if err != nil {
		return
	}
	s.mc = mc
	s.user = mc.GetUser()
	for !mc.Closed() {
		if err := mc.HandleCommand(); err != nil {
			return
		}
	}
}

// setup turns capture on for this session: a capture table per captured database,
// shadowing the permanent one.
func (s *session) setup() error {
	for _, db := range s.g.R.Databases {
		if _, err := s.up.Execute("CREATE TEMPORARY TABLE IF NOT EXISTS " + mysql.Q(db) + ".countersign_log " + mysql.LogTable); err != nil {
			return err
		}
		s.logs[db] = true
	}
	_, err := s.up.Execute("SET @countersign_capture = 1")
	return err
}

func refusal(why string) error {
	return gomysql.NewError(gomysql.ER_SPECIFIC_ACCESS_DENIED_ERROR, "refused by Countersign: "+why)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---------------------------------------------------------------- the Handler

func (s *session) UseDB(db string) error {
	_, err := s.up.UseDBWithResult(db)
	return err
}

func (s *session) HandleQuery(q string) (*gomysql.Result, error) {
	si := s.g.an.get(q)
	return s.run(si, func() (*gomysql.Result, error) { return s.up.Execute(q) })
}

func (s *session) HandleFieldList(table, wildcard string) ([]*gomysql.Field, error) {
	return s.up.FieldList(table, wildcard)
}

func (s *session) HandleStmtPrepare(q string) (int, int, any, error) {
	si := s.g.an.get(q)
	if why := s.decide(si); why != "" {
		return 0, 0, nil, refusal(why)
	}
	st, err := s.up.Prepare(q)
	if err != nil {
		return 0, 0, nil, err
	}
	return st.ParamNum(), st.ColumnNum(), &pstmt{st: st, si: si}, nil
}

func (s *session) HandleStmtExecute(ctx any, q string, args []any) (*gomysql.Result, error) {
	p, ok := ctx.(*pstmt)
	if !ok {
		return nil, fmt.Errorf("unknown statement")
	}
	return s.run(p.si, func() (*gomysql.Result, error) { return p.st.Execute(args...) })
}

func (s *session) HandleStmtClose(ctx any) error {
	if p, ok := ctx.(*pstmt); ok {
		return p.st.Close()
	}
	return nil
}

func (s *session) HandleOtherCommand(cmd byte, data []byte) error {
	return gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, fmt.Sprintf("command %d is not supported through the Countersign gateway", cmd))
}

// ---------------------------------------------------------------- deciding

func (s *session) decide(si *stmtInfo) string {
	s.g.stats.statements.Add(1)
	if why, ok := s.decided[si]; ok {
		if why != "" {
			s.g.stats.refused.Add(1)
		}
		return why
	}
	f := model.Facts{}
	for k, v := range si.facts {
		f[k] = v
	}
	f["requester"], f["gateway"] = s.user, s.g.R.Name
	eff, op := model.Read, "query"
	if si.kind == kWrite {
		eff, op = model.Reversible, "execute"
	}
	why := s.g.judge(s.user, &model.Action{Connector: "sql", Operation: op, Effect: eff, Facts: f}, si.text)
	if len(s.decided) < 4096 {
		s.decided[si] = why
	}
	return why
}

func (g *Gateway) judge(user string, a *model.Action, what string) string {
	g.pol.Evaluate(a)
	if a.Decision != model.Deny && a.Decision != model.RequireApproval {
		return ""
	}
	reason := strings.Join(a.Reasons, "; ")
	g.M.Audit.Note("gateway_refused", map[string]any{"gateway": g.R.Name, "user": user, "sql": clip(what, 2000),
		"reason": reason, "mode": g.R.Mode})
	if g.R.Mode == "watch" {
		return ""
	}
	g.stats.refused.Add(1)
	return reason
}

// ---------------------------------------------------------------- running

func (s *session) run(si *stmtInfo, exec func() (*gomysql.Result, error)) (*gomysql.Result, error) {
	if why := s.decide(si); why != "" {
		return nil, refusal(why)
	}
	switch si.kind {
	case kBegin:
		if err := s.implicitCommit(); err != nil {
			return nil, err
		}
		r, err := exec()
		if err == nil {
			s.begin()
		}
		return r, err
	case kCommit:
		var r *gomysql.Result
		var err error
		if s.writes || s.failed != "" {
			r, err = s.commit(exec)
		} else {
			r, err = exec()
		}
		s.end()
		if si.chain && err == nil {
			s.begin()
		}
		return r, err
	case kRollback:
		r, err := exec()
		s.end()
		if si.chain && err == nil {
			s.begin()
		}
		return r, err
	case kAutocommit:
		if si.auto == 1 {
			if err := s.implicitCommit(); err != nil {
				return nil, err
			}
		}
		r, err := exec()
		if err == nil {
			s.autocommit = si.auto == 1
			if s.autocommit {
				s.end()
			}
		}
		return r, err
	case kImplicit:
		if err := s.implicitCommit(); err != nil {
			return nil, err
		}
		r, err := exec()
		s.end()
		if err == nil && si.ddlTables {
			if serr := s.g.Sync(); serr != nil {
				s.g.M.Audit.Note("gateway_capture_failed", map[string]any{"gateway": s.g.R.Name, "error": serr.Error()})
			}
		}
		return r, err
	case kUse:
		return exec()
	case kWrite:
		if !s.inTx && s.autocommit {
			return s.autocommitWrite(si, exec)
		}
		s.inTx = true
		s.sqlSeen = append(s.sqlSeen, clip(si.text, 4000))
		r, err := exec()
		if err != nil {
			return r, err
		}
		s.writes = true
		if r.AffectedRows > 0 && !s.temps[si.target] {
			seq, err := s.maxSeq()
			if err != nil {
				return nil, err
			}
			if seq <= s.lastSeq && s.g.R.Mode != "watch" {
				s.failed = "a statement changed rows no trigger recorded"
				return nil, refusal("this statement changed rows that could not be recorded (a table without capture, or outside the captured databases); the transaction will be rolled back")
			}
			s.lastSeq = seq
		}
		return r, nil
	}
	r, err := exec()
	if err == nil && si.tempMade != "" {
		s.temps[si.tempMade] = true
	}
	return r, err
}

func (s *session) begin() {
	s.inTx, s.writes, s.failed, s.sqlSeen = true, false, "", nil
}

func (s *session) end() {
	s.inTx, s.writes, s.failed, s.sqlSeen, s.lastSeq = false, false, "", nil, 0
}

// implicitCommit: MySQL commits an open transaction before DDL, BEGIN and SET
// autocommit = 1; what it changed goes to the vault first.
func (s *session) implicitCommit() error {
	if !s.inTx || (!s.writes && s.failed == "") {
		return nil
	}
	_, err := s.commit(func() (*gomysql.Result, error) { return s.up.Execute("COMMIT") })
	s.end()
	return err
}

func (s *session) maxSeq() (int64, error) {
	var parts []string
	for db := range s.logs {
		parts = append(parts, "(SELECT COALESCE(MAX(seq), 0) FROM "+mysql.Q(db)+".countersign_log)")
	}
	r, err := s.up.Execute("SELECT " + strings.Join(parts, " + "))
	if err != nil {
		return 0, err
	}
	return r.GetInt(0, 0)
}

// autocommitWrite: a write outside a transaction runs inside one the gateway opens.
func (s *session) autocommitWrite(si *stmtInfo, exec func() (*gomysql.Result, error)) (*gomysql.Result, error) {
	if _, err := s.up.Execute("START TRANSACTION"); err != nil {
		return nil, err
	}
	s.sqlSeen = []string{clip(si.text, 4000)}
	defer func() { s.sqlSeen = nil }()
	r, err := exec()
	if err != nil {
		_, _ = s.up.Execute("ROLLBACK")
		return nil, err
	}
	rows, rec, why := s.capture()
	if why == "" && r.AffectedRows > 0 && len(rows) == 0 && !s.temps[si.target] && s.g.R.Mode != "watch" {
		why = "the statement changed rows that could not be recorded (a table without capture, or outside the captured databases)"
	}
	if why != "" {
		_, _ = s.up.Execute("ROLLBACK")
		return nil, refusal(why)
	}
	id, batch, why := s.intent(rows, rec)
	if why != "" {
		_, _ = s.up.Execute("ROLLBACK")
		return nil, refusal(why)
	}
	_, cerr := s.up.Execute("COMMIT")
	s.settle(id, batch, cerr)
	if cerr != nil {
		return nil, cerr
	}
	r.Status &^= gomysql.SERVER_STATUS_IN_TRANS
	return r, nil
}

// commit: what the transaction changed goes to the vault, then its COMMIT is passed on.
func (s *session) commit(exec func() (*gomysql.Result, error)) (*gomysql.Result, error) {
	if s.failed != "" && s.g.R.Mode != "watch" {
		_, _ = s.up.Execute("ROLLBACK")
		return nil, refusal(s.failed + "; the transaction was rolled back")
	}
	rows, rec, why := s.capture()
	if why != "" {
		_, _ = s.up.Execute("ROLLBACK")
		return nil, refusal(why + "; the transaction was rolled back")
	}
	id, batch, why := s.intent(rows, rec)
	if why != "" {
		_, _ = s.up.Execute("ROLLBACK")
		return nil, refusal(why + "; the transaction was rolled back")
	}
	r, err := exec()
	s.settle(id, batch, err)
	return r, err
}

// capture reads what the transaction recorded, empties the capture table (inside the
// transaction), checks every row against its table's columns now, and judges the whole.
func (s *session) capture() ([]mysql.Row, *mysql.UndoRecord, string) {
	var parts []string
	for db := range s.logs {
		parts = append(parts, "SELECT "+mysql.Lit(db)+", seq, tbl, h, CAST(old_row AS CHAR), CAST(new_row AS CHAR), COALESCE(@countersign_capture, 0) FROM "+
			mysql.Q(db)+".countersign_log")
	}
	r, err := s.up.Execute(strings.Join(parts, " UNION ALL ") + " ORDER BY 2")
	if err != nil {
		return nil, nil, "reading what the transaction changed: " + err.Error()
	}
	n := r.RowNumber()
	if n == 0 {
		if on, _ := s.up.Execute("SELECT COALESCE(@countersign_capture, 0)"); on != nil {
			if v, _ := on.GetInt(0, 0); v != 1 {
				return nil, nil, "capture is off in this session"
			}
		}
		return nil, nil, ""
	}
	type logRow struct{ db, tbl, h, old, new string }
	var logs []logRow
	tables := map[string]map[string]bool{}
	for i := 0; i < n; i++ {
		var lr logRow
		lr.db, _ = r.GetString(i, 0)
		lr.tbl, _ = r.GetString(i, 2)
		lr.h, _ = r.GetString(i, 3)
		lr.old, _ = r.GetString(i, 4)
		lr.new, _ = r.GetString(i, 5)
		if on, _ := r.GetInt(i, 6); on != 1 {
			return nil, nil, "capture is off in this session"
		}
		logs = append(logs, lr)
		if tables[lr.db] == nil {
			tables[lr.db] = map[string]bool{}
		}
		tables[lr.db][lr.tbl] = true
	}
	for db := range tables {
		if _, err := s.up.Execute("DELETE FROM " + mysql.Q(db) + ".countersign_log"); err != nil {
			return nil, nil, err.Error()
		}
	}
	s.lastSeq = 0
	// the tables as they are now (this transaction holds their metadata locks, so as they
	// were when it wrote)
	rec := &mysql.UndoRecord{Tables: map[string]*mysql.Table{}}
	for db, ts := range tables {
		var names []string
		for t := range ts {
			names = append(names, t)
		}
		got, err := mysql.Columns(s.up, db, names)
		if err != nil {
			return nil, nil, err.Error()
		}
		for _, t := range got {
			rec.Tables[t.Key()] = t
		}
	}
	idx := map[string]int{}
	var rows []mysql.Row
	stale := map[string]bool{}
	for _, l := range logs {
		t := rec.Tables[l.db+"."+l.tbl]
		if t == nil || t.Hash != l.h {
			stale[l.db] = true
			continue
		}
		src := l.new
		if src == "" {
			src = l.old
		}
		k := l.db + "." + l.tbl + "\x00" + keyOf(t, src)
		if l.old != "" && l.new != "" {
			if ok := keyOf(t, l.old) == keyOf(t, l.new); !ok {
				// the key changed: the row's old key goes, the new one comes
				s.mergeRow(&rows, idx, l.db+"."+l.tbl+"\x00"+keyOf(t, l.old), mysql.Row{DB: l.db, Table: l.tbl, Before: l.old})
				s.mergeRow(&rows, idx, k, mysql.Row{DB: l.db, Table: l.tbl, After: l.new})
				continue
			}
		}
		s.mergeRow(&rows, idx, k, mysql.Row{DB: l.db, Table: l.tbl, Before: l.old, After: l.new})
	}
	if len(stale) > 0 {
		go func() { _ = s.g.Sync() }()
		return nil, nil, "a table changed since its capture was installed (it is being reinstalled); run the transaction again"
	}
	kept := rows[:0]
	for _, r := range rows {
		if mysql.Canon(r.Before) != mysql.Canon(r.After) {
			kept = append(kept, r)
		}
	}
	rows = kept
	rec.Rows = rows
	if why := s.judgeRows(rows, rec); why != "" {
		return nil, nil, why
	}
	return rows, rec, ""
}

// mergeRow folds a row's changes within the transaction: its state before the first, after the last.
func (s *session) mergeRow(rows *[]mysql.Row, idx map[string]int, k string, r mysql.Row) {
	if i, ok := idx[k]; ok {
		(*rows)[i].After = r.After
		return
	}
	idx[k] = len(*rows)
	*rows = append(*rows, r)
}

func keyOf(t *mysql.Table, row string) string {
	var m map[string]json.RawMessage
	_ = json.Unmarshal([]byte(row), &m)
	var parts []string
	for _, k := range t.PK {
		parts = append(parts, string(m[k]))
	}
	if len(t.PK) == 0 {
		return row // no key: each distinct row is its own
	}
	return strings.Join(parts, "\x00")
}

// judgeRows applies the commit rules to what the transaction changed.
func (s *session) judgeRows(rows []mysql.Row, rec *mysql.UndoRecord) string {
	per := map[string]int{}
	deleted := 0
	noPK := []string{}
	cascades := []string{}
	seenNoPK := map[string]bool{}
	for _, r := range rows {
		k := r.DB + "." + r.Table
		per[k]++
		if r.After == "" {
			deleted++
		}
		t := rec.Tables[k]
		if len(t.PK) == 0 && !seenNoPK[k] {
			seenNoPK[k] = true
			noPK = append(noPK, k)
		}
		if c := s.g.cascades(r.DB)[r.Table]; c != nil {
			switch {
			case r.After == "" && r.Before != "" && c.OnDelete:
				cascades = append(cascades, k)
			case r.After != "" && r.Before != "":
				var b, a map[string]json.RawMessage
				_ = json.Unmarshal([]byte(r.Before), &b)
				_ = json.Unmarshal([]byte(r.After), &a)
				for col := range c.OnUpdate {
					if string(b[col]) != string(a[col]) {
						cascades = append(cascades, k)
						break
					}
				}
			}
		}
	}
	frac := 0.0
	touched := []string{}
	for k, n := range per {
		touched = append(touched, k)
		db, t, _ := strings.Cut(k, ".")
		total := s.g.tableSize(s.up, db, t)
		if float64(n) > total {
			total = float64(n)
		}
		if total >= 20 && float64(n)/total > frac {
			frac = float64(n) / total
		}
	}
	f := model.Facts{"rows_affected": len(rows), "rows_deleted": deleted, "tables_touched": touched,
		"table_fraction_changed": frac, "no_primary_key": noPK, "undoable": len(noPK) == 0,
		"foreign_key_cascades": cascades, "requester": s.user, "gateway": s.g.R.Name}
	return s.g.judge(s.user, &model.Action{Connector: "sql", Operation: "commit", Effect: model.Reversible, Facts: f}, "COMMIT")
}

// intent stores what the transaction changed, on a quorum, before it commits.
func (s *session) intent(rows []mysql.Row, rec *mysql.UndoRecord) (id, batch, why string) {
	if len(rows) == 0 {
		return "", "", ""
	}
	if s.g.M.Vault == nil {
		return "", "", "the vault is disabled, so no before state can be kept"
	}
	raw, _ := json.Marshal(rec)
	vr, _ := s.g.Conn.DescribeRows(raw)
	id = newID()
	rc, err := s.g.M.Vault.Append(vault.Entry{Tx: id, Task: clip("gateway "+s.g.R.Name+": "+strings.Join(s.sqlSeen, "; "), 500),
		Requester: s.user, Connector: s.g.Conn.Name(), Phase: "intent", Rows: vr, Undo: raw})
	if err != nil {
		return "", "", "the vault could not store the before state: " + err.Error()
	}
	return id, rc.Batch, ""
}

func (s *session) settle(id, batch string, err error) {
	if batch == "" {
		return
	}
	var me *gomysql.MyError
	phase := "committed"
	if err != nil {
		if !asMyError(err, &me) {
			return // the connection broke: the rows themselves will tell (ResolveInFlight)
		}
		phase = "failed"
	}
	s.g.stats.commits.Add(1)
	s.g.M.Audit.Note("gateway_commit", map[string]any{"tx": id, "gateway": s.g.R.Name, "user": s.user, "outcome": phase})
	s.g.M.Vault.AppendLater(vault.Entry{Tx: id, Requester: s.user, Connector: s.g.Conn.Name(), Phase: phase, Ref: batch})
}

func asMyError(err error, me **gomysql.MyError) bool {
	for e := err; e != nil; {
		if m, ok := e.(*gomysql.MyError); ok {
			*me = m
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
