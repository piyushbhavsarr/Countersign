// Package postgres: the SQL connector for PostgreSQL, built on what the server itself
// reports.
//
//   - Classification: Postgres's own parser (libpg_query) gives the statement tree; the
//     whole tree is searched for data-modifying nodes (so a DELETE inside a CTE counts),
//     transaction control, SET, COPY to/from programs or files, DO/CALL blocks, role and
//     privilege changes, and destructive DDL. Calls to user-defined functions are opaque
//     (the catalog says which functions are built in).
//   - Capture: row triggers installed once (InstallSQL) log the old/new image of every row
//     change - FK cascades included - into a temporary table of this session only.
//   - Staging: one held transaction, one savepoint per statement; a statement policy
//     rejects after seeing its measured effect is rolled back alone.
//   - Undo: every touched row is restored to its recorded image via jsonb_populate_record
//     (typed, exact), after verifying nothing changed since commit, with user triggers
//     suspended (session_replication_role = replica) and capture still on to refuse any
//     change outside the recorded set. Additive DDL (new tables, columns, indexes, views)
//     is inverted; destructive DDL is refused before it runs.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"undolayer/internal/model"
	"undolayer/internal/tx"
)

// ---------------------------------------------------------------- classification

var dataNodes = map[string]string{"InsertStmt": "insert", "UpdateStmt": "update", "DeleteStmt": "delete", "MergeStmt": "merge"}
var privilegeNodes = map[string]bool{"GrantStmt": true, "GrantRoleStmt": true, "CreateRoleStmt": true, "AlterRoleStmt": true,
	"DropRoleStmt": true, "AlterRoleSetStmt": true, "ReassignOwnedStmt": true, "AlterOwnerStmt": true}
var additiveDDL = map[string]bool{"CreateStmt": true, "IndexStmt": true, "ViewStmt": true, "CreateTableAsStmt": true, "CreateSeqStmt": true}
var readTop = map[string]bool{"SelectStmt": true, "VariableShowStmt": true, "ExplainStmt": true}

// views and functions that show or act on other sessions
var sessionViews = map[string]bool{"pg_stat_activity": true, "pg_stat_statements": true, "pg_stat_statements_info": true,
	"pg_locks": true, "pg_blocking_pids": true, "pg_prepared_xacts": true, "pg_stat_replication": true, "pg_stat_ssl": true,
	"pg_stat_gssapi": true, "pg_stat_progress_vacuum": true, "pg_stat_progress_copy": true, "pg_stat_progress_create_index": true}

var sessionFuncs = map[string]bool{"pg_cancel_backend": true, "pg_terminate_backend": true, "pg_stat_get_activity": true,
	"pg_stat_get_backend_activity": true, "pg_stat_get_backend_pid": true, "pg_stat_get_backend_idset": true,
	"pg_stat_statements": true, "pg_stat_statements_reset": true, "pg_blocking_pids": true, "pg_safe_snapshot_blocking_pids": true,
	"pg_log_backend_memory_contexts": true, "pg_signal_backend": true}

func walk(v any, fn func(key string, node map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if m, ok := e.(map[string]any); ok {
				fn(k, m)
			}
			walk(e, fn)
		}
	case []any:
		for _, e := range x {
			walk(e, fn)
		}
	}
}

func relName(n map[string]any) string {
	r, _ := n["relation"].(map[string]any)
	name, _ := r["relname"].(string)
	if s, _ := r["schemaname"].(string); s != "" {
		return s + "." + name
	}
	return name
}

var pgDelay = map[string]bool{"pg_sleep": true, "pg_sleep_for": true, "pg_sleep_until": true}

var pgFileOrProgram = map[string]bool{"pg_read_file": true, "pg_read_binary_file": true, "pg_ls_dir": true,
	"pg_stat_file": true, "lo_import": true, "lo_export": true, "pg_ls_logdir": true, "pg_ls_waldir": true}

// alwaysTrue: an OR operand that is true by its own text: a true constant, or two equal
// constants (or one column) compared for equality.
func alwaysTrue(n map[string]any) bool {
	if c, ok := n["A_Const"].(map[string]any); ok {
		if b, ok := c["boolval"].(map[string]any); ok {
			return b["boolval"] == true
		}
		if iv, ok := c["ival"].(map[string]any); ok {
			return iv["ival"] != nil && fmt.Sprint(iv["ival"]) != "0"
		}
		return false
	}
	if tc, ok := n["TypeCast"].(map[string]any); ok {
		if arg, ok := tc["arg"].(map[string]any); ok {
			if c, ok := arg["A_Const"].(map[string]any); ok {
				if sv, ok := c["sval"].(map[string]any); ok {
					v := strings.ToLower(fmt.Sprint(sv["sval"]))
					return v == "t" || v == "true" || v == "y" || v == "yes" || v == "on" || v == "1"
				}
			}
		}
		return false
	}
	e, ok := n["A_Expr"].(map[string]any)
	if !ok || e["kind"] != "AEXPR_OP" {
		return false
	}
	names, _ := e["name"].([]any)
	op := ""
	if len(names) == 1 {
		if sv, ok := names[0].(map[string]any)["String"].(map[string]any); ok {
			op = fmt.Sprint(sv["sval"])
		}
	}
	if op != "=" && op != "<=" && op != ">=" {
		return false
	}
	l, _ := e["lexpr"].(map[string]any)
	r, _ := e["rexpr"].(map[string]any)
	_, lc := l["A_Const"]
	_, rc := r["A_Const"]
	_, lcol := l["ColumnRef"]
	_, rcol := r["ColumnRef"]
	if !(lc && rc) && !(lcol && rcol) {
		return false
	}
	return canonNode(l) == canonNode(r)
}

// canonNode: a node's JSON without source positions.
func canonNode(n map[string]any) string {
	var strip func(any) any
	strip = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			o := map[string]any{}
			for k, e := range x {
				if k != "location" {
					o[k] = strip(e)
				}
			}
			return o
		case []any:
			o := make([]any, len(x))
			for i, e := range x {
				o[i] = strip(e)
			}
			return o
		}
		return v
	}
	b, _ := json.Marshal(strip(n))
	return string(b)
}

func sortedKeys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// analyzeCache: a bounded cache of Analyze results by statement text. When full it starts
// over (simple, and an application's working set of statements is small).
type factCache struct {
	mu sync.Mutex
	m  map[string]model.Facts
}

var analyzeCache = &factCache{m: map[string]model.Facts{}}

const analyzeCacheSize = 8192

func (c *factCache) get(sql string) (model.Facts, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.m[sql]
	if !ok {
		return nil, false
	}
	return copyFacts(f), true
}

func (c *factCache) put(sql string, f model.Facts) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= analyzeCacheSize {
		c.m = map[string]model.Facts{}
	}
	c.m[sql] = copyFacts(f)
}

// copyFacts: callers add to and change the facts they get; the cached copy stays as it was.
func copyFacts(f model.Facts) model.Facts {
	out := model.Facts{}
	for k, v := range f {
		if l, ok := v.([]string); ok {
			v = append([]string{}, l...)
		}
		out[k] = v
	}
	return out
}

// Analyze turns one statement's parse tree into policy facts. It is a pure function of the
// text, so results are cached by text: an application repeats the same statements (with
// parameters) millions of times, and each is parsed once.
func Analyze(sql string) (model.Facts, error) {
	if f, ok := analyzeCache.get(sql); ok {
		return f, nil
	}
	f, err := analyze(sql)
	if err != nil {
		return nil, err
	}
	analyzeCache.put(sql, f)
	return copyFacts(f), nil
}

func analyze(sql string) (model.Facts, error) {
	js, err := pg_query.ParseToJSON(sql)
	if err != nil {
		return nil, err
	}
	var tree map[string]any
	if err := json.Unmarshal([]byte(js), &tree); err != nil {
		return nil, err
	}
	stmts, _ := tree["stmts"].([]any)
	f := model.Facts{"statements": len(stmts)}
	others, capture := false, false
	sigs := map[string]bool{}
	if fp, err := pg_query.Fingerprint(sql); err == nil {
		f["query_shape"] = fp
	}
	if sc, err := pg_query.Scan(sql); err == nil {
		for i, tk := range sc.Tokens {
			if tk.Token == pg_query.Token_SQL_COMMENT || tk.Token == pg_query.Token_C_COMMENT {
				sigs["comment"] = true
				if i == len(sc.Tokens)-1 && tk.Token == pg_query.Token_SQL_COMMENT && i > 0 {
					sigs["trailing_comment"] = true
				}
			}
		}
	}
	if len(stmts) > 1 {
		sigs["stacked"] = true
	}
	defer func() { f["sql_injection_signals"] = sortedKeys(sigs) }()
	if len(stmts) != 1 {
		return f, nil
	}
	top := ""
	stmt, _ := stmts[0].(map[string]any)["stmt"].(map[string]any)
	for k := range stmt {
		top = k
	}
	f["statement_type"] = top
	writes := map[string]bool{}
	funcs := map[string]bool{}
	ctrl, set, copyExt, opaque, priv, destroys, renames, unsupported, additive := false, []string{}, false, false, false, false, false, false, false
	analyzeExplain := false
	walk(stmt, func(k string, n map[string]any) {
		switch k {
		case "BoolExpr":
			if n["boolop"] == "OR_EXPR" {
				args, _ := n["args"].([]any)
				for _, a := range args {
					if am, ok := a.(map[string]any); ok && alwaysTrue(am) {
						sigs["or_tautology"] = true
					}
				}
			}
		case "SelectStmt":
			if op, _ := n["op"].(string); op == "SETOP_UNION" {
				sigs["union"] = true
			}
		case "RangeVar", "relation":
			schema, _ := n["schemaname"].(string)
			name, _ := n["relname"].(string)
			if schema == "pg_catalog" || schema == "information_schema" || (schema == "" && strings.HasPrefix(name, "pg_")) {
				sigs["system_catalog"] = true
			}
			if sessionViews[name] {
				others = true
			}
			if schema == "undolayer" {
				capture = true
			}
		}
		if kind, ok := dataNodes[k]; ok {
			writes[relName(n)] = true
			_ = kind
		}
		switch {
		case k == "TransactionStmt":
			ctrl = true
		case k == "VariableSetStmt":
			name, _ := n["name"].(string)
			set = append(set, name)
		case k == "CopyStmt":
			if n["is_program"] == true || n["filename"] != nil {
				copyExt = true
			} else {
				unsupported = true
			}
			if n["is_from"] == true {
				writes[relName(n)] = true
			}
		case k == "DoStmt" || k == "CallStmt" || k == "CreateFunctionStmt" || k == "CreateTrigStmt" || k == "CreateEventTrigStmt" || k == "RuleStmt":
			opaque = true
		case privilegeNodes[k]:
			priv = true
		case k == "TruncateStmt":
			destroys = true
		case k == "DropStmt":
			switch n["removeType"] {
			case "OBJECT_TABLE", "OBJECT_SCHEMA", "OBJECT_MATVIEW", "OBJECT_DATABASE", "OBJECT_SEQUENCE", "OBJECT_TYPE":
				destroys = true
			default:
				unsupported = true
			}
		case k == "AlterTableStmt":
			cmds, _ := n["cmds"].([]any)
			for _, c := range cmds {
				cm, _ := c.(map[string]any)["AlterTableCmd"].(map[string]any)
				switch cm["subtype"] {
				case "AT_DropColumn":
					destroys = true
				case "AT_AddColumn":
					additive = true
				default:
					unsupported = true
				}
			}
		case k == "RenameStmt":
			renames = true
		case additiveDDL[k]:
			additive = true
		case k == "FuncCall":
			if names, ok := n["funcname"].([]any); ok {
				parts := []string{}
				for _, x := range names {
					if s, ok := x.(map[string]any)["String"].(map[string]any); ok {
						parts = append(parts, fmt.Sprint(s["sval"]))
					}
				}
				funcs[strings.Join(parts, ".")] = true
			}
		case k == "ExplainStmt":
			opts, _ := n["options"].([]any)
			for _, o := range opts {
				if d, ok := o.(map[string]any)["DefElem"].(map[string]any); ok && d["defname"] == "analyze" {
					analyzeExplain = true // EXPLAIN ANALYZE executes the statement
				}
			}
		}
	})
	if !readTop[top] && !additiveDDL[top] && top != "TransactionStmt" && top != "VariableSetStmt" && top != "CopyStmt" &&
		dataNodes[top] == "" && top != "AlterTableStmt" && top != "DropStmt" && top != "RenameStmt" && top != "TruncateStmt" &&
		!privilegeNodes[top] && top != "DoStmt" && top != "CallStmt" && top != "CreateFunctionStmt" && top != "CreateTrigStmt" &&
		top != "CreateEventTrigStmt" && top != "RuleStmt" {
		f["unknown_statement"] = true
	}
	tl := []string{}
	for t := range writes {
		tl = append(tl, t)
	}
	sort.Strings(tl)
	fl := []string{}
	for fn := range funcs {
		fl = append(fl, fn)
	}
	sort.Strings(fl)
	f["tables_written"], f["functions"] = tl, fl
	for _, fn := range fl {
		if sessionFuncs[fn[strings.LastIndex(fn, ".")+1:]] {
			others = true
		}
	}
	// what other sessions run and hold (through a gateway every client is the same database
	// user, so these would show one client another's statements, with their values)
	f["other_sessions"] = others
	for _, fn := range fl {
		if strings.HasPrefix(fn, "undolayer.") {
			capture = true
		}
	}
	// the capture schema: the outbox holds every gateway client's before states
	f["touches_capture"] = capture
	for _, fn := range fl {
		base := fn[strings.LastIndex(fn, ".")+1:]
		switch {
		case pgDelay[base]:
			sigs["time_delay"] = true
		case pgFileOrProgram[base] || strings.HasPrefix(base, "dblink"):
			sigs["file_or_program"] = true
		}
	}
	if copyExt {
		sigs["file_or_program"] = true
	}
	f["transaction_control"], f["pragma_set"], f["copy_external"], f["opaque_code"] = ctrl, set, copyExt, opaque
	f["privilege_change"], f["destroys_schema"], f["renames_schema"], f["schema_unsupported"] = priv, destroys, renames, unsupported
	f["schema_change"] = additive || destroys || renames || unsupported
	f["attach"] = false
	f["is_write"] = len(tl) > 0 || ctrl || len(set) > 0 || copyExt || opaque || priv || additive || destroys || renames || unsupported || analyzeExplain
	return f, nil
}

// ---------------------------------------------------------------- state

type Event struct {
	T   string `json:"t"`
	Op  string `json:"op"`
	KO  string `json:"ko,omitempty"`
	KN  string `json:"kn,omitempty"`
	Old string `json:"old,omitempty"` // jsonb text (canonical)
	New string `json:"new,omitempty"`
}

type Created struct {
	Kind   string `json:"kind"` // relation | column
	Rel    string `json:"rel"`
	RelKnd string `json:"relkind,omitempty"`
	Column string `json:"column,omitempty"`
}

type Change struct {
	ActionID string    `json:"action_id"`
	SQL      string    `json:"sql"`
	Events   []Event   `json:"events"`
	Created  []Created `json:"created,omitempty"`
}

type State struct {
	Changes    []*Change        `json:"changes"`
	TableStart map[string]int64 `json:"table_start"`
	Seq        int64            `json:"seq"`
}

type UndoRecord struct {
	DSN     string    `json:"dsn"`
	Changes []*Change `json:"changes"`
	// XID is the held transaction's id (txid_current), recorded before COMMIT so that after
	// a crash the server itself can say whether the commit happened (txid_status).
	XID int64 `json:"xid,omitempty"`
}

type Connector struct {
	tx.Base
	// Hide: not offered to agents as tools (a gateway's: only undo and restore use it).
	Hide            bool
	DSN             string
	Env             string
	FractionMinRows int64
	MaxPreviewRows  int
}

func New(dsn string) *Connector {
	return &Connector{Base: tx.Base{ConnName: "sql"}, DSN: dsn, Env: "production", FractionMinRows: 20, MaxPreviewRows: 20}
}

func (c *Connector) Operations() map[string]tx.OpSchema {
	p := map[string]any{"sql": map[string]any{"type": "string"}, "params": map[string]any{"type": "array"}}
	return map[string]tx.OpSchema{
		"query": {Description: "Run a read-only SQL query (sees this transaction's staged writes).", Properties: p, Required: []string{"sql"}},
		"execute": {Description: "Run SQL that writes. Staged inside the transaction; nothing is visible to others until commit. " +
			"Transaction control (BEGIN/COMMIT) is managed for you.", Properties: p, Required: []string{"sql"}},
		"restore_rows": {Description: "Put rows back as they were before an earlier task, without undoing the rest of it. " +
			"Each row must still be as that task left it (on_conflict: fail, the default, or skip).",
			Properties: map[string]any{"source_tx": map[string]any{"type": "string"},
				"tables":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"keys":        map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
				"on_conflict": map[string]any{"type": "string", "enum": []any{"fail", "skip"}}},
			Required: []string{"source_tx"}},
	}
}

type live struct {
	conn  *pgx.Conn
	ctx   context.Context
	saves []string
	pk    map[string][]string
}

func (l *live) exec(q string, args ...any) error {
	_, err := l.conn.Exec(l.ctx, q, args...)
	return err
}

func (l *live) CloseForCrash() { _ = l.conn.Close(context.Background()) }

const tempLog = `CREATE TEMP TABLE IF NOT EXISTS undolayer_log(seq bigserial PRIMARY KEY, tbl text, op text, old_row jsonb, new_row jsonb) ON COMMIT DROP`

func open(dsn, txid string, replica bool) (*live, error) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	l := &live{conn: conn, ctx: ctx, pk: map[string][]string{}}
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT to_regproc('undolayer.capture') IS NOT NULL").Scan(&ok); err != nil || !ok {
		conn.Close(ctx)
		return nil, errors.New("capture is not installed in this database; run `undolayer pg install` once")
	}
	steps := []string{"BEGIN", "SET LOCAL lock_timeout = '5s'", "SET LOCAL statement_timeout = '120s'"}
	if replica {
		steps = append(steps, "SET LOCAL session_replication_role = replica")
	}
	for _, s := range steps {
		if err := l.exec(s); err != nil {
			conn.Close(ctx)
			return nil, err
		}
	}
	if err := l.exec("SELECT set_config('undolayer.tx', $1, true)", txid); err != nil {
		conn.Close(ctx)
		return nil, err
	}
	if err := l.exec(tempLog); err != nil {
		conn.Close(ctx)
		return nil, err
	}
	return l, nil
}

func (c *Connector) live(t *tx.Tx) (*live, error) {
	if h, ok := t.Handles[c.Name()].(*live); ok {
		return h, nil
	}
	l, err := open(c.DSN, t.ID, false)
	if err != nil {
		return nil, err
	}
	t.Handles[c.Name()] = l
	st := tx.GetState[State](t, c.Name())
	if st.TableStart == nil {
		st.TableStart = map[string]int64{}
	}
	return l, nil
}

func (l *live) pkCols(table string) ([]string, error) {
	if p, ok := l.pk[table]; ok {
		return p, nil
	}
	rows, err := l.conn.Query(l.ctx, `SELECT a.attname FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
		WHERE i.indrelid = $1::regclass AND i.indisprimary ORDER BY array_position(i.indkey, a.attnum)`, table)
	if err != nil {
		return nil, err
	}
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	rows.Close()
	l.pk[table] = out
	return out, rows.Err()
}

func keyOf(row string, pk []string) string {
	var m map[string]json.RawMessage
	_ = json.Unmarshal([]byte(row), &m)
	k := map[string]json.RawMessage{}
	for _, p := range pk {
		k[p] = m[p]
	}
	b, _ := json.Marshal(k)
	return string(b)
}

func (l *live) drain(st *State) ([]Event, []string, error) {
	rows, err := l.conn.Query(l.ctx, "SELECT seq, tbl, op, old_row::text, new_row::text FROM pg_temp.undolayer_log WHERE seq > $1 ORDER BY seq", st.Seq)
	if err != nil {
		return nil, nil, err
	}
	type raw struct {
		seq        int64
		tbl, op    string
		oldR, newR *string
	}
	var rs []raw
	for rows.Next() {
		var r raw
		if err := rows.Scan(&r.seq, &r.tbl, &r.op, &r.oldR, &r.newR); err != nil {
			rows.Close()
			return nil, nil, err
		}
		rs = append(rs, r)
	}
	rows.Close()
	var evs []Event
	var noPK []string
	for _, r := range rs {
		st.Seq = r.seq
		pk, err := l.pkCols(r.tbl)
		if err != nil {
			return nil, nil, err
		}
		if len(pk) == 0 {
			noPK = append(noPK, r.tbl)
		}
		e := Event{T: r.tbl}
		switch r.op {
		case "INSERT":
			e.Op, e.New, e.KN = "I", *r.newR, keyOf(*r.newR, pk)
		case "UPDATE":
			e.Op, e.Old, e.New, e.KO, e.KN = "U", *r.oldR, *r.newR, keyOf(*r.oldR, pk), keyOf(*r.newR, pk)
		case "DELETE":
			e.Op, e.Old, e.KO = "D", *r.oldR, keyOf(*r.oldR, pk)
		}
		evs = append(evs, e)
	}
	return evs, noPK, nil
}

// catalog: relations and columns outside system schemas (for additive-DDL inversion).
func (l *live) catalog() (map[string]string, map[string]bool, error) {
	rels, cols := map[string]string{}, map[string]bool{}
	rows, err := l.conn.Query(l.ctx, `SELECT c.oid::regclass::text, c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname NOT IN ('pg_catalog','information_schema','undolayer') AND n.nspname NOT LIKE 'pg_temp%' AND n.nspname NOT LIKE 'pg_toast%'`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var n, k string
		_ = rows.Scan(&n, &k)
		rels[n] = k
	}
	rows.Close()
	rows, err = l.conn.Query(l.ctx, `SELECT a.attrelid::regclass::text, a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r','p')
		AND n.nspname NOT IN ('pg_catalog','information_schema','undolayer') AND n.nspname NOT LIKE 'pg_temp%' AND n.nspname NOT LIKE 'pg_toast%'`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var r, a string
		_ = rows.Scan(&r, &a)
		cols[r+"\x00"+a] = true
	}
	rows.Close()
	return rels, cols, nil
}

// ---------------------------------------------------------------- tx.Connector

func params(a map[string]any) []any {
	l, _ := a["params"].([]any)
	return l
}

func (c *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	if op == "restore_rows" {
		return c.classifyRestore(t, args)
	}
	sql, _ := args["sql"].(string)
	f, err := Analyze(sql)
	base := model.Facts{"env": c.Env, "dialect": "postgres"}
	if err != nil {
		base["compile_error"], base["is_write"] = err.Error(), false
		return model.Read, base, nil
	}
	for k, v := range base {
		f[k] = v
	}
	if n, _ := f["statements"].(int); n > 1 {
		f["multi_statement"] = true
		return model.Reversible, f, nil
	}
	if fl, _ := f["functions"].([]string); len(fl) > 0 {
		l, err := c.live(t)
		if err != nil {
			return "", nil, err
		}
		var user []string
		for _, fn := range fl {
			var builtin bool
			err := l.conn.QueryRow(l.ctx, `SELECT coalesce(bool_and(n.nspname = 'pg_catalog'), true) FROM pg_proc p
				JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.oid IN (SELECT oid FROM pg_proc WHERE proname = $1)`,
				fn[strings.LastIndex(fn, ".")+1:]).Scan(&builtin)
			if err != nil || !builtin || strings.Contains(fn, ".") && !strings.HasPrefix(fn, "pg_catalog.") {
				user = append(user, fn)
			}
		}
		if len(user) > 0 {
			f["opaque_code"], f["user_functions"] = true, user
		}
	}
	if op == "query" && f["is_write"] == true {
		f["write_via_query"] = true
	}
	if f["is_write"] == true || f["opaque_code"] == true {
		return model.Reversible, f, nil
	}
	return model.Read, f, nil
}

func display(rows pgx.Rows) ([]any, error) {
	defer rows.Close()
	var out []any
	fields := rows.FieldDescriptions()
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		m := map[string]any{}
		for i, f := range fields {
			v := vals[i]
			switch x := v.(type) {
			case time.Time:
				v = x.Format(time.RFC3339Nano)
			case []byte:
				v = fmt.Sprintf("\\x%x", x)
			}
			m[f.Name] = v
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (c *Connector) Stage(t *tx.Tx, a *model.Action) (any, error) {
	if a.Operation == "restore_rows" {
		return c.stageRestore(t, a)
	}
	sql, _ := a.Args["sql"].(string)
	if e, ok := a.Facts["compile_error"].(string); ok {
		return nil, errors.New(e)
	}
	if a.Facts["write_via_query"] == true {
		return nil, errors.New("sql.query is read-only; use sql.execute for statements that write")
	}
	l, err := c.live(t)
	if err != nil {
		return nil, err
	}
	st := tx.GetState[State](t, c.Name())
	if a.Facts["multi_statement"] == true {
		return c.script(t, a, sql)
	}
	sp := "ul_" + strings.ReplaceAll(a.ID, "-", "_")
	if err := l.exec("SAVEPOINT " + sp); err != nil {
		return nil, err
	}
	l.saves = append(l.saves, sp)
	fail := func(err error) (any, error) { _ = c.rewind(t, sp, -1); return nil, err }
	var relsB map[string]string
	var colsB map[string]bool
	if a.Facts["schema_change"] == true {
		if relsB, colsB, err = l.catalog(); err != nil {
			return fail(err)
		}
	}
	rows, err := l.conn.Query(l.ctx, sql, params(a.Args)...)
	if err != nil {
		return fail(err)
	}
	result, err := display(rows)
	if err != nil {
		return fail(err)
	}
	events, noPK, err := l.drain(st)
	if err != nil {
		return fail(err)
	}
	ch := &Change{ActionID: a.ID, SQL: sql, Events: events}
	if relsB != nil {
		relsA, colsA, err := l.catalog()
		if err != nil {
			return fail(err)
		}
		for r, k := range relsA {
			if _, ok := relsB[r]; !ok {
				ch.Created = append(ch.Created, Created{Kind: "relation", Rel: r, RelKnd: k})
			}
		}
		for rc := range colsA {
			parts := strings.SplitN(rc, "\x00", 2)
			if _, newRel := relsB[parts[0]]; !colsB[rc] && newRel {
				ch.Created = append(ch.Created, Created{Kind: "column", Rel: parts[0], Column: parts[1]})
			}
		}
		lost := false
		for r := range relsB {
			if _, ok := relsA[r]; !ok {
				lost = true
			}
		}
		for rc := range colsB {
			if parts := strings.SplitN(rc, "\x00", 2); !colsA[rc] {
				if _, still := relsA[parts[0]]; still {
					lost = true
				}
			}
		}
		if lost {
			a.Facts["destroys_schema"] = true
		}
	}
	if a.Effect == model.Read && len(events) == 0 && len(ch.Created) == 0 {
		_ = l.exec("RELEASE SAVEPOINT " + sp)
		l.saves = l.saves[:len(l.saves)-1]
		if len(result) > 1000 {
			result = result[:1000]
		}
		return map[string]any{"rows": result, "row_count": len(result)}, nil
	}
	if a.Effect == model.Read {
		a.Facts["wrote_despite_read"] = true // a "read" changed data (e.g. through a function)
	}
	st.Changes = append(st.Changes, ch)
	c.recordStart(l, st, events)
	slots := netSlots(events)
	affected, deleted, inserted := 0, 0, 0
	for _, ss := range slots {
		affected += len(ss)
		for _, s := range ss {
			if s.Orig != "" && s.Final == "" {
				deleted++
			}
			if s.Final != "" && s.Orig == "" {
				inserted++
			}
		}
	}
	a.Facts["rows_affected"], a.Facts["rows_deleted"], a.Facts["rows_inserted"] = affected, deleted, inserted
	a.Facts["undoable"] = len(noPK) == 0
	if len(noPK) > 0 {
		a.Facts["no_primary_key"] = noPK
	}
	a.Facts["_reevaluate"] = true
	out := map[string]any{"rows_affected": affected, "staged": true}
	if len(result) > 0 {
		if len(result) > 100 {
			result = result[:100]
		}
		out["returning"] = result
	}
	return out, nil
}

func (c *Connector) recordStart(l *live, st *State, events []Event) {
	slots := netSlots(events)
	for tbl, ss := range slots {
		if _, ok := st.TableStart[tbl]; ok {
			continue
		}
		var n int64
		_ = l.conn.QueryRow(l.ctx, "SELECT count(*) FROM "+tbl).Scan(&n)
		for _, s := range ss {
			if s.Final != "" && s.Orig == "" {
				n--
			}
			if s.Orig != "" && s.Final == "" {
				n++
			}
		}
		st.TableStart[tbl] = n
	}
}

func (c *Connector) script(t *tx.Tx, a *model.Action, sql string) (any, error) {
	parts, err := pg_query.SplitWithParser(sql, true)
	if err != nil {
		return nil, err
	}
	l, _ := c.live(t)
	sp := "ul_" + strings.ReplaceAll(a.ID, "-", "_")
	if err := l.exec("SAVEPOINT " + sp); err != nil {
		return nil, err
	}
	l.saves = append(l.saves, sp)
	n := len(tx.GetState[State](t, c.Name()).Changes)
	var results []any
	for _, p := range parts {
		r, err := t.CallNested(c.Name(), a.Operation, map[string]any{"sql": p})
		if err != nil {
			_ = c.rewind(t, sp, n)
			return nil, err
		}
		results = append(results, r)
	}
	return map[string]any{"statements": len(results), "results": results, "staged": true}, nil
}

func (c *Connector) rewind(t *tx.Tx, sp string, keep int) error {
	l, err := c.live(t)
	if err != nil {
		return err
	}
	if err := l.exec("ROLLBACK TO SAVEPOINT " + sp); err != nil {
		return err
	}
	_ = l.exec("RELEASE SAVEPOINT " + sp)
	for i := len(l.saves) - 1; i >= 0; i-- {
		if l.saves[i] == sp {
			l.saves = l.saves[:i]
			break
		}
	}
	st := tx.GetState[State](t, c.Name())
	if keep >= 0 && keep < len(st.Changes) {
		st.Changes = st.Changes[:keep]
	}
	_ = l.conn.QueryRow(l.ctx, "SELECT coalesce(max(seq), 0) FROM pg_temp.undolayer_log").Scan(&st.Seq)
	return nil
}

func (c *Connector) Settle(t *tx.Tx, a *model.Action) {
	l, ok := t.Handles[c.Name()].(*live)
	if !ok {
		return
	}
	sp := "ul_" + strings.ReplaceAll(a.ID, "-", "_")
	for i, s := range l.saves {
		if s == sp {
			_ = l.exec("RELEASE SAVEPOINT " + sp)
			l.saves = append(l.saves[:i], l.saves[i+1:]...)
			return
		}
	}
}

func (c *Connector) Discard(t *tx.Tx, a *model.Action) bool {
	sp := "ul_" + strings.ReplaceAll(a.ID, "-", "_")
	st := tx.GetState[State](t, c.Name())
	idx := len(st.Changes)
	for i, ch := range st.Changes {
		if ch.ActionID == a.ID {
			idx = i
		}
	}
	return c.rewind(t, sp, idx) == nil
}

// ---------------------------------------------------------------- net effect

type slot struct{ Key, Orig, Final string }

func netSlots(events []Event) map[string]map[string]*slot {
	type origin struct {
		key, row string
		set      bool
	}
	chains, final := map[string]map[string]origin{}, map[string]map[string]string{}
	ended := map[string][]origin{}
	for _, e := range events {
		if chains[e.T] == nil {
			chains[e.T], final[e.T] = map[string]origin{}, map[string]string{}
		}
		ch, fin := chains[e.T], final[e.T]
		switch e.Op {
		case "I":
			ch[e.KN], fin[e.KN] = origin{}, e.New
		case "U":
			o, ok := ch[e.KO]
			if !ok {
				o = origin{key: e.KO, row: e.Old, set: true}
			}
			delete(ch, e.KO)
			delete(fin, e.KO)
			ch[e.KN], fin[e.KN] = o, e.New
		case "D":
			o, ok := ch[e.KO]
			if !ok {
				o = origin{key: e.KO, row: e.Old, set: true}
			}
			delete(ch, e.KO)
			delete(fin, e.KO)
			ended[e.T] = append(ended[e.T], o)
		}
	}
	out := map[string]map[string]*slot{}
	get := func(t, k string) *slot {
		if out[t] == nil {
			out[t] = map[string]*slot{}
		}
		if out[t][k] == nil {
			out[t][k] = &slot{Key: k}
		}
		return out[t][k]
	}
	for t, ch := range chains {
		for cur, o := range ch {
			get(t, cur).Final = final[t][cur]
			if o.set {
				get(t, o.key).Orig = o.row
			}
		}
	}
	for t, os := range ended {
		for _, o := range os {
			if o.set {
				get(t, o.key).Orig = o.row
			}
		}
	}
	for t, ss := range out {
		for k, s := range ss {
			if s.Orig == s.Final {
				delete(ss, k)
			}
		}
		if len(ss) == 0 {
			delete(out, t)
		}
	}
	return out
}

// ---------------------------------------------------------------- preview / totals

func (c *Connector) Preview(t *tx.Tx) map[string]any {
	st := tx.PeekState[State](t, c.Name())
	if st == nil || len(st.Changes) == 0 {
		return nil
	}
	var stmts []any
	for _, ch := range st.Changes {
		item := map[string]any{"sql": ch.SQL}
		n := 0
		tables := map[string]any{}
		for tbl, ss := range netSlots(ch.Events) {
			n += len(ss)
			var del, ins, upd []any
			for _, s := range ss {
				var o, f any
				_ = json.Unmarshal([]byte(s.Orig), &o)
				_ = json.Unmarshal([]byte(s.Final), &f)
				switch {
				case s.Orig != "" && s.Final == "":
					del = append(del, o)
				case s.Final != "" && s.Orig == "":
					ins = append(ins, f)
				default:
					upd = append(upd, map[string]any{"old": o, "new": f})
				}
			}
			tb := map[string]any{}
			for name, l := range map[string][]any{"deleted": del, "inserted": ins, "updated": upd} {
				if len(l) == 0 {
					continue
				}
				if len(l) > c.MaxPreviewRows {
					tb[name+"_total"] = len(l)
					l = l[:c.MaxPreviewRows]
				}
				tb[name] = l
			}
			tables[tbl] = tb
		}
		item["rows_affected"] = n
		if len(tables) > 0 {
			item["tables"] = tables
		}
		if len(ch.Created) > 0 {
			item["created"] = ch.Created
		}
		stmts = append(stmts, item)
	}
	return map[string]any{"database": redact(c.DSN), "env": c.Env, "statements": stmts}
}

// Hidden: see tx.Hidden.
func (c *Connector) Hidden() bool { return c.Hide }

// RecordDSN is the database name written into undo records made for this connector by
// others (the gateway): the DSN without its password, which stays in the configuration.
func (c *Connector) RecordDSN() string { return redact(c.DSN) }

// dsnOf: the DSN to connect with for a recorded one (the password comes from here).
func (c *Connector) dsnOf(recorded string) string {
	if recorded == redact(c.DSN) {
		return c.DSN
	}
	return recorded
}

// sameDB: a record names this connector's database.
func (c *Connector) sameDB(recorded string) bool {
	return recorded == c.DSN || recorded == redact(c.DSN)
}

// ResolveInFlight tells, for a record whose commit may not have happened (written before
// COMMIT, by the gateway), whether the server committed it: from txid_status.
func (c *Connector) ResolveInFlight(raw json.RawMessage) (committed, known bool, err error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.XID == 0 {
		return false, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, c.dsnOf(rec.DSN))
	if err != nil {
		return false, false, err
	}
	defer conn.Close(ctx)
	var status *string
	if err := conn.QueryRow(ctx, "SELECT txid_status($1)", rec.XID).Scan(&status); err != nil {
		return false, false, err
	}
	if status == nil || *status == "in progress" {
		return false, false, nil
	}
	return *status == "committed", true, nil
}

// KeyOf is a row's primary key, as captured (exported for the gateway).
func KeyOf(row string, pk []string) string { return keyOf(row, pk) }

func redact(dsn string) string {
	if i := strings.Index(dsn, "://"); i >= 0 {
		if j := strings.Index(dsn[i+3:], "@"); j >= 0 {
			cred := dsn[i+3 : i+3+j]
			if k := strings.Index(cred, ":"); k >= 0 {
				return dsn[:i+3] + cred[:k] + ":***" + dsn[i+3+j:]
			}
		}
	}
	return dsn
}

func (c *Connector) Totals(t *tx.Tx) map[string]float64 {
	st := tx.PeekState[State](t, c.Name())
	if st == nil {
		return nil
	}
	var all []Event
	for _, ch := range st.Changes {
		all = append(all, ch.Events...)
	}
	changed, worst := 0, 0.0
	for tbl, ss := range netSlots(all) {
		d := 0
		for _, s := range ss {
			if s.Orig != "" {
				d++
			}
		}
		changed += len(ss)
		if start := st.TableStart[tbl]; start >= c.FractionMinRows {
			if f := float64(d) / float64(start); f > worst {
				worst = f
			}
		}
	}
	return map[string]float64{"rows_changed": float64(changed), "max_table_fraction_changed": worst}
}

func (c *Connector) Commit(t *tx.Tx) (any, error) {
	l, ok := t.Handles[c.Name()].(*live)
	if !ok {
		return nil, nil
	}
	delete(t.Handles, c.Name())
	defer l.conn.Close(context.Background())
	if err := l.exec("COMMIT"); err != nil {
		return nil, err
	}
	st := tx.PeekState[State](t, c.Name())
	var ch []*Change
	if st != nil {
		for _, x := range st.Changes {
			if len(x.Events) > 0 || len(x.Created) > 0 {
				ch = append(ch, x)
			}
		}
	}
	if len(ch) == 0 {
		return nil, nil
	}
	return &UndoRecord{DSN: c.DSN, Changes: ch}, nil
}

// Intent: the row images were captured while staging; the transaction id lets recovery ask
// the server whether COMMIT happened.
func (c *Connector) Intent(t *tx.Tx) (any, error) {
	l, ok := t.Handles[c.Name()].(*live)
	if !ok {
		return nil, nil
	}
	st := tx.PeekState[State](t, c.Name())
	var ch []*Change
	if st != nil {
		for _, x := range st.Changes {
			if len(x.Events) > 0 || len(x.Created) > 0 {
				ch = append(ch, x)
			}
		}
	}
	if len(ch) == 0 {
		return nil, nil
	}
	var xid int64
	if err := l.conn.QueryRow(l.ctx, "SELECT txid_current()").Scan(&xid); err != nil {
		return nil, err
	}
	return &UndoRecord{DSN: c.DSN, Changes: ch, XID: xid}, nil
}

// UndoInFlight asks the server whether the interrupted COMMIT happened, and undoes it if so.
func (c *Connector) UndoInFlight(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	if rec.XID == 0 || len(rec.Changes) == 0 {
		return nil
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, c.dsnOf(rec.DSN))
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	for i := 0; i < 50; i++ {
		var status *string
		if err := conn.QueryRow(ctx, "SELECT txid_status($1)", rec.XID).Scan(&status); err != nil {
			return err
		}
		switch {
		case status == nil:
			return model.Conflict("the server no longer knows transaction %d (too old to tell whether it committed)", rec.XID)
		case *status == "aborted":
			return nil // never happened
		case *status == "committed":
			return c.Undo(raw)
		}
		time.Sleep(200 * time.Millisecond) // "in progress": the dying connection is still being cleaned up
	}
	return model.Conflict("transaction %d is still in progress on the server", rec.XID)
}

func (c *Connector) Rollback(t *tx.Tx) error {
	l, ok := t.Handles[c.Name()].(*live)
	if !ok {
		return nil
	}
	delete(t.Handles, c.Name())
	defer l.conn.Close(context.Background())
	return l.exec("ROLLBACK")
}

// Recover: the server rolled the transaction back when the connection died.
func (c *Connector) Recover(t *tx.Tx) error { return nil }

// ---------------------------------------------------------------- undo

func (c *Connector) Undo(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	l, err := open(c.dsnOf(rec.DSN), "undo", true)
	if err != nil {
		return err
	}
	defer l.conn.Close(context.Background())
	if err := c.undo(l, &rec); err != nil {
		_ = l.exec("ROLLBACK")
		return err
	}
	return l.exec("COMMIT")
}

type colInfo struct {
	names    []string // restorable columns (not generated)
	settable []string // updatable columns (also not identity ALWAYS)
}

func (l *live) columns(tbl string) (colInfo, error) {
	rows, err := l.conn.Query(l.ctx, `SELECT attname, attgenerated::text, attidentity::text FROM pg_attribute
		WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum`, tbl)
	if err != nil {
		return colInfo{}, err
	}
	defer rows.Close()
	var ci colInfo
	for rows.Next() {
		var n, g, id string
		_ = rows.Scan(&n, &g, &id)
		if g != "" {
			continue
		}
		ci.names = append(ci.names, pgx.Identifier{n}.Sanitize())
		if id != "a" {
			ci.settable = append(ci.settable, pgx.Identifier{n}.Sanitize())
		}
	}
	return ci, rows.Err()
}

func (l *live) current(tbl string, pk []string, key string) (string, error) {
	cols := make([]string, len(pk))
	for i, p := range pk {
		cols[i] = pgx.Identifier{p}.Sanitize()
	}
	pl := strings.Join(cols, ", ")
	var s *string
	err := l.conn.QueryRow(l.ctx, fmt.Sprintf("SELECT to_jsonb(t)::text FROM %s t WHERE (%s) = (SELECT %s FROM jsonb_populate_record(NULL::%s, $1::jsonb))",
		tbl, pl, pl, tbl), key).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil || s == nil {
		return "", err
	}
	return *s, nil
}

func (c *Connector) undo(l *live, rec *UndoRecord) error {
	first := true
	ch := rec.Changes
	for i := len(ch) - 1; i >= 0; {
		if len(ch[i].Created) > 0 && len(ch[i].Events) == 0 {
			if err := c.undoCreated(l, ch[i]); err != nil {
				return err
			}
			i--
			first = false
			continue
		}
		j := i
		for j >= 0 && !(len(ch[j].Created) > 0 && len(ch[j].Events) == 0) {
			j--
		}
		var evs []Event
		for _, x := range ch[j+1 : i+1] {
			evs = append(evs, x.Events...)
		}
		if err := c.restore(l, evs, first); err != nil {
			return err
		}
		for k := i; k > j; k-- {
			if len(ch[k].Created) > 0 {
				if err := c.undoCreated(l, ch[k]); err != nil {
					return err
				}
			}
		}
		first = false
		i = j
	}
	return nil
}

func (c *Connector) undoCreated(l *live, ch *Change) error {
	// Tables first: dropping a table also drops what it owns (its indexes, constraint
	// indexes, serial sequences). Then whatever else still exists.
	ordered := []Created{}
	for _, pass := range []func(Created) bool{
		func(x Created) bool { return x.Kind == "column" },
		func(x Created) bool { return x.Kind == "relation" && (x.RelKnd == "r" || x.RelKnd == "p") },
		func(x Created) bool { return x.Kind == "relation" && x.RelKnd != "r" && x.RelKnd != "p" },
	} {
		for _, x := range ch.Created {
			if pass(x) {
				ordered = append(ordered, x)
			}
		}
	}
	for _, cr := range ordered {
		switch cr.Kind {
		case "column":
			if err := l.exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", cr.Rel, pgx.Identifier{cr.Column}.Sanitize())); err != nil {
				return err
			}
		case "relation":
			var exists bool
			_ = l.conn.QueryRow(l.ctx, "SELECT to_regclass($1) IS NOT NULL", cr.Rel).Scan(&exists)
			if !exists {
				continue // dropped together with its table
			}
			switch cr.RelKnd {
			case "r", "p":
				var n int64
				if err := l.conn.QueryRow(l.ctx, "SELECT count(*) FROM "+cr.Rel).Scan(&n); err != nil {
					return err
				}
				if n > 0 {
					return model.Conflict("table %s (created by this transaction) now holds %d rows; refusing to drop it", cr.Rel, n)
				}
				if err := l.exec("DROP TABLE " + cr.Rel); err != nil {
					return err
				}
			case "i":
				if err := l.exec("DROP INDEX " + cr.Rel); err != nil {
					return err
				}
			case "v":
				if err := l.exec("DROP VIEW " + cr.Rel); err != nil {
					return err
				}
			case "S":
				if err := l.exec("DROP SEQUENCE " + cr.Rel); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *Connector) restore(l *live, evs []Event, verify bool) error {
	slots := netSlots(evs)
	st := &State{}
	_ = l.conn.QueryRow(l.ctx, "SELECT coalesce(max(seq), 0) FROM pg_temp.undolayer_log").Scan(&st.Seq)
	pks := map[string][]string{}
	for tbl := range slots {
		pk, err := l.pkCols(tbl)
		if err != nil {
			return err
		}
		if len(pk) == 0 {
			return &model.NotUndoable{Msg: tbl + " has no primary key; its rows cannot be identified for undo"}
		}
		pks[tbl] = pk
	}
	canon := func(s string) string { // exact: numbers stay as their decimal text
		if s == "" {
			return ""
		}
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		var v any
		_ = dec.Decode(&v)
		b, _ := json.Marshal(v)
		return string(b)
	}
	if verify {
		for tbl, ss := range slots {
			for k, s := range ss {
				cur, err := l.current(tbl, pks[tbl], k)
				if err != nil {
					return err
				}
				if canon(cur) != canon(s.Final) {
					return model.Conflict("%s row %s changed after commit; refusing to undo", tbl, k)
				}
			}
		}
	}
	for pass := 0; pass < 3; pass++ {
		pending := 0
		for tbl, ss := range slots {
			pk := pks[tbl]
			ci, err := l.columns(tbl)
			if err != nil {
				return err
			}
			pkc := make([]string, len(pk))
			for i, p := range pk {
				pkc[i] = pgx.Identifier{p}.Sanitize()
			}
			pl := strings.Join(pkc, ", ")
			for k, s := range ss {
				cur, err := l.current(tbl, pk, k)
				if err != nil {
					return err
				}
				if canon(cur) == canon(s.Orig) {
					continue
				}
				pending++
				where := fmt.Sprintf("(%s) = (SELECT %s FROM jsonb_populate_record(NULL::%s, $1::jsonb))", pl, pl, tbl)
				switch {
				case s.Orig == "":
					err = l.exec(fmt.Sprintf("DELETE FROM %s WHERE %s", tbl, where), k)
				case cur == "":
					cl := strings.Join(ci.names, ", ")
					err = l.exec(fmt.Sprintf("INSERT INTO %s (%s) OVERRIDING SYSTEM VALUE SELECT %s FROM jsonb_populate_record(NULL::%s, $1::jsonb)",
						tbl, cl, cl, tbl), s.Orig)
				default:
					set := strings.Join(ci.settable, ", ")
					if len(ci.settable) == 1 {
						err = l.exec(fmt.Sprintf("UPDATE %s SET %s = (SELECT %s FROM jsonb_populate_record(NULL::%s, $2::jsonb)) WHERE %s",
							tbl, set, set, tbl, where), k, s.Orig)
					} else {
						err = l.exec(fmt.Sprintf("UPDATE %s SET (%s) = (SELECT %s FROM jsonb_populate_record(NULL::%s, $2::jsonb)) WHERE %s",
							tbl, set, set, tbl, where), k, s.Orig)
					}
				}
				if err != nil {
					return err
				}
			}
		}
		touched, _, err := l.drain(st)
		if err != nil {
			return err
		}
		for _, e := range touched {
			for _, k := range []string{e.KO, e.KN} {
				if k != "" && slots[e.T][k] == nil {
					return model.Conflict("undo would also change %s row %s, which this transaction never touched; refusing", e.T, k)
				}
			}
		}
		if pending == 0 {
			return nil
		}
	}
	return model.Conflict("undo did not converge")
}

// Contained: staging runs inside a transaction this process holds (or a server-side dry
// run); nothing reaches anyone else before commit.
func (c *Connector) Contained(string) bool { return true }
