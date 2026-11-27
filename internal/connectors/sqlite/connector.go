package sqlite

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"undolayer/internal/model"
	"undolayer/internal/sqlshape"
	"undolayer/internal/tx"
)

type Change struct {
	ActionID     string           `json:"action_id"`
	SQL          string           `json:"sql"`
	Events       []Event          `json:"events"`
	Schema       []SchemaOp       `json:"schema,omitempty"`
	SchemaBefore map[string]Obj   `json:"schema_before,omitempty"`
	SigBefore    string           `json:"signature_before,omitempty"`
	Meta         map[string]*Meta `json:"meta"`
}

type State struct {
	Changes    []*Change        `json:"changes"`
	TableStart map[string]int64 `json:"table_start"`
	Snapshot   string           `json:"snapshot,omitempty"` // the task's private copy (snapshot staging)
}

type UndoRecord struct {
	DSN      string    `json:"dsn"`
	Changes  []*Change `json:"changes"`
	FinalSig string    `json:"final_signature"`
}

type Connector struct {
	tx.Base
	DSN             string
	Env             string
	MaxPreviewRows  int
	FractionMinRows int64
	ForeignKeys     bool
	// Staging: "snapshot" (default) stages each task on its own consistent copy of the
	// database, so agents never hold the real database's single write lock while they work;
	// commit replays the task's statements on the real database and keeps the result only
	// if it is exactly what was previewed. "lock" stages on the real database inside one
	// held write transaction (one task writes at a time; no copy is made).
	Staging     string
	SnapshotDir string
}

func New(dsn string) *Connector {
	return &Connector{Base: tx.Base{ConnName: "sql"}, DSN: dsn, Env: "production", MaxPreviewRows: 20,
		FractionMinRows: 20, ForeignKeys: true}
}

func (s *Connector) Operations() map[string]tx.OpSchema {
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

func (s *Connector) live(t *tx.Tx) (*live, error) {
	if h, ok := t.Handles[s.Name()].(*live); ok {
		return h, nil
	}
	st := tx.GetState[State](t, s.Name())
	dsn := s.DSN
	if s.snapshotStaging() {
		p, err := s.snapshot(t.ID)
		if err != nil {
			return nil, err
		}
		st.Snapshot, dsn = p, p
	}
	l, err := open(dsn, s.ForeignKeys)
	if err != nil {
		return nil, err
	}
	t.Handles[s.Name()] = l
	if st.TableStart == nil {
		st.TableStart = map[string]int64{}
	}
	return l, nil
}

func params(a map[string]any) []any {
	var out []any
	if l, ok := a["params"].([]any); ok {
		for _, v := range l {
			if f, ok := v.(float64); ok && f == float64(int64(f)) {
				out = append(out, int64(f))
			} else {
				out = append(out, v)
			}
		}
	}
	return out
}

func (s *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	if op == "restore_rows" {
		return s.classifyRestore(t, args)
	}
	stmt, _ := args["sql"].(string)
	base := model.Facts{"env": s.Env, "dialect": "sqlite"}
	shape := sqlshape.Analyze(stmt)
	base["query_shape"], base["sql_injection_signals"] = shape.Shape, shape.Signals
	if parts := SplitStatements(stmt); len(parts) > 1 {
		base["statements"], base["multi_statement"] = len(parts), true
		return model.Reversible, base, nil
	}
	l, err := s.live(t)
	if err != nil {
		return "", nil, err
	}
	l.g.log = nil
	l.g.logging.Store(true)
	rows, err := l.c.QueryContext(l.ctx, "EXPLAIN "+stmt, params(args)...)
	if err == nil {
		for rows.Next() {
		}
		rows.Close()
	}
	l.g.logging.Store(false)
	facts := model.Facts{}
	if err != nil {
		facts["compile_error"], facts["is_write"] = err.Error(), false
	} else {
		facts = analyze(l.g.log)
	}
	for k, v := range base {
		facts[k] = v
	}
	facts["sql_injection_signals"] = injectionSignals(shape.Signals, facts)
	unc := []string{}
	if tw, ok := facts["tables_written"].([]string); ok {
		for _, tname := range tw {
			if l.cap.uncaptured[tname] {
				unc = append(unc, tname)
			}
		}
	}
	facts["uncaptured_tables"], facts["undoable"] = unc, len(unc) == 0
	if op == "query" && facts["is_write"] == true {
		facts["write_via_query"] = true
	}
	if facts["is_write"] == true {
		return model.Reversible, facts, nil
	}
	return model.Read, facts, nil
}

func display(row []Val, cols []string) map[string]any {
	out := map[string]any{}
	for i, c := range cols {
		if i < len(row) {
			out[c] = row[i].Display()
		}
	}
	return out
}

func (s *Connector) Stage(t *tx.Tx, a *model.Action) (any, error) {
	if a.Operation == "restore_rows" {
		return s.stageRestore(t, a)
	}
	stmt, _ := a.Args["sql"].(string)
	if a.Facts["write_via_query"] == true {
		return nil, errors.New("sql.query is read-only; use sql.execute for statements that write")
	}
	if e, ok := a.Facts["compile_error"].(string); ok {
		return nil, errors.New(e)
	}
	l, err := s.live(t)
	if err != nil {
		return nil, err
	}
	if a.Facts["multi_statement"] == true {
		return s.stageScript(t, a, stmt)
	}
	if a.Effect == model.Read {
		rows, err := l.c.QueryContext(l.ctx, stmt, params(a.Args)...)
		if err != nil {
			return nil, err
		}
		cols, _ := rows.Columns()
		data, err := scanAll(rows)
		if err != nil {
			return nil, err
		}
		out := []any{}
		for i, r := range data {
			if i >= 1000 {
				break
			}
			out = append(out, display(r, cols))
		}
		return map[string]any{"rows": out, "row_count": len(data), "truncated": len(data) > 1000}, nil
	}
	sp := prefix + a.ID
	if err := l.iexec("SAVEPOINT " + q(sp)); err != nil {
		return nil, err
	}
	l.saves = append(l.saves, sp)
	fail := func(err error) (any, error) { _ = s.rewind(t, sp, -1); return nil, err }
	if err := l.cap.install(); err != nil {
		return fail(err)
	}
	before := l.cap.snap
	ver := l.cap.schemaVersion()
	ddl := len(a.Facts["schema_ops"].([]string)) > 0
	var sigBefore string
	if ddl {
		_ = l.internal(func() error { sigBefore, err = signature(l.ctx, l.c, true); return err })
		if err := l.cap.uninstall(); err != nil {
			return fail(err)
		}
	}
	run := func() ([]map[string]any, error) {
		rows, err := l.c.QueryContext(l.ctx, stmt, params(a.Args)...)
		if err != nil {
			return nil, err
		}
		cols, _ := rows.Columns()
		data, err := scanAll(rows)
		var out []map[string]any
		for _, r := range data {
			out = append(out, display(r, cols))
		}
		return out, err
	}
	returned, err := run()
	if err != nil {
		return fail(err)
	}
	events, err := l.cap.drain()
	if err != nil {
		return fail(err)
	}
	var schema []SchemaOp
	if l.cap.schemaVersion() != ver {
		var after *Snapshot
		_ = l.internal(func() error { after, err = snapshot(l.ctx, l.c); return err })
		altered := map[string]bool{}
		for _, x := range a.Facts["altered_tables"].([]string) {
			altered[x] = true
		}
		schema = schemaDiff(before, after, altered)
		destroys := false
		for _, o := range schema {
			destroys = destroys || (o.Op == "drop" && o.Type == "table") || (o.Op == "alter_table" && len(o.Dropped) > 0)
		}
		if destroys { // rewind, save exactly what will be lost, run again
			if err := l.iexec("ROLLBACK TO " + q(sp)); err != nil {
				return fail(err)
			}
			if err := l.cap.install(); err != nil {
				return fail(err)
			}
			if err := s.saveLost(l, schema); err != nil {
				return fail(err)
			}
			_, _ = l.cap.drain()
			_ = l.cap.uninstall()
			if returned, err = run(); err != nil {
				return fail(err)
			}
			events, _ = l.cap.drain()
		}
	}
	if err := l.cap.install(); err != nil {
		return fail(err)
	}
	ch := &Change{ActionID: a.ID, SQL: stmt, Events: events, Schema: schema, Meta: map[string]*Meta{}}
	if len(schema) > 0 {
		ch.SchemaBefore, ch.SigBefore = before.Objects, sigBefore
	}
	for _, e := range events {
		if m := l.cap.meta[e.T]; m != nil {
			ch.Meta[e.T] = m
		} else if info, ok := before.Columns[e.T]; ok {
			ch.Meta[e.T] = metaFrom(info, true)
		}
	}
	st := tx.GetState[State](t, s.Name())
	st.Changes = append(st.Changes, ch)
	s.recordTableStart(l, st, events)
	slots := netSlots(events)
	affected, deleted, inserted := 0, 0, 0
	touched := []string{}
	for tname, ss := range slots {
		touched = append(touched, tname)
		affected += len(ss)
		for _, v := range ss {
			if v.Orig != nil && v.Final == nil {
				deleted++
			}
			if v.Final != nil && v.Orig == nil {
				inserted++
			}
		}
	}
	sort.Strings(touched)
	var dropsTable, dropsColumn, renames []string
	lost := 0
	for _, o := range schema {
		switch {
		case o.Op == "drop" && o.Type == "table":
			dropsTable = append(dropsTable, o.Name)
			lost += len(o.Rows)
		case o.Op == "alter_table":
			for _, c := range o.Dropped {
				dropsColumn = append(dropsColumn, o.Table+"."+c)
			}
			lost += len(o.Values)
		case o.Op == "rename_table":
			renames = append(renames, o.From+"->"+o.To)
		}
	}
	f := a.Facts
	f["rows_affected"], f["rows_deleted"], f["rows_inserted"], f["tables_touched"] = affected, deleted, inserted, touched
	f["drops_table"], f["drops_column"], f["renames_table"] = dropsTable, dropsColumn, renames
	f["destroys_schema"] = len(dropsTable)+len(dropsColumn) > 0
	f["renames_schema"] = len(renames) > 0
	f["data_lost_rows"] = lost
	f["_reevaluate"] = true
	out := map[string]any{"rows_affected": affected, "staged": true}
	if len(schema) > 0 {
		sc := []any{}
		for _, o := range schema {
			sc = append(sc, map[string]any{"op": o.Op, "type": o.Type, "name": o.Name, "table": o.Table, "from": o.From,
				"to": o.To, "added": o.Added, "dropped": o.Dropped})
		}
		out["schema_changes"] = sc
	}
	if len(returned) > 0 {
		if len(returned) > 100 {
			returned = returned[:100]
		}
		out["returning"] = returned
	}
	return out, nil
}

func (s *Connector) saveLost(l *live, schema []SchemaOp) error {
	return l.internal(func() error {
		for i := range schema {
			o := &schema[i]
			switch {
			case o.Op == "drop" && o.Type == "table":
				if m := l.cap.meta[o.Name]; m != nil {
					o.Meta = m
					rows, err := l.query("SELECT " + selectList(m, true) + " FROM main." + q(o.Name))
					if err != nil {
						return err
					}
					o.Rows = rows
				}
			case o.Op == "alter_table" && len(o.Dropped) > 0:
				m := l.cap.meta[o.Table]
				o.Meta = m
				keysel := keyList(m)
				cols := []string{}
				for _, c := range o.Dropped {
					cols = append(cols, "+"+q(c))
				}
				rows, err := l.query("SELECT " + keysel + ", " + strings.Join(cols, ", ") + " FROM main." + q(o.Table))
				if err != nil {
					return err
				}
				nk := len(m.Key)
				for _, r := range rows {
					o.Values = append(o.Values, KeyVals{Key: r[:nk], Vals: r[nk:]})
				}
			}
		}
		return nil
	})
}

// selectList reads stored columns without declared types, so values come back exactly as
// stored (no driver conversion of DATETIME etc.).
func selectList(m *Meta, withRowid bool) string {
	parts := []string{}
	if withRowid && m.Rowid && m.Alias == "" {
		parts = append(parts, "rowid")
	}
	for _, c := range m.Cols {
		parts = append(parts, "+"+q(c))
	}
	return strings.Join(parts, ", ")
}

func keyList(m *Meta) string {
	if m.Rowid {
		return "rowid"
	}
	parts := []string{}
	for _, k := range m.Key {
		parts = append(parts, "+"+q(k))
	}
	return strings.Join(parts, ", ")
}

func (s *Connector) recordTableStart(l *live, st *State, events []Event) {
	slots := netSlots(events)
	seen := map[string]bool{}
	for _, e := range events {
		if _, ok := st.TableStart[e.T]; ok || seen[e.T] {
			continue
		}
		seen[e.T] = true
		r, err := l.iquery("SELECT COUNT(*) FROM main." + q(e.T))
		var now int64
		if err == nil && len(r) > 0 {
			now = r[0][0].I
		}
		for _, v := range slots[e.T] {
			if v.Final != nil && v.Orig == nil {
				now--
			}
			if v.Orig != nil && v.Final == nil {
				now++
			}
		}
		st.TableStart[e.T] = now
	}
}

func (s *Connector) stageScript(t *tx.Tx, a *model.Action, stmt string) (any, error) {
	if len(params(a.Args)) > 0 {
		return nil, errors.New("parameters are not supported with multiple statements")
	}
	l, _ := s.live(t)
	sp := prefix + a.ID
	if err := l.iexec("SAVEPOINT " + q(sp)); err != nil {
		return nil, err
	}
	l.saves = append(l.saves, sp)
	n := len(tx.GetState[State](t, s.Name()).Changes)
	results := []any{}
	for _, part := range SplitStatements(stmt) {
		r, err := t.CallNested(s.Name(), a.Operation, map[string]any{"sql": part})
		if err != nil {
			_ = s.rewind(t, sp, n)
			return nil, err
		}
		results = append(results, r)
	}
	return map[string]any{"statements": len(results), "results": results, "staged": true}, nil
}

// rewind rolls back to a savepoint and forgets the changes recorded after it.
func (s *Connector) rewind(t *tx.Tx, sp string, keep int) error {
	l, err := s.live(t)
	if err != nil {
		return err
	}
	if err := l.iexec("ROLLBACK TO " + q(sp)); err != nil {
		return err
	}
	_ = l.iexec("RELEASE " + q(sp))
	for i := len(l.saves) - 1; i >= 0; i-- {
		if l.saves[i] == sp {
			l.saves = l.saves[:i]
			break
		}
	}
	st := tx.GetState[State](t, s.Name())
	if keep >= 0 && keep < len(st.Changes) {
		st.Changes = st.Changes[:keep]
	}
	l.cap.version = -1
	_ = l.cap.install()
	_, _ = l.cap.drain()
	return nil
}

func (s *Connector) Settle(t *tx.Tx, a *model.Action) {
	l, ok := t.Handles[s.Name()].(*live)
	if !ok {
		return
	}
	sp := prefix + a.ID
	for i, x := range l.saves {
		if x == sp {
			_ = l.iexec("RELEASE " + q(sp))
			l.saves = append(l.saves[:i], l.saves[i+1:]...)
			return
		}
	}
}

func (s *Connector) Discard(t *tx.Tx, a *model.Action) bool {
	l, ok := t.Handles[s.Name()].(*live)
	if !ok {
		return false
	}
	sp := prefix + a.ID
	found := false
	for _, x := range l.saves {
		found = found || x == sp
	}
	if !found {
		return false
	}
	st := tx.GetState[State](t, s.Name())
	idx := len(st.Changes)
	for i, c := range st.Changes {
		if c.ActionID == a.ID {
			idx = i
		}
	}
	return s.rewind(t, sp, idx) == nil
}

// ---------------------------------------------------------------- preview

func (s *Connector) Preview(t *tx.Tx) map[string]any {
	st := tx.PeekState[State](t, s.Name())
	if st == nil || len(st.Changes) == 0 {
		return nil
	}
	stmts := []any{}
	for _, c := range st.Changes {
		slots := netSlots(c.Events)
		item := map[string]any{"sql": c.SQL}
		n := 0
		tables := map[string]any{}
		for tname, ss := range slots {
			n += len(ss)
			m := c.Meta[tname]
			cols := []string{}
			if m != nil {
				cols = m.Cols
			}
			del, ins, upd := []any{}, []any{}, []any{}
			keys := make([]string, 0, len(ss))
			for k := range ss {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := ss[k]
				switch {
				case v.Orig != nil && v.Final == nil:
					del = append(del, display(v.Orig, cols))
				case v.Final != nil && v.Orig == nil:
					ins = append(ins, display(v.Final, cols))
				default:
					changed := map[string]any{}
					for i, col := range cols {
						if i < len(v.Orig) && i < len(v.Final) && !v.Orig[i].Equal(v.Final[i]) {
							changed[col] = map[string]any{"old": v.Orig[i].Display(), "new": v.Final[i].Display()}
						}
					}
					kd := []any{}
					for _, x := range v.Key {
						kd = append(kd, x.Display())
					}
					upd = append(upd, map[string]any{"key": kd, "changed": changed})
				}
			}
			tbl := map[string]any{}
			for name, l := range map[string][]any{"deleted": del, "inserted": ins, "updated": upd} {
				if len(l) == 0 {
					continue
				}
				if len(l) > s.MaxPreviewRows {
					tbl[name+"_total"] = len(l)
					l = l[:s.MaxPreviewRows]
				}
				tbl[name] = l
			}
			tables[tname] = tbl
		}
		item["rows_affected"] = n
		if len(tables) > 0 {
			item["tables"] = tables
		}
		if len(c.Schema) > 0 {
			sc := []any{}
			for _, o := range c.Schema {
				sc = append(sc, map[string]any{"op": o.Op, "type": o.Type, "name": o.Name, "table": o.Table, "from": o.From,
					"to": o.To, "added": o.Added, "dropped": o.Dropped, "rows_saved": len(o.Rows) + len(o.Values)})
			}
			item["schema"] = sc
		}
		stmts = append(stmts, item)
	}
	return map[string]any{"database": s.DSN, "env": s.Env, "statements": stmts}
}

func (s *Connector) Totals(t *tx.Tx) map[string]float64 {
	st := tx.PeekState[State](t, s.Name())
	if st == nil {
		return nil
	}
	var all []Event
	for _, c := range st.Changes {
		all = append(all, c.Events...)
	}
	changed, worst := 0, 0.0
	for tname, ss := range netSlots(all) {
		destroyed := 0
		for _, v := range ss {
			if v.Orig != nil {
				destroyed++
			}
		}
		changed += len(ss)
		if start := st.TableStart[tname]; start >= s.FractionMinRows {
			if f := float64(destroyed) / float64(start); f > worst {
				worst = f
			}
		}
	}
	return map[string]float64{"rows_changed": float64(changed), "max_table_fraction_changed": worst}
}

// ---------------------------------------------------------------- commit

// Intent is the undo record, complete before COMMIT: the row images were captured while
// staging, and the final schema signature is read inside the held transaction.
func (s *Connector) Intent(t *tx.Tx) (any, error) {
	l, ok := t.Handles[s.Name()].(*live)
	st := tx.PeekState[State](t, s.Name())
	if !ok || st == nil {
		return nil, nil
	}
	var changes []*Change
	for _, c := range st.Changes {
		if len(c.Events) > 0 || len(c.Schema) > 0 {
			changes = append(changes, c)
		}
	}
	if len(changes) == 0 {
		return nil, nil
	}
	var sig string
	var err error
	if err := l.internal(func() error { sig, err = signature(l.ctx, l.c, true); return err }); err != nil {
		return nil, err
	}
	return &UndoRecord{DSN: s.DSN, Changes: changes, FinalSig: sig}, nil
}

// UndoInFlight: SQLite commits atomically (a commit cut short is rolled back by SQLite when
// the database is next opened), so the database holds either the state before the commit
// or the one after. Which one is read from the database itself; only the latter is undone.
func (s *Connector) UndoInFlight(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	if len(rec.Changes) == 0 {
		return nil
	}
	l, err := open(rec.DSN, false)
	if err != nil {
		return err
	}
	defer l.close()
	done, err := s.committed(l, &rec)
	if err != nil || !done {
		_ = l.iexec("ROLLBACK")
		return err
	}
	if err := s.undo(l, &rec); err != nil {
		_ = l.iexec("ROLLBACK")
		return err
	}
	return nil
}

// committed tells, for a commit that may not have happened, whether it did.
func (s *Connector) committed(l *live, rec *UndoRecord) (bool, error) {
	schema := false
	meta := map[string]*Meta{}
	var events []Event
	for _, c := range rec.Changes {
		schema = schema || len(c.Schema) > 0
		for k, m := range c.Meta {
			meta[k] = m
		}
		events = append(events, c.Events...)
	}
	if schema {
		var now string
		var err error
		if err := l.internal(func() error { now, err = signature(l.ctx, l.c, true); return err }); err != nil {
			return false, err
		}
		return now == rec.FinalSig, nil
	}
	before, after := 0, 0
	for tname, ss := range netSlots(events) {
		m := meta[tname]
		if m == nil {
			return false, fmt.Errorf("no metadata for %s", tname)
		}
		for k, v := range ss {
			if RowEqual(v.Orig, v.Final) {
				continue
			}
			cur, err := s.current(l, tname, m, v.Key)
			if err != nil {
				return false, err
			}
			switch {
			case RowEqual(cur, v.Final):
				after++
			case RowEqual(cur, v.Orig):
				before++
			default:
				return false, model.Conflict("%s row %s is neither its state before nor after the interrupted commit", tname, k)
			}
		}
	}
	if after > 0 && before > 0 {
		return false, model.Conflict("rows are partly in their committed state; another writer changed them")
	}
	return after > 0, nil
}

func (s *Connector) Commit(t *tx.Tx) (any, error) {
	l, ok := t.Handles[s.Name()].(*live)
	st := tx.PeekState[State](t, s.Name())
	if !ok {
		return nil, nil
	}
	delete(t.Handles, s.Name())
	defer l.close()
	var sig string
	var err error
	if err := l.internal(func() error {
		if _, err = l.c.ExecContext(l.ctx, "SELECT 1"); err != nil {
			return err
		}
		sig, err = signature(l.ctx, l.c, true)
		return err
	}); err != nil {
		return nil, err
	}
	if st != nil && st.Snapshot != "" {
		_ = l.iexec("ROLLBACK") // the copy has served its purpose
		l.close()
		defer removeSnapshot(st.Snapshot)
		if err := s.commitSnapshot(t, st, sig); err != nil {
			return nil, err
		}
	} else if err := l.internal(func() error { return l.exec("COMMIT") }); err != nil {
		return nil, err
	}
	var changes []*Change
	if st != nil {
		for _, c := range st.Changes {
			if len(c.Events) > 0 || len(c.Schema) > 0 {
				changes = append(changes, c)
			}
		}
	}
	if len(changes) == 0 {
		return nil, nil
	}
	return &UndoRecord{DSN: s.DSN, Changes: changes, FinalSig: sig}, nil
}

func (s *Connector) Rollback(t *tx.Tx) error {
	if st := tx.PeekState[State](t, s.Name()); st != nil {
		defer removeSnapshot(st.Snapshot)
	}
	l, ok := t.Handles[s.Name()].(*live)
	if !ok {
		return nil
	}
	delete(t.Handles, s.Name())
	defer l.close()
	return l.iexec("ROLLBACK")
}

// Recover: the database discarded the held transaction when the connection died; a
// snapshot copy left behind is removed.
func (s *Connector) Recover(t *tx.Tx) error {
	if st := tx.PeekState[State](t, s.Name()); st != nil {
		removeSnapshot(st.Snapshot)
	}
	return nil
}

// ---------------------------------------------------------------- undo

func (s *Connector) Undo(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	// Foreign keys off while restoring: no cascade may fire and no table rebuild rewrites a
	// reference. Integrity is verified with foreign_key_check before COMMIT.
	l, err := open(rec.DSN, false)
	if err != nil {
		return err
	}
	defer l.close()
	if err := s.undo(l, &rec); err != nil {
		_ = l.iexec("ROLLBACK")
		return err
	}
	return nil
}

func (s *Connector) undo(l *live, rec *UndoRecord) error {
	if rec.FinalSig != "" {
		var now string
		var err error
		_ = l.internal(func() error { now, err = signature(l.ctx, l.c, true); return err })
		if err != nil || now != rec.FinalSig {
			return model.Conflict("schema changed after commit; refusing to undo")
		}
	}
	// User triggers already did their work, and its effects were captured; re-firing them
	// while restoring would apply them twice. They are lifted for the restore (DDL is
	// transactional: nobody else ever sees them missing) and recreated after.
	trig, err := l.iquery("SELECT name, sql FROM main.sqlite_master WHERE type='trigger' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return err
	}
	for _, r := range trig {
		if err := l.iexec("DROP TRIGGER main." + q(r[0].S)); err != nil {
			return err
		}
	}
	first := true
	ch := rec.Changes
	for i := len(ch) - 1; i >= 0; {
		if len(ch[i].Schema) > 0 {
			if err := s.undoSchema(l, ch[i]); err != nil {
				return err
			}
			i--
			first = false
			continue
		}
		j := i
		for j >= 0 && len(ch[j].Schema) == 0 {
			j--
		}
		run := ch[j+1 : i+1]
		meta := map[string]*Meta{}
		var events []Event
		for _, c := range run {
			for k, m := range c.Meta {
				meta[k] = m
			}
			events = append(events, c.Events...)
		}
		if err := s.restore(l, events, meta, first); err != nil {
			return err
		}
		first = false
		i = j
	}
	// triggers as they were before the transaction (it may have created or dropped some)
	target := [][2]string{}
	var firstDDL *Change
	for _, c := range ch {
		if c.SchemaBefore != nil {
			firstDDL = c
			break
		}
	}
	if firstDDL != nil {
		for _, o := range firstDDL.SchemaBefore {
			if o.Type == "trigger" {
				target = append(target, [2]string{o.Name, o.SQL})
			}
		}
	} else {
		for _, r := range trig {
			target = append(target, [2]string{r[0].S, r[1].S})
		}
	}
	if err := l.cap.uninstall(); err != nil {
		return err
	}
	cur, _ := l.iquery("SELECT name FROM main.sqlite_master WHERE type='trigger' AND name NOT LIKE 'sqlite_%'")
	for _, r := range cur {
		if err := l.iexec("DROP TRIGGER main." + q(r[0].S)); err != nil {
			return err
		}
	}
	for _, tr := range target {
		if err := l.iexec(tr[1]); err != nil {
			return err
		}
	}
	if s.ForeignKeys {
		bad, err := l.iquery("PRAGMA foreign_key_check")
		if err != nil {
			return err
		}
		if len(bad) > 0 {
			return model.Conflict("undo would violate foreign keys (%d rows)", len(bad))
		}
	}
	return l.iexec("COMMIT")
}

func where(m *Meta, key []Val) (string, []any) {
	if m.Rowid {
		return "rowid = ?", []any{key[0].Any()}
	}
	parts, args := []string{}, []any{}
	for i, k := range m.Key {
		parts = append(parts, q(k)+" IS ?")
		args = append(args, key[i].Any())
	}
	return strings.Join(parts, " AND "), args
}

func (s *Connector) current(l *live, table string, m *Meta, key []Val) ([]Val, error) {
	w, args := where(m, key)
	rows, err := l.iquery("SELECT "+selectList(m, false)+" FROM main."+q(table)+" WHERE "+w, args...)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

func (s *Connector) restore(l *live, events []Event, meta map[string]*Meta, verify bool) error {
	slots := netSlots(events)
	if err := l.cap.install(); err != nil {
		return err
	}
	_, _ = l.cap.drain()
	if verify {
		for tname, ss := range slots {
			m := meta[tname]
			if m == nil {
				return fmt.Errorf("no metadata for %s", tname)
			}
			for k, v := range ss {
				cur, err := s.current(l, tname, m, v.Key)
				if err != nil {
					return err
				}
				if !RowEqual(cur, v.Final) {
					return model.Conflict("%s row %s changed after commit; refusing to undo", tname, k)
				}
			}
		}
	}
	for pass := 0; pass < 3; pass++ {
		pending := 0
		for tname, ss := range slots {
			m := meta[tname]
			for _, v := range ss {
				cur, err := s.current(l, tname, m, v.Key)
				if err != nil {
					return err
				}
				if RowEqual(cur, v.Orig) {
					continue
				}
				pending++
				w, wargs := where(m, v.Key)
				switch {
				case v.Orig == nil:
					err = l.exec("DELETE FROM main."+q(tname)+" WHERE "+w, wargs...)
				case cur == nil:
					names, vals := []string{}, []any{}
					if m.Rowid && m.Alias == "" {
						names, vals = append(names, "rowid"), append(vals, v.Key[0].Any())
					}
					for i, c := range m.Cols {
						names, vals = append(names, q(c)), append(vals, v.Orig[i].Any())
					}
					err = l.exec("INSERT INTO main."+q(tname)+" ("+strings.Join(names, ", ")+") VALUES ("+
						strings.TrimSuffix(strings.Repeat("?, ", len(names)), ", ")+")", vals...)
				default:
					sets, vals := []string{}, []any{}
					for i, c := range m.Cols {
						sets, vals = append(sets, q(c)+" = ?"), append(vals, v.Orig[i].Any())
					}
					err = l.exec("UPDATE main."+q(tname)+" SET "+strings.Join(sets, ", ")+" WHERE "+w, append(vals, wargs...)...)
				}
				if err != nil {
					return err
				}
			}
		}
		touched, err := l.cap.drain()
		if err != nil {
			return err
		}
		for _, e := range touched {
			for _, k := range [][]Val{e.KO, e.KN} {
				if k != nil && slots[e.T][keyString(k)] == nil {
					return model.Conflict("undo would also change %s row %s, which this transaction never touched; refusing",
						e.T, keyString(k))
				}
			}
		}
		if pending == 0 {
			return nil
		}
	}
	return model.Conflict("undo did not converge")
}

func (s *Connector) undoSchema(l *live, c *Change) error {
	if err := l.cap.uninstall(); err != nil {
		return err
	}
	err := l.internal(func() error {
		for i := len(c.Schema) - 1; i >= 0; i-- {
			o := c.Schema[i]
			if o.Type != "" && o.Type != "table" {
				continue // indexes, views, triggers: reconciled below
			}
			switch o.Op {
			case "create":
				r, err := l.query("SELECT COUNT(*) FROM main." + q(o.Name))
				if err != nil {
					return err
				}
				if r[0][0].I > 0 {
					return model.Conflict("table %s (created by this transaction) now holds %d rows; refusing to drop it", o.Name, r[0][0].I)
				}
				if err := l.exec("DROP TABLE main." + q(o.Name)); err != nil {
					return err
				}
			case "drop":
				if err := l.exec(o.SQL); err != nil {
					return err
				}
				if o.Meta != nil {
					names := []string{}
					if o.Meta.Rowid && o.Meta.Alias == "" {
						names = append(names, "rowid")
					}
					for _, col := range o.Meta.Cols {
						names = append(names, q(col))
					}
					ins := "INSERT INTO main." + q(o.Name) + " (" + strings.Join(names, ", ") + ") VALUES (" +
						strings.TrimSuffix(strings.Repeat("?, ", len(names)), ", ") + ")"
					for _, r := range o.Rows {
						vals := []any{}
						for _, v := range r {
							vals = append(vals, v.Any())
						}
						if err := l.exec(ins, vals...); err != nil {
							return err
						}
					}
				}
			case "rename_table":
				if err := l.exec("ALTER TABLE main." + q(o.To) + " RENAME TO " + q(o.From)); err != nil {
					return err
				}
			case "alter_table":
				if err := s.rebuild(l, o); err != nil {
					return err
				}
			}
		}
		// reconcile indexes and views to the definitions recorded before the statement
		before := map[string]Obj{}
		for k, o := range c.SchemaBefore {
			if o.Type != "table" && o.Type != "trigger" {
				before[k] = o
			}
		}
		rows, err := l.query("SELECT type, name, sql FROM main.sqlite_master WHERE type NOT IN ('table','trigger') AND name NOT LIKE 'sqlite_%'")
		if err != nil {
			return err
		}
		now := map[string]string{}
		for _, r := range rows {
			now[r[0].S+":"+r[1].S] = r[2].S
			if b, ok := before[r[0].S+":"+r[1].S]; !ok || b.SQL != r[2].S {
				if err := l.exec("DROP " + strings.ToUpper(r[0].S) + " IF EXISTS main." + q(r[1].S)); err != nil {
					return err
				}
				delete(now, r[0].S+":"+r[1].S)
			}
		}
		for k, o := range before {
			if _, ok := now[k]; !ok && o.SQL != "" {
				if err := l.exec(o.SQL); err != nil {
					return err
				}
			}
		}
		if c.SigBefore != "" {
			got, err := signature(l.ctx, l.c, false)
			if err != nil {
				return err
			}
			if got != stripTriggers(c.SigBefore) {
				return model.Conflict("could not restore schema exactly after undoing %q", c.SQL)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	l.cap.version = -1
	return l.cap.install()
}

// rebuild returns a table to its recorded definition (SQLite's documented procedure).
func (s *Connector) rebuild(l *live, o SchemaOp) error {
	t, tmp := o.Table, prefix+"rebuild"
	curInfo, err := xinfo(l.ctx, l.c, t)
	if err != nil {
		return err
	}
	back := map[string]string{}
	for old, nw := range o.RenamedColumns {
		back[nw] = old
	}
	src := map[string]string{}
	for _, c := range curInfo {
		if c.Hidden == 0 {
			name := c.Name
			if b, ok := back[name]; ok {
				name = b
			}
			src[name] = c.Name
		}
	}
	rowid := true
	if o.Meta != nil {
		rowid = o.Meta.Rowid
	}
	m := metaFrom(o.OldColumns, rowid)
	var names, sel []string
	if m.Rowid && m.Alias == "" {
		names, sel = append(names, "rowid"), append(sel, "rowid")
	}
	for _, c := range m.Cols {
		if sc, ok := src[c]; ok {
			names, sel = append(names, q(c)), append(sel, q(sc))
		}
	}
	steps := []string{"PRAGMA legacy_alter_table=ON", "ALTER TABLE main." + q(t) + " RENAME TO " + q(tmp),
		"PRAGMA legacy_alter_table=OFF", o.OldSQL,
		"INSERT INTO main." + q(t) + " (" + strings.Join(names, ", ") + ") SELECT " + strings.Join(sel, ", ") + " FROM main." + q(tmp)}
	for _, st := range steps {
		if err := l.exec(st); err != nil {
			return err
		}
	}
	mm := o.Meta
	if mm == nil {
		mm = m
	}
	for _, kv := range o.Values {
		w, wargs := where(mm, kv.Key)
		sets, vals := []string{}, []any{}
		for i, c := range o.Dropped {
			sets, vals = append(sets, q(c)+" = ?"), append(vals, kv.Vals[i].Any())
		}
		if err := l.exec("UPDATE main."+q(t)+" SET "+strings.Join(sets, ", ")+" WHERE "+w, append(vals, wargs...)...); err != nil {
			return err
		}
	}
	return l.exec("DROP TABLE main." + q(tmp))
}

// NodeLocal: a SQLite database is a file on this node.
func (*Connector) NodeLocal() bool { return true }

// Contained: staging runs inside a transaction this process holds (or a server-side dry
// run); nothing reaches anyone else before commit.
func (s *Connector) Contained(string) bool { return true }

// SQLite functions that reach the file system or load code.
var fileOrCode = map[string]bool{"load_extension": true, "readfile": true, "writefile": true, "edit": true,
	"fsdir": true, "zipfile": true, "fts3_tokenizer": true}

// injectionSignals adds what SQLite itself reported (functions called, catalog tables
// read) to the structural signs from the statement's tokens.
func injectionSignals(fromTokens []string, f model.Facts) []string {
	set := map[string]bool{}
	for _, x := range fromTokens {
		set[x] = true
	}
	if fl, ok := f["functions"].([]string); ok {
		for _, fn := range fl {
			if fileOrCode[fn] {
				set["file_or_program"] = true
			}
		}
	}
	if f["reads_catalog"] == true {
		set["system_catalog"] = true
	}
	out := []string{}
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}
