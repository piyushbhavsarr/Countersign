package sqlite

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"undolayer/internal/model"
	"undolayer/internal/tx"
)

// Restoring rows: sql.restore_rows puts chosen rows back as they were before an earlier
// task, without undoing the rest of that task. It is an ordinary write in a new task: each
// row is checked first (it must still be as the earlier task left it), then put back with
// plain INSERT / UPDATE / DELETE statements that run as nested sql.execute calls. So the
// restore is classified by policy, previewed, approved if policy says so, replayed and
// verified at commit like any write, and can itself be undone. Triggers fire as for any
// write, and what they do shows in the preview.

const restoreBatch = 200

type restoreSel struct {
	tables map[string]bool
	keys   []map[string]any
}

func (r restoreSel) match(table string, key map[string]any) bool {
	if len(r.tables) > 0 && !r.tables[table] {
		return false
	}
	if len(r.keys) == 0 {
		return true
	}
	kb := canonJSON(key)
	for _, k := range r.keys {
		if t, ok := k["_table"].(string); ok && t != table {
			continue
		}
		want := map[string]any{}
		for n, v := range k {
			if n != "_table" {
				want[n] = v
			}
		}
		if canonJSON(want) == kb {
			return true
		}
	}
	return false
}

// canonJSON compares values from different sources: numbers by their decimal value.
func canonJSON(v any) string {
	b, _ := json.Marshal(v)
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var x any
	_ = dec.Decode(&x)
	return canonNum(x)
}

func canonNum(v any) string {
	switch x := v.(type) {
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		parts := make([]string, len(ks))
		for i, k := range ks {
			kb, _ := json.Marshal(k)
			parts[i] = string(kb) + ":" + canonNum(x[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = canonNum(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case json.Number:
		if i, err := strconv.ParseInt(x.String(), 10, 64); err == nil {
			return strconv.FormatInt(i, 10)
		}
		if f, err := strconv.ParseFloat(x.String(), 64); err == nil {
			if f == math.Trunc(f) && math.Abs(f) < 1e15 {
				return strconv.FormatInt(int64(f), 10)
			}
			return strconv.FormatFloat(f, 'g', -1, 64)
		}
		return x.String()
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func parseSel(args map[string]any) (restoreSel, error) {
	sel := restoreSel{tables: map[string]bool{}}
	switch ts := args["tables"].(type) {
	case nil:
	case []any:
		for _, t := range ts {
			s, ok := t.(string)
			if !ok {
				return sel, errors.New("tables must be a list of table names")
			}
			sel.tables[s] = true
		}
	case []string:
		for _, s := range ts {
			sel.tables[s] = true
		}
	default:
		return sel, errors.New("tables must be a list of table names")
	}
	switch ks := args["keys"].(type) {
	case nil:
	case []any:
		for _, k := range ks {
			m, ok := k.(map[string]any)
			if !ok || len(m) == 0 {
				return sel, errors.New(`keys must be a list of objects, e.g. [{"id": 42}] (add "_table" to pick a table)`)
			}
			sel.keys = append(sel.keys, m)
		}
	case []map[string]any:
		sel.keys = ks
	default:
		return sel, errors.New(`keys must be a list of objects, e.g. [{"id": 42}]`)
	}
	return sel, nil
}

// sourceRecord merges this connector's undo records of the source task.
func (s *Connector) sourceRecord(t *tx.Tx, src string) (*UndoRecord, error) {
	if src == "" {
		return nil, errors.New("restore_rows needs source_tx: the task whose changes to put back")
	}
	if src == t.ID {
		return nil, errors.New("a task cannot restore its own changes; roll it back instead")
	}
	crs, err := t.Mgr.ChangedRows(src)
	if err != nil {
		return nil, err
	}
	out := &UndoRecord{DSN: s.DSN}
	found := false
	for _, cr := range crs {
		if cr.Connector != s.Name() || len(cr.Record) == 0 {
			continue
		}
		var rec UndoRecord
		if err := json.Unmarshal(cr.Record, &rec); err != nil {
			return nil, fmt.Errorf("%s: unreadable undo record: %v", src, err)
		}
		if rec.DSN != s.DSN {
			return nil, fmt.Errorf("%s changed another database (%s); restore it from a gateway connected to that one", src, rec.DSN)
		}
		out.Changes = append(out.Changes, rec.Changes...)
		found = true
	}
	if !found {
		return nil, fmt.Errorf("%s changed nothing in %s", src, s.Name())
	}
	return out, nil
}

type pick struct {
	table string
	m     *Meta
	slot  *Slot
}

func (s *Connector) picks(rec *UndoRecord, sel restoreSel) ([]pick, error) {
	meta := map[string]*Meta{}
	var events []Event
	for _, c := range rec.Changes {
		for k, m := range c.Meta {
			meta[k] = m
		}
		events = append(events, c.Events...)
	}
	slots := netSlots(events)
	var out []pick
	tables := make([]string, 0, len(slots))
	for t := range slots {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, tname := range tables {
		m := meta[tname]
		if m == nil {
			return nil, fmt.Errorf("no metadata for %s", tname)
		}
		ks := make([]string, 0, len(slots[tname]))
		for k := range slots[tname] {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			v := slots[tname][k]
			if sel.match(tname, keyMap(m, v.Key)) {
				out = append(out, pick{tname, m, v})
			}
		}
	}
	return out, nil
}

func (s *Connector) classifyRestore(t *tx.Tx, args map[string]any) (model.Effect, model.Facts, error) {
	src, _ := args["source_tx"].(string)
	sel, err := parseSel(args)
	if err != nil {
		return "", nil, err
	}
	rec, err := s.sourceRecord(t, src)
	if err != nil {
		return "", nil, err
	}
	ps, err := s.picks(rec, sel)
	if err != nil {
		return "", nil, err
	}
	tables := map[string]bool{}
	for _, p := range ps {
		tables[p.table] = true
	}
	tw := []string{}
	for x := range tables {
		tw = append(tw, x)
	}
	sort.Strings(tw)
	return model.Reversible, model.Facts{"env": s.Env, "dialect": "sqlite", "is_write": true, "restore_from": src,
		"rows_selected": len(ps), "tables_written": tw, "schema_ops": []string{}, "altered_tables": []string{},
		"uncaptured_tables": []string{}, "undoable": true}, nil
}

func sameColumns(a, b *Meta) bool {
	if a.Rowid != b.Rowid || strings.Join(a.Key, "\x00") != strings.Join(b.Key, "\x00") || a.Alias != b.Alias {
		return false
	}
	return strings.Join(a.Cols, "\x00") == strings.Join(b.Cols, "\x00")
}

// literal renders a value so it keeps its exact storage class: integers and reals as SQL
// literals (a parameter would pass through JSON and could lose its type or precision),
// blobs as hex literals, text as a parameter.
func literal(v Val) (string, []any) {
	switch v.K {
	case 'i':
		return strconv.FormatInt(v.I, 10), nil
	case 'f':
		switch {
		case math.IsNaN(v.F):
			return "NULL", nil // SQLite stores NaN as NULL
		case math.IsInf(v.F, 1):
			return "9e999", nil
		case math.IsInf(v.F, -1):
			return "-9e999", nil
		}
		f := strconv.FormatFloat(v.F, 'g', -1, 64)
		if !strings.ContainsAny(f, ".eE") {
			f += ".0"
		}
		return f, nil
	case 's':
		return "?", []any{v.S}
	case 'b':
		return "x'" + hex.EncodeToString(v.B) + "'", nil
	}
	return "NULL", nil
}

func keyWhere(m *Meta, key []Val) (string, []any) {
	cols := m.Key
	if m.Rowid {
		cols = []string{"rowid"}
	}
	parts, args := []string{}, []any{}
	for i, c := range cols {
		l, a := literal(key[i])
		name := q(c)
		if c == "rowid" && m.Rowid {
			name = "rowid"
		}
		parts = append(parts, name+" IS "+l)
		args = append(args, a...)
	}
	return "(" + strings.Join(parts, " AND ") + ")", args
}

func (s *Connector) stageRestore(t *tx.Tx, a *model.Action) (any, error) {
	src, _ := a.Args["source_tx"].(string)
	onConflict, _ := a.Args["on_conflict"].(string)
	if onConflict == "" {
		onConflict = "fail"
	}
	if onConflict != "fail" && onConflict != "skip" {
		return nil, errors.New(`on_conflict must be "fail" or "skip"`)
	}
	sel, err := parseSel(a.Args)
	if err != nil {
		return nil, err
	}
	rec, err := s.sourceRecord(t, src)
	if err != nil {
		return nil, err
	}
	ps, err := s.picks(rec, sel)
	if err != nil {
		return nil, err
	}
	l, err := s.live(t)
	if err != nil {
		return nil, err
	}
	if err := l.cap.install(); err != nil {
		return nil, err
	}
	sp := prefix + a.ID
	if err := l.iexec("SAVEPOINT " + q(sp)); err != nil {
		return nil, err
	}
	l.saves = append(l.saves, sp)
	n := len(tx.GetState[State](t, s.Name()).Changes)
	fail := func(err error) (any, error) { _ = s.rewind(t, sp, n); return nil, err }
	// tables and columns the earlier task dropped come back first, with their data; then
	// the rows it changed
	schema, schemaConflicts, err := s.restoreSchema(t, l, rec, sel)
	if err != nil {
		return fail(fmt.Errorf("restoring what %s dropped: %v", src, err))
	}
	if len(schemaConflicts) > 0 && onConflict == "fail" {
		b, _ := json.Marshal(schemaConflicts)
		return fail(model.Conflict("dropped tables or columns cannot be put back; nothing was restored "+
			"(on_conflict: \"skip\" restores the rest): %s", b))
	}
	if len(schema) > 0 {
		l.cap.version = -1
		if err := l.cap.install(); err != nil {
			return fail(err)
		}
	}
	type stmt struct {
		sql  string
		args []any
	}
	var stmts []stmt
	var conflicts []map[string]any
	already := 0
	inserts := map[string][]*pick{}
	deletes := map[string][]*pick{}
	var order []string
	for i := range ps {
		p := &ps[i]
		cur := l.cap.meta[p.table]
		if cur == nil {
			conflicts = append(conflicts, map[string]any{"table": p.table, "key": keyMap(p.m, p.slot.Key),
				"reason": "the table no longer exists"})
			continue
		}
		if !sameColumns(cur, p.m) {
			conflicts = append(conflicts, map[string]any{"table": p.table, "key": keyMap(p.m, p.slot.Key),
				"reason": "the table's columns or key changed since"})
			continue
		}
		now, err := s.current(l, p.table, p.m, p.slot.Key)
		if err != nil {
			return fail(err)
		}
		switch {
		case RowEqual(now, p.slot.Orig):
			already++
			continue
		case !RowEqual(now, p.slot.Final):
			c := map[string]any{"table": p.table, "key": keyMap(p.m, p.slot.Key),
				"reason": "changed since that task; putting it back would overwrite the newer change"}
			if now != nil {
				c["now"] = display(now, p.m.Cols)
			} else {
				c["now"] = nil
			}
			conflicts = append(conflicts, c)
			continue
		}
		if inserts[p.table] == nil && deletes[p.table] == nil {
			order = append(order, p.table)
		}
		switch {
		case p.slot.Orig == nil: // the earlier task created it
			deletes[p.table] = append(deletes[p.table], p)
		case now == nil: // it deleted it
			inserts[p.table] = append(inserts[p.table], p)
		default: // it changed it
			sets, args := []string{}, []any{}
			for i, c := range p.m.Cols {
				l, a := literal(p.slot.Orig[i])
				sets, args = append(sets, q(c)+" = "+l), append(args, a...)
			}
			w, wa := keyWhere(p.m, p.slot.Key)
			stmts = append(stmts, stmt{"UPDATE main." + q(p.table) + " SET " + strings.Join(sets, ", ") + " WHERE " + w,
				append(args, wa...)})
		}
	}
	if len(conflicts) > 0 && onConflict == "fail" {
		b, _ := json.Marshal(conflicts[:min(len(conflicts), 5)])
		return fail(model.Conflict("%d of %d rows cannot be put back without overwriting newer changes; nothing was restored "+
			"(on_conflict: \"skip\" restores the others): %s", len(conflicts), len(ps), b))
	}
	// foreign keys: rows are put back parents first, and taken away children first
	parentsFirst, err := s.fkOrder(l, order)
	if err != nil {
		return fail(err)
	}
	var updates []stmt
	updates, stmts = stmts, nil
	for _, tname := range parentsFirst {
		for i := 0; i < len(inserts[tname]); i += restoreBatch {
			batch := inserts[tname][i:min(i+restoreBatch, len(inserts[tname]))]
			m := batch[0].m
			names := []string{}
			withRowid := m.Rowid && m.Alias == ""
			if withRowid {
				names = append(names, "rowid")
			}
			for _, c := range m.Cols {
				names = append(names, q(c))
			}
			tuples, args := []string{}, []any{}
			for _, p := range batch {
				vals := []string{}
				if withRowid {
					l, a := literal(p.slot.Key[0])
					vals, args = append(vals, l), append(args, a...)
				}
				for _, v := range p.slot.Orig {
					l, a := literal(v)
					vals, args = append(vals, l), append(args, a...)
				}
				tuples = append(tuples, "("+strings.Join(vals, ", ")+")")
			}
			stmts = append(stmts, stmt{"INSERT INTO main." + q(tname) + " (" + strings.Join(names, ", ") + ") VALUES " +
				strings.Join(tuples, ", "), args})
		}
	}
	stmts = append(stmts, updates...)
	for i := len(parentsFirst) - 1; i >= 0; i-- {
		tname := parentsFirst[i]
		for i := 0; i < len(deletes[tname]); i += restoreBatch {
			batch := deletes[tname][i:min(i+restoreBatch, len(deletes[tname]))]
			ws, args := []string{}, []any{}
			for _, p := range batch {
				w, wa := keyWhere(p.m, p.slot.Key)
				ws, args = append(ws, w), append(args, wa...)
			}
			stmts = append(stmts, stmt{"DELETE FROM main." + q(tname) + " WHERE " + strings.Join(ws, " OR "), args})
		}
	}
	for _, st := range stmts {
		args := map[string]any{"sql": st.sql}
		if len(st.args) > 0 {
			args["params"] = st.args
		}
		if _, err := t.CallNested(s.Name(), "execute", args); err != nil {
			return fail(fmt.Errorf("restoring rows from %s: %v", src, err))
		}
	}
	conflicts = append(schemaConflicts, conflicts...)
	restored := len(ps) - already - (len(conflicts) - len(schemaConflicts))
	a.Facts["rows_restored"], a.Facts["rows_already_restored"], a.Facts["restore_conflicts"] = restored, already, len(conflicts)
	out := map[string]any{"staged": true, "source_tx": src, "rows_selected": len(ps), "rows_restored": restored,
		"rows_already_as_before": already, "conflicts": conflicts}
	if len(schema) > 0 {
		out["schema_restored"] = schema
	}
	if conflicts == nil {
		out["conflicts"] = []any{}
	}
	return out, nil
}

func (r restoreSel) tableOK(t string) bool { return len(r.tables) == 0 || r.tables[t] }

// restoreSchema recreates the tables (with their rows, indexes and triggers) and the
// columns (with their values) that the source task dropped, through nested sql.execute
// calls, so they are staged, previewed and undoable like any change. A table or column of
// that name existing again is a conflict. A restored column is added at the end of its
// table (SQLite adds columns there); undo of the whole task restores the exact layout.
func (s *Connector) restoreSchema(t *tx.Tx, l *live, rec *UndoRecord, sel restoreSel) ([]map[string]any, []map[string]any, error) {
	var done, conflicts []map[string]any
	exists := func(typ, name string) (bool, error) {
		rows, err := l.iquery("SELECT 1 FROM main.sqlite_master WHERE type = ? AND name = ?", typ, name)
		return len(rows) > 0, err
	}
	exec := func(stmt string, args []any) error {
		a := map[string]any{"sql": stmt}
		if len(args) > 0 {
			a["params"] = args
		}
		_, err := t.CallNested(s.Name(), "execute", a)
		return err
	}
	for _, c := range rec.Changes {
		for _, o := range c.Schema {
			switch {
			case o.Op == "drop" && o.Type == "table" && o.Meta != nil && o.SQL != "" && sel.tableOK(o.Name):
				ex, err := exists("table", o.Name)
				if err != nil {
					return nil, nil, err
				}
				if ex {
					conflicts = append(conflicts, map[string]any{"table": o.Name, "reason": "a table of that name exists again"})
					continue
				}
				if err := exec(o.SQL, nil); err != nil {
					return nil, nil, err
				}
				m := o.Meta
				withRowid := m.Rowid && m.Alias == ""
				names := []string{}
				if withRowid {
					names = append(names, "rowid")
				}
				for _, col := range m.Cols {
					names = append(names, q(col))
				}
				var tuples []string
				var args []any
				rows := 0
				flush := func() error {
					if len(tuples) == 0 {
						return nil
					}
					err := exec("INSERT INTO main."+q(o.Name)+" ("+strings.Join(names, ", ")+") VALUES "+strings.Join(tuples, ", "), args)
					tuples, args = nil, nil
					return err
				}
				for _, row := range o.Rows {
					vals, key := row, []Val(nil)
					if withRowid && len(row) > 0 {
						key, vals = row[:1], row[1:]
					} else {
						key = keyFromRow(m, vals)
					}
					if !sel.match(o.Name, keyMap(m, key)) {
						continue
					}
					lits := []string{}
					for _, v := range row {
						lt, a := literal(v)
						lits, args = append(lits, lt), append(args, a...)
					}
					tuples = append(tuples, "("+strings.Join(lits, ", ")+")")
					rows++
					if len(tuples) >= restoreBatch {
						if err := flush(); err != nil {
							return nil, nil, err
						}
					}
				}
				if err := flush(); err != nil {
					return nil, nil, err
				}
				// its indexes and triggers, dropped with it (triggers last, so restoring the
				// rows did not fire them)
				for _, typ := range []string{"index", "trigger"} {
					for _, x := range c.Schema {
						if x.Op == "drop" && x.Type == typ && x.Tbl == o.Name && x.SQL != "" {
							if ex, _ := exists(typ, x.Name); !ex {
								if err := exec(x.SQL, nil); err != nil {
									return nil, nil, err
								}
							}
						}
					}
				}
				done = append(done, map[string]any{"table": o.Name, "recreated": true, "rows": rows})
			case o.Op == "alter_table" && len(o.Dropped) > 0 && o.Meta != nil && sel.tableOK(o.Table):
				var cur []ColInfo
				err := l.internal(func() error { var e error; cur, e = xinfo(l.ctx, l.c, o.Table); return e })
				if err != nil || len(cur) == 0 {
					conflicts = append(conflicts, map[string]any{"table": o.Table, "columns": o.Dropped, "reason": "the table no longer exists"})
					continue
				}
				var decls []string
				var why string
				for _, name := range o.Dropped {
					for _, ci := range cur {
						if ci.Name == name {
							why = "a column of that name exists again"
						}
					}
					var info *ColInfo
					for i := range o.OldColumns {
						if o.OldColumns[i].Name == name {
							info = &o.OldColumns[i]
						}
					}
					switch {
					case info == nil:
						why = "its definition was not recorded"
					case info.PK > 0 || info.Hidden != 0:
						why = "it was part of the key or generated; undo of the whole task restores it"
					case info.NotNull != 0 && info.Dflt.K == 'n':
						why = "it was NOT NULL without a default, which SQLite cannot add to a table; undo of the whole task restores it"
					}
					if why != "" {
						break
					}
					d := q(name)
					if info.Type != "" {
						d += " " + info.Type
					}
					if info.Dflt.K != 'n' {
						d += " DEFAULT " + info.Dflt.S
					}
					if info.NotNull != 0 {
						d += " NOT NULL"
					}
					decls = append(decls, d)
				}
				if why != "" {
					conflicts = append(conflicts, map[string]any{"table": o.Table, "columns": o.Dropped, "reason": why})
					continue
				}
				for _, d := range decls {
					if err := exec("ALTER TABLE main."+q(o.Table)+" ADD COLUMN "+d, nil); err != nil {
						return nil, nil, err
					}
				}
				vals := 0
				for _, kv := range o.Values {
					if !sel.match(o.Table, keyMap(o.Meta, kv.Key)) {
						continue
					}
					sets, args := []string{}, []any{}
					for i, col := range o.Dropped {
						lt, a := literal(kv.Vals[i])
						sets, args = append(sets, q(col)+" = "+lt), append(args, a...)
					}
					w, wa := keyWhere(o.Meta, kv.Key)
					if err := exec("UPDATE main."+q(o.Table)+" SET "+strings.Join(sets, ", ")+" WHERE "+w, append(args, wa...)); err != nil {
						return nil, nil, err
					}
					vals++
				}
				done = append(done, map[string]any{"table": o.Table, "columns_added": o.Dropped, "values": vals,
					"note": "added at the end of the table; undo of the whole task restores the exact column order"})
			}
		}
	}
	return done, conflicts, nil
}

// fkOrder sorts tables so that a table comes after the tables its foreign keys reference
// (cycles keep their given order; SQLite checks immediate constraints per statement).
func (s *Connector) fkOrder(l *live, tables []string) ([]string, error) {
	in := map[string]bool{}
	for _, t := range tables {
		in[t] = true
	}
	refs := map[string][]string{}
	for _, t := range tables {
		rows, err := l.iquery("SELECT \"table\" FROM pragma_foreign_key_list(?)", t)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if p := r[0].S; in[p] && p != t {
				refs[t] = append(refs[t], p)
			}
		}
	}
	var out []string
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(string)
	visit = func(t string) {
		if state[t] != 0 {
			return
		}
		state[t] = 1
		for _, p := range refs[t] {
			visit(p)
		}
		state[t] = 2
		out = append(out, t)
	}
	for _, t := range tables {
		visit(t)
	}
	return out, nil
}

// ExportSQL renders statements that put the matching rows back as they were before the
// task: INSERT for deleted rows, UPDATE for changed ones, DELETE for created ones. They
// carry no conflict check; sql.restore_rows is the checked way. Values keep their exact
// storage class.
func (s *Connector) ExportSQL(raw json.RawMessage, match func(table string, key map[string]any) bool) ([]string, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	ps, err := s.picks(&rec, restoreSel{})
	if err != nil {
		return nil, err
	}
	inline := func(v Val) string {
		if v.K == 's' {
			return "'" + strings.ReplaceAll(v.S, "'", "''") + "'"
		}
		l, _ := literal(v)
		return l
	}
	where := func(m *Meta, key []Val) string {
		cols := m.Key
		parts := []string{}
		for i, c := range cols {
			name := q(c)
			if m.Rowid {
				name = "rowid"
			}
			parts = append(parts, name+" IS "+inline(key[i]))
		}
		return strings.Join(parts, " AND ")
	}
	var out []string
	for _, p := range ps {
		if match != nil && !match(p.table, keyMap(p.m, p.slot.Key)) {
			continue
		}
		switch {
		case p.slot.Orig == nil:
			out = append(out, "DELETE FROM "+q(p.table)+" WHERE "+where(p.m, p.slot.Key)+";")
		case p.slot.Final == nil:
			names, vals := []string{}, []string{}
			if p.m.Rowid && p.m.Alias == "" {
				names, vals = append(names, "rowid"), append(vals, inline(p.slot.Key[0]))
			}
			for i, c := range p.m.Cols {
				names, vals = append(names, q(c)), append(vals, inline(p.slot.Orig[i]))
			}
			out = append(out, "INSERT INTO "+q(p.table)+" ("+strings.Join(names, ", ")+") VALUES ("+strings.Join(vals, ", ")+");")
		default:
			sets := []string{}
			for i, c := range p.m.Cols {
				sets = append(sets, q(c)+" = "+inline(p.slot.Orig[i]))
			}
			out = append(out, "UPDATE "+q(p.table)+" SET "+strings.Join(sets, ", ")+" WHERE "+where(p.m, p.slot.Key)+";")
		}
	}
	return out, nil
}
