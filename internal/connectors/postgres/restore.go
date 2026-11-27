package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"undolayer/internal/model"
	"undolayer/internal/tx"
)

// Restoring rows: sql.restore_rows puts chosen rows back as they were before an earlier
// task, without undoing the rest of it. Each row is locked and checked first (it must
// still be as the earlier task left it); then it is put back by nested sql.execute calls
// that read the exact old row from its JSON form with jsonb_populate_recordset, so every
// type is restored by PostgreSQL itself. The restore is an ordinary write in a new task:
// classified by policy, previewed, approved if policy says so, committed, undoable.

const restoreBatch = 500

type restoreSel struct {
	tables map[string]bool
	keys   []map[string]any
}

func (r restoreSel) tableOK(table string) bool {
	if len(r.tables) == 0 {
		return true
	}
	return r.tables[table] || r.tables[strings.TrimPrefix(table, "public.")]
}

func (r restoreSel) match(table string, key map[string]any) bool {
	if !r.tableOK(table) {
		return false
	}
	if len(r.keys) == 0 {
		return true
	}
	kb := canonAny(key)
	for _, k := range r.keys {
		if t, ok := k["_table"].(string); ok && t != table && "public."+t != table {
			continue
		}
		want := map[string]any{}
		for n, v := range k {
			if n != "_table" {
				want[n] = v
			}
		}
		if canonAny(want) == kb {
			return true
		}
	}
	return false
}

// canonAny: one text per value, numbers compared by their decimal text.
func canonAny(v any) string {
	b, _ := json.Marshal(v)
	return canonText(string(b))
}

func canonText(s string) string {
	if s == "" {
		return ""
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
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

func (c *Connector) sourceRecord(t *tx.Tx, src string) (*UndoRecord, error) {
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
	out := &UndoRecord{DSN: c.DSN}
	found := false
	for _, cr := range crs {
		if cr.Connector != c.Name() || len(cr.Record) == 0 {
			continue
		}
		var rec UndoRecord
		if err := json.Unmarshal(cr.Record, &rec); err != nil {
			return nil, fmt.Errorf("%s: unreadable undo record: %v", src, err)
		}
		if !c.sameDB(rec.DSN) {
			return nil, fmt.Errorf("%s changed another database (%s); restore it from a gateway connected to that one", src, redact(rec.DSN))
		}
		out.Changes = append(out.Changes, rec.Changes...)
		found = true
	}
	if !found {
		return nil, fmt.Errorf("%s changed nothing in %s", src, c.Name())
	}
	return out, nil
}

type pick struct {
	table, key string
	s          *slot
}

func picks(rec *UndoRecord, sel restoreSel) ([]pick, error) {
	var events []Event
	for _, ch := range rec.Changes {
		events = append(events, ch.Events...)
	}
	slots := netSlots(events)
	tables := make([]string, 0, len(slots))
	for t := range slots {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	var out []pick
	for _, tbl := range tables {
		ks := make([]string, 0, len(slots[tbl]))
		for k := range slots[tbl] {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			key, err := jsonObject(k)
			if err != nil {
				return nil, err
			}
			if sel.match(tbl, key) {
				out = append(out, pick{tbl, k, slots[tbl][k]})
			}
		}
	}
	return out, nil
}

func (c *Connector) classifyRestore(t *tx.Tx, args map[string]any) (model.Effect, model.Facts, error) {
	src, _ := args["source_tx"].(string)
	sel, err := parseSel(args)
	if err != nil {
		return "", nil, err
	}
	rec, err := c.sourceRecord(t, src)
	if err != nil {
		return "", nil, err
	}
	ps, err := picks(rec, sel)
	if err != nil {
		return "", nil, err
	}
	seen := map[string]bool{}
	tw := []string{}
	for _, p := range ps {
		if !seen[p.table] {
			seen[p.table] = true
			tw = append(tw, p.table)
		}
	}
	return model.Reversible, model.Facts{"env": c.Env, "dialect": "postgres", "is_write": true, "restore_from": src,
		"rows_selected": len(ps), "tables": tw, "tables_written": tw, "undoable": true}, nil
}

// allColumns: every column a row's JSON form has (generated ones included).
func (l *live) allColumns(tbl string) (map[string]bool, error) {
	rows, err := l.conn.Query(l.ctx, `SELECT attname FROM pg_attribute WHERE attrelid = $1::regclass AND attnum > 0
		AND NOT attisdropped`, tbl)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

func (l *live) currentLocked(tbl string, pk []string, key string) (string, error) {
	cols := make([]string, len(pk))
	for i, p := range pk {
		cols[i] = pgx.Identifier{p}.Sanitize()
	}
	pl := strings.Join(cols, ", ")
	var s *string
	err := l.conn.QueryRow(l.ctx, fmt.Sprintf("SELECT to_jsonb(t)::text FROM %s t WHERE (%s) = (SELECT %s FROM jsonb_populate_record(NULL::%s, $1::jsonb)) FOR UPDATE",
		tbl, pl, pl, tbl), key).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil || s == nil {
		return "", err
	}
	return *s, nil
}

// fkOrder: a table after the tables its foreign keys reference.
func (l *live) fkOrder(tables []string) ([]string, error) {
	in := map[string]bool{}
	for _, t := range tables {
		in[t] = true
	}
	refs := map[string][]string{}
	for _, t := range tables {
		rows, err := l.conn.Query(l.ctx, `SELECT confrelid::regclass::text FROM pg_constraint WHERE contype = 'f' AND conrelid = $1::regclass`, t)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				rows.Close()
				return nil, err
			}
			// regclass text omits public.; captured names carry it
			for _, cand := range []string{p, "public." + p} {
				if in[cand] && cand != t {
					refs[t] = append(refs[t], cand)
				}
			}
		}
		rows.Close()
	}
	var out []string
	state := map[string]int{}
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

func (c *Connector) stageRestore(t *tx.Tx, a *model.Action) (any, error) {
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
	rec, err := c.sourceRecord(t, src)
	if err != nil {
		return nil, err
	}
	ps, err := picks(rec, sel)
	if err != nil {
		return nil, err
	}
	l, err := c.live(t)
	if err != nil {
		return nil, err
	}
	sp := "ul_" + strings.ReplaceAll(a.ID, "-", "_")
	if err := l.exec("SAVEPOINT " + sp); err != nil {
		return nil, err
	}
	l.saves = append(l.saves, sp)
	n := len(tx.GetState[State](t, c.Name()).Changes)
	fail := func(err error) (any, error) { _ = c.rewind(t, sp, n); return nil, err }

	type plan struct{ ins, upd, del []pick }
	plans := map[string]*plan{}
	var order []string
	var conflicts []map[string]any
	already := 0
	colsOf := map[string]map[string]bool{}
	for _, p := range ps {
		key, _ := jsonObject(p.key)
		pk, err := l.pkCols(p.table)
		if err != nil {
			conflicts = append(conflicts, map[string]any{"table": p.table, "key": key, "reason": "the table no longer exists"})
			continue
		}
		if len(pk) == 0 {
			conflicts = append(conflicts, map[string]any{"table": p.table, "key": key, "reason": "the table has no primary key now"})
			continue
		}
		if colsOf[p.table] == nil {
			if colsOf[p.table], err = l.allColumns(p.table); err != nil {
				return fail(err)
			}
		}
		if !sameShape(colsOf[p.table], p.s.Orig, p.s.Final) {
			conflicts = append(conflicts, map[string]any{"table": p.table, "key": key, "reason": "the table's columns changed since"})
			continue
		}
		cur, err := l.currentLocked(p.table, pk, p.key)
		if err != nil {
			return fail(err)
		}
		switch {
		case canonText(cur) == canonText(p.s.Orig):
			already++
			continue
		case canonText(cur) != canonText(p.s.Final):
			cf := map[string]any{"table": p.table, "key": key,
				"reason": "changed since that task; putting it back would overwrite the newer change"}
			if cur != "" {
				cf["now"], _ = jsonObject(cur)
			} else {
				cf["now"] = nil
			}
			conflicts = append(conflicts, cf)
			continue
		}
		if plans[p.table] == nil {
			plans[p.table] = &plan{}
			order = append(order, p.table)
		}
		pl := plans[p.table]
		switch {
		case p.s.Orig == "":
			pl.del = append(pl.del, p)
		case cur == "":
			pl.ins = append(pl.ins, p)
		default:
			pl.upd = append(pl.upd, p)
		}
	}
	if len(conflicts) > 0 && onConflict == "fail" {
		b, _ := json.Marshal(conflicts[:min(len(conflicts), 5)])
		return fail(model.Conflict("%d of %d rows cannot be put back without overwriting newer changes; nothing was restored "+
			"(on_conflict: \"skip\" restores the others): %s", len(conflicts), len(ps), b))
	}
	parentsFirst, err := l.fkOrder(order)
	if err != nil {
		return fail(err)
	}
	type stmt struct {
		sql  string
		rows []string
	}
	var stmts []stmt
	batches := func(ps []pick, rowOf func(pick) string, mk func(string) string) {
		for i := 0; i < len(ps); i += restoreBatch {
			b := ps[i:min(i+restoreBatch, len(ps))]
			rows := make([]string, len(b))
			for j, p := range b {
				rows[j] = rowOf(p)
			}
			stmts = append(stmts, stmt{mk(b[0].table), rows})
		}
	}
	orig := func(p pick) string { return p.s.Orig }
	keyRow := func(p pick) string { return p.key }
	for _, tbl := range parentsFirst {
		ci, err := l.columns(tbl)
		if err != nil {
			return fail(err)
		}
		cl := strings.Join(ci.names, ", ")
		batches(plans[tbl].ins, orig, func(tbl string) string {
			return fmt.Sprintf("INSERT INTO %s (%s) OVERRIDING SYSTEM VALUE SELECT %s FROM jsonb_populate_recordset(NULL::%s, $1::jsonb)",
				tbl, cl, cl, tbl)
		})
	}
	for _, tbl := range parentsFirst {
		ci, err := l.columns(tbl)
		if err != nil {
			return fail(err)
		}
		pk, _ := l.pkCols(tbl)
		if len(ci.settable) == 0 || len(plans[tbl].upd) == 0 {
			continue
		}
		src := make([]string, len(ci.settable))
		for i, s := range ci.settable {
			src[i] = "s." + s
		}
		on := make([]string, len(pk))
		for i, p := range pk {
			id := pgx.Identifier{p}.Sanitize()
			on[i] = "t." + id + " = s." + id
		}
		set := fmt.Sprintf("(%s) = ROW(%s)", strings.Join(ci.settable, ", "), strings.Join(src, ", "))
		if len(ci.settable) == 1 {
			set = fmt.Sprintf("%s = %s", ci.settable[0], src[0])
		}
		batches(plans[tbl].upd, orig, func(tbl string) string {
			return fmt.Sprintf("UPDATE %s t SET %s FROM jsonb_populate_recordset(NULL::%s, $1::jsonb) s WHERE %s",
				tbl, set, tbl, strings.Join(on, " AND "))
		})
	}
	for i := len(parentsFirst) - 1; i >= 0; i-- {
		tbl := parentsFirst[i]
		pk, _ := l.pkCols(tbl)
		cols := make([]string, len(pk))
		for i, p := range pk {
			cols[i] = pgx.Identifier{p}.Sanitize()
		}
		pl := strings.Join(cols, ", ")
		batches(plans[tbl].del, keyRow, func(tbl string) string {
			return fmt.Sprintf("DELETE FROM %s WHERE (%s) IN (SELECT %s FROM jsonb_populate_recordset(NULL::%s, $1::jsonb))",
				tbl, pl, pl, tbl)
		})
	}
	for _, st := range stmts {
		arr := "[" + strings.Join(st.rows, ",") + "]"
		if _, err := t.CallNested(c.Name(), "execute", map[string]any{"sql": st.sql, "params": []any{arr}}); err != nil {
			return fail(fmt.Errorf("restoring rows from %s: %v", src, err))
		}
	}
	restored := len(ps) - already - len(conflicts)
	a.Facts["rows_restored"], a.Facts["rows_already_restored"], a.Facts["restore_conflicts"] = restored, already, len(conflicts)
	out := map[string]any{"staged": true, "source_tx": src, "rows_selected": len(ps), "rows_restored": restored,
		"rows_already_as_before": already, "conflicts": conflicts}
	if conflicts == nil {
		out["conflicts"] = []any{}
	}
	return out, nil
}

// sameShape: the recorded row images have exactly the table's columns now.
func sameShape(cols map[string]bool, images ...string) bool {
	for _, img := range images {
		if img == "" {
			continue
		}
		m, err := jsonObject(img)
		if err != nil || len(m) != len(cols) {
			return false
		}
		for k := range m {
			if !cols[k] {
				return false
			}
		}
	}
	return true
}

// ExportSQL renders statements that put the matching rows back as they were before the
// task (no conflict check; sql.restore_rows is the checked way). Each is a DO block that
// reads the row back from its exact JSON form with jsonb_populate_record, so PostgreSQL
// restores every type itself, and that looks up, when it runs, which columns can be
// written (generated columns are left to PostgreSQL; identity columns are overridden).
func (c *Connector) ExportSQL(raw json.RawMessage, match func(table string, key map[string]any) bool) ([]string, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	ps, err := picks(&rec, restoreSel{})
	if err != nil {
		return nil, err
	}
	str := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	var out []string
	for _, p := range ps {
		key, err := jsonObject(p.key)
		if err != nil {
			return nil, err
		}
		if match != nil && !match(p.table, key) {
			continue
		}
		names := make([]string, 0, len(key))
		for k := range key {
			names = append(names, pgx.Identifier{k}.Sanitize())
		}
		sort.Strings(names)
		kl := strings.Join(names, ", ")
		where := fmt.Sprintf("(%s) = (SELECT %s FROM jsonb_populate_record(NULL::%s, %s::jsonb))", kl, kl, p.table, str(p.key))
		if p.s.Orig == "" {
			out = append(out, fmt.Sprintf("DELETE FROM %s WHERE %s;", p.table, where))
			continue
		}
		body := fmt.Sprintf(`DECLARE c text; s text; n int; row jsonb := %s::jsonb;
BEGIN
  SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum), count(*) INTO c, n FROM pg_attribute
    WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped AND attgenerated = '';
  SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum) INTO s FROM pg_attribute
    WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped AND attgenerated = '' AND attidentity <> 'a';
`, str(p.s.Orig), str(p.table), str(p.table))
		if p.s.Final == "" {
			body += fmt.Sprintf(`  EXECUTE format('INSERT INTO %%s (%%s) OVERRIDING SYSTEM VALUE SELECT %%s FROM jsonb_populate_record(NULL::%%s, $1)', %s, c, c, %s) USING row;
END`, str(p.table), str(p.table))
		} else {
			body += fmt.Sprintf(`  IF position(',' IN s) = 0 THEN
    EXECUTE format('UPDATE %%s SET %%s = (SELECT %%s FROM jsonb_populate_record(NULL::%%s, $1)) WHERE %%s', %s, s, s, %s, %s) USING row;
  ELSE
    EXECUTE format('UPDATE %%s SET (%%s) = (SELECT %%s FROM jsonb_populate_record(NULL::%%s, $1)) WHERE %%s', %s, s, s, %s, %s) USING row;
  END IF;
END`, str(p.table), str(p.table), str(where), str(p.table), str(p.table), str(where))
		}
		tag := "$cs$"
		for i := 0; strings.Contains(body, tag); i++ { // the row's data may contain any text
			tag = fmt.Sprintf("$cs%d$", i)
		}
		out = append(out, "DO "+tag+" "+body+" "+tag+";")
	}
	return out, nil
}
