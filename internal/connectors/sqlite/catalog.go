package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

func q(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

type Obj struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Tbl  string `json:"tbl"`
	SQL  string `json:"sql"`
}

type ColInfo struct {
	CID     int64  `json:"cid"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	NotNull int64  `json:"notnull"`
	Dflt    Val    `json:"dflt"`
	PK      int64  `json:"pk"`
	Hidden  int64  `json:"hidden"`
}

type Snapshot struct {
	Objects map[string]Obj       `json:"objects"`
	Columns map[string][]ColInfo `json:"columns"`
}

type Meta struct {
	Cols  []string `json:"cols"`  // stored columns, in table_xinfo order
	All   []string `json:"all"`   // every column including generated ones
	Rowid bool     `json:"rowid"` // rowid table (vs WITHOUT ROWID)
	Key   []string `json:"key"`   // ["rowid"] or primary key columns
	Alias string   `json:"alias"` // INTEGER PRIMARY KEY column aliasing rowid, if any
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func scanAll(rows *sql.Rows) ([][]Val, error) {
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]Val
	for rows.Next() {
		v := make([]any, len(cols))
		p := make([]any, len(cols))
		for i := range v {
			p[i] = &v[i]
		}
		if err := rows.Scan(p...); err != nil {
			return nil, err
		}
		r := make([]Val, len(cols))
		for i := range v {
			r[i] = FromAny(v[i])
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func query(ctx context.Context, c querier, s string, args ...any) ([][]Val, error) {
	rows, err := c.QueryContext(ctx, s, args...)
	if err != nil {
		return nil, err
	}
	return scanAll(rows)
}

func xinfo(ctx context.Context, c querier, table string) ([]ColInfo, error) {
	rows, err := query(ctx, c, "PRAGMA main.table_xinfo("+q(table)+")")
	if err != nil {
		return nil, err
	}
	out := []ColInfo{}
	for _, r := range rows {
		out = append(out, ColInfo{CID: r[0].I, Name: r[1].S, Type: r[2].S, NotNull: r[3].I, Dflt: r[4], PK: r[5].I, Hidden: r[6].I})
	}
	return out, nil
}

func snapshot(ctx context.Context, c querier) (*Snapshot, error) {
	rows, err := query(ctx, c, "SELECT type, name, tbl_name, sql FROM main.sqlite_master WHERE name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Objects: map[string]Obj{}, Columns: map[string][]ColInfo{}}
	for _, r := range rows {
		o := Obj{Type: r[0].S, Name: r[1].S, Tbl: r[2].S, SQL: r[3].S}
		s.Objects[o.Type+":"+o.Name] = o
		if o.Type == "table" {
			if s.Columns[o.Name], err = xinfo(ctx, c, o.Name); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

// signature describes the schema structurally (independent of how CREATE text is
// spelled or quoted), from SQLite's introspection pragmas. Canonical JSON.
func signature(ctx context.Context, c querier, triggers bool) (string, error) {
	sig := map[string]any{}
	objs, err := query(ctx, c, "SELECT type, name FROM main.sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
	if err != nil {
		return "", err
	}
	for _, o := range objs {
		typ, name := o[0].S, o[1].S
		switch {
		case typ == "table":
			cols, _ := query(ctx, c, "PRAGMA main.table_xinfo("+q(name)+")")
			fks, _ := query(ctx, c, "PRAGMA main.foreign_key_list("+q(name)+")")
			fkl := []string{}
			for _, f := range fks {
				parts := []string{}
				for _, x := range f[2:] {
					parts = append(parts, strings.ToLower(fmt.Sprint(x.Display())))
				}
				fkl = append(fkl, strings.Join(parts, "|"))
			}
			sort.Strings(fkl)
			idx := []string{}
			il, _ := query(ctx, c, "PRAGMA main.index_list("+q(name)+")")
			for _, r := range il {
				ic, _ := query(ctx, c, "PRAGMA main.index_xinfo("+q(r[1].S)+")")
				label := r[3].S
				if label == "c" {
					label = r[1].S
				}
				b, _ := json.Marshal([]any{label, r[2], r[4], ic})
				idx = append(idx, string(b))
			}
			sort.Strings(idx)
			sig["table:"+name] = map[string]any{"cols": cols, "fks": fkl, "indexes": idx}
		case typ == "index":
		case typ == "trigger" && !triggers:
		default:
			sig[typ+":"+name] = true
		}
	}
	b, err := json.Marshal(sig)
	return string(b), err
}

func stripTriggers(sig string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(sig), &m) != nil {
		return sig
	}
	for k := range m {
		if strings.HasPrefix(k, "trigger:") {
			delete(m, k)
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func metaFrom(info []ColInfo, rowid bool) *Meta {
	m := &Meta{Rowid: rowid}
	var pk []ColInfo
	for _, c := range info {
		m.All = append(m.All, c.Name)
		if c.Hidden == 0 {
			m.Cols = append(m.Cols, c.Name)
		}
		if c.PK > 0 {
			pk = append(pk, c)
		}
	}
	sort.Slice(pk, func(i, j int) bool { return pk[i].PK < pk[j].PK })
	if rowid {
		m.Key = []string{"rowid"}
		if len(pk) == 1 && strings.EqualFold(pk[0].Type, "INTEGER") {
			m.Alias = pk[0].Name
		}
	} else {
		for _, c := range pk {
			m.Key = append(m.Key, c.Name)
		}
	}
	return m
}

func tableMeta(ctx context.Context, c querier, table string, info []ColInfo) *Meta {
	_, err := query(ctx, c, "SELECT rowid FROM main."+q(table)+" LIMIT 0")
	return metaFrom(info, err == nil)
}

// ---------------------------------------------------------------- schema diff

type KeyVals struct {
	Key  []Val `json:"key"`
	Vals []Val `json:"vals"`
}

type SchemaOp struct {
	Op             string            `json:"op"` // create drop rename_table alter_table
	Type           string            `json:"type,omitempty"`
	Name           string            `json:"name,omitempty"`
	Tbl            string            `json:"tbl,omitempty"`
	SQL            string            `json:"sql,omitempty"`
	From           string            `json:"from,omitempty"`
	To             string            `json:"to,omitempty"`
	Table          string            `json:"table,omitempty"`
	OldSQL         string            `json:"old_sql,omitempty"`
	OldColumns     []ColInfo         `json:"old_columns,omitempty"`
	Added          []string          `json:"added,omitempty"`
	Dropped        []string          `json:"dropped,omitempty"`
	RenamedColumns map[string]string `json:"renamed_columns,omitempty"`
	Meta           *Meta             `json:"meta,omitempty"`
	Rows           [][]Val           `json:"rows,omitempty"`
	Values         []KeyVals         `json:"values,omitempty"`
}

func colNames(cs []ColInfo) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func schemaDiff(old, nw *Snapshot, altered map[string]bool) []SchemaOp {
	var ops []SchemaOp
	var gone, born []Obj
	for k, o := range old.Objects {
		if _, ok := nw.Objects[k]; !ok {
			gone = append(gone, o)
		}
	}
	for k, o := range nw.Objects {
		if _, ok := old.Objects[k]; !ok {
			born = append(born, o)
		}
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].Name < gone[j].Name })
	sort.Slice(born, func(i, j int) bool { return born[i].Name < born[j].Name })
	renamed := map[string]string{}
	for gi := 0; gi < len(gone); gi++ {
		g := gone[gi]
		if g.Type != "table" || !altered[g.Name] {
			continue
		}
		for bi := 0; bi < len(born); bi++ {
			b := born[bi]
			if b.Type == "table" && reflect.DeepEqual(colNames(old.Columns[g.Name]), colNames(nw.Columns[b.Name])) {
				ops = append(ops, SchemaOp{Op: "rename_table", From: g.Name, To: b.Name})
				renamed[g.Name] = b.Name
				gone = append(gone[:gi], gone[gi+1:]...)
				born = append(born[:bi], born[bi+1:]...)
				gi--
				break
			}
		}
	}
	for _, g := range gone {
		ops = append(ops, SchemaOp{Op: "drop", Type: g.Type, Name: g.Name, Tbl: g.Tbl, SQL: g.SQL})
	}
	for _, b := range born {
		ops = append(ops, SchemaOp{Op: "create", Type: b.Type, Name: b.Name, Tbl: b.Tbl, SQL: b.SQL})
	}
	keys := []string{}
	for k := range old.Objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		o := old.Objects[k]
		name := o.Name
		if r, ok := renamed[o.Name]; ok {
			name = r
		}
		nk := o.Type + ":" + name
		n, ok := nw.Objects[nk]
		if !ok {
			continue
		}
		if o.Type == "table" {
			if !altered[o.Name] || reflect.DeepEqual(old.Columns[o.Name], nw.Columns[name]) {
				continue
			}
			oc, nc := colNames(old.Columns[o.Name]), colNames(nw.Columns[name])
			op := SchemaOp{Op: "alter_table", Table: name, OldSQL: o.SQL, OldColumns: old.Columns[o.Name], RenamedColumns: map[string]string{}}
			if len(oc) == len(nc) {
				for i := range oc {
					if oc[i] != nc[i] {
						op.RenamedColumns[oc[i]] = nc[i]
					}
				}
			}
			if len(op.RenamedColumns) == 0 {
				for _, c := range oc {
					if !contains(nc, c) {
						op.Dropped = append(op.Dropped, c)
					}
				}
				for _, c := range nc {
					if !contains(oc, c) {
						op.Added = append(op.Added, c)
					}
				}
			}
			ops = append(ops, op)
		} else if n.SQL != o.SQL {
			ops = append(ops, SchemaOp{Op: "drop", Type: o.Type, Name: o.Name, Tbl: o.Tbl, SQL: o.SQL},
				SchemaOp{Op: "create", Type: n.Type, Name: n.Name, Tbl: n.Tbl, SQL: n.SQL})
		}
	}
	return ops
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- net effect

type Event struct {
	T   string `json:"t"`
	Op  string `json:"op"` // I U D
	KO  []Val  `json:"ko,omitempty"`
	KN  []Val  `json:"kn,omitempty"`
	Old []Val  `json:"old,omitempty"`
	New []Val  `json:"new,omitempty"`
}

// Slot is a key position in a table: what it held before the events and after.
type Slot struct {
	Key   []Val
	Orig  []Val // nil = no row
	Final []Val
}

// netSlots collapses row events into per-table slots, following identity through key
// changes (an UPDATE of a primary key empties one slot and fills another).
func netSlots(events []Event) map[string]map[string]*Slot {
	type origin struct {
		key, row []Val
		set      bool
	}
	chains := map[string]map[string]origin{}
	final := map[string]map[string][]Val{}
	keys := map[string]map[string][]Val{}
	ended := map[string][]origin{}
	for _, e := range events {
		if chains[e.T] == nil {
			chains[e.T], final[e.T], keys[e.T] = map[string]origin{}, map[string][]Val{}, map[string][]Val{}
		}
		ch, fin, ks := chains[e.T], final[e.T], keys[e.T]
		switch e.Op {
		case "I":
			k := keyString(e.KN)
			ch[k], fin[k], ks[k] = origin{}, e.New, e.KN
		case "U":
			ko, kn := keyString(e.KO), keyString(e.KN)
			o, ok := ch[ko]
			if !ok {
				o = origin{key: e.KO, row: e.Old, set: true}
			}
			delete(ch, ko)
			delete(fin, ko)
			ch[kn], fin[kn], ks[kn] = o, e.New, e.KN
		case "D":
			ko := keyString(e.KO)
			o, ok := ch[ko]
			if !ok {
				o = origin{key: e.KO, row: e.Old, set: true}
			}
			delete(ch, ko)
			delete(fin, ko)
			ended[e.T] = append(ended[e.T], o)
		}
	}
	out := map[string]map[string]*Slot{}
	get := func(t, k string, key []Val) *Slot {
		if out[t] == nil {
			out[t] = map[string]*Slot{}
		}
		if out[t][k] == nil {
			out[t][k] = &Slot{Key: key}
		}
		return out[t][k]
	}
	for t, ch := range chains {
		for cur, o := range ch {
			get(t, cur, keys[t][cur]).Final = final[t][cur]
			if o.set {
				get(t, keyString(o.key), o.key).Orig = o.row
			}
		}
	}
	for t, os := range ended {
		for _, o := range os {
			if o.set {
				get(t, keyString(o.key), o.key).Orig = o.row
			}
		}
	}
	for t, s := range out {
		for k, v := range s {
			if RowEqual(v.Orig, v.Final) {
				delete(s, k)
			}
		}
		if len(s) == 0 {
			delete(out, t)
		}
	}
	return out
}
