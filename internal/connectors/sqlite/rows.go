package sqlite

import (
	"encoding/json"
	"fmt"
	"sort"

	"undolayer/internal/vault"
)

// DescribeRows lists the net change an undo record holds, row by row: rows the task
// inserted, updated or deleted, rows lost with a dropped table, and the values of dropped
// columns. Values are shown as previews show them (blobs as {"$blob": base64}).
func (s *Connector) DescribeRows(raw json.RawMessage) ([]vault.Row, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	meta := map[string]*Meta{}
	var events []Event
	var out []vault.Row
	for _, c := range rec.Changes {
		for k, m := range c.Meta {
			meta[k] = m
		}
		events = append(events, c.Events...)
	}
	slots := netSlots(events)
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
		keys := make([]string, 0, len(slots[tname]))
		for k := range slots[tname] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := slots[tname][k]
			r := vault.Row{Table: tname, Key: keyMap(m, v.Key)}
			switch {
			case v.Orig == nil:
				r.Op = "insert"
			case v.Final == nil:
				r.Op = "delete"
			default:
				r.Op = "update"
			}
			if v.Orig != nil {
				r.Before = display(v.Orig, m.Cols)
			}
			if v.Final != nil {
				r.After = display(v.Final, m.Cols)
			}
			out = append(out, r)
		}
	}
	for _, c := range rec.Changes {
		for _, o := range c.Schema {
			switch {
			case o.Op == "drop" && o.Type == "table" && o.Meta != nil:
				for _, row := range o.Rows {
					vals, key := row, []Val(nil)
					if o.Meta.Rowid && o.Meta.Alias == "" && len(row) > 0 {
						key, vals = row[:1], row[1:]
					}
					before := display(vals, o.Meta.Cols)
					if key == nil {
						key = keyFromRow(o.Meta, vals)
					}
					out = append(out, vault.Row{Table: o.Name, Op: "drop_table", Key: keyMap(o.Meta, key), Before: before})
				}
			case o.Op == "alter_table" && o.Meta != nil:
				for _, kv := range o.Values {
					out = append(out, vault.Row{Table: o.Table, Op: "drop_column", Key: keyMap(o.Meta, kv.Key),
						Before: display(kv.Vals, o.Dropped)})
				}
			}
		}
	}
	return out, nil
}

// keyMap names a row's key: the primary key columns, or rowid (named after the column that
// aliases it, if there is one).
func keyMap(m *Meta, key []Val) map[string]any {
	out := map[string]any{}
	if m.Rowid {
		name := "rowid"
		if m.Alias != "" {
			name = m.Alias
		}
		if len(key) > 0 {
			out[name] = key[0].Display()
		}
		return out
	}
	for i, k := range m.Key {
		if i < len(key) {
			out[k] = key[i].Display()
		}
	}
	return out
}

func keyFromRow(m *Meta, row []Val) []Val {
	var out []Val
	names := m.Key
	if m.Rowid && m.Alias != "" {
		names = []string{m.Alias} // the column is the rowid
	}
	for _, k := range names {
		for i, c := range m.Cols {
			if c == k && i < len(row) {
				out = append(out, row[i])
			}
		}
	}
	return out
}
