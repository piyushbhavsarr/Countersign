package postgres

import (
	"encoding/json"
	"sort"
	"strings"

	"undolayer/internal/vault"
)

// DescribeRows lists the net change an undo record holds, row by row. Values are the
// row's JSON form (to_jsonb), numbers kept exactly as PostgreSQL printed them.
func (c *Connector) DescribeRows(raw json.RawMessage) ([]vault.Row, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
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
	var out []vault.Row
	for _, tname := range tables {
		keys := make([]string, 0, len(slots[tname]))
		for k := range slots[tname] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := slots[tname][k]
			r := vault.Row{Table: tname}
			var err error
			if r.Key, err = jsonObject(k); err != nil {
				return nil, err
			}
			switch {
			case s.Orig == "":
				r.Op = "insert"
			case s.Final == "":
				r.Op = "delete"
			default:
				r.Op = "update"
			}
			if s.Orig != "" {
				if r.Before, err = jsonObject(s.Orig); err != nil {
					return nil, err
				}
			}
			if s.Final != "" {
				if r.After, err = jsonObject(s.Final); err != nil {
					return nil, err
				}
			}
			out = append(out, r)
		}
	}
	return out, nil
}

func jsonObject(s string) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}
