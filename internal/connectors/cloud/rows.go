package cloud

import (
	"encoding/json"

	"undolayer/internal/vault"
)

// DescribeRows lists every cloud resource a task created or changed, with its properties
// before and after.
func (c *Connector) DescribeRows(raw json.RawMessage) ([]vault.Row, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	var out []vault.Row
	for _, e := range rec.CC {
		r := vault.Row{Table: e.Type, Key: map[string]any{"id": e.ID}, Before: e.Before, After: e.After, Op: "update"}
		switch e.Op {
		case "created":
			r.Op = "insert"
		case "deleted":
			r.Op = "delete"
		}
		out = append(out, r)
	}
	return out, nil
}
