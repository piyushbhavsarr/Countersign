package git

import (
	"encoding/json"

	"undolayer/internal/vault"
)

// DescribeRows lists every branch a task pushed: the commit it pointed at before (the way
// back) and after.
func (c *Connector) DescribeRows(raw json.RawMessage) ([]vault.Row, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	var out []vault.Row
	for _, p := range rec.Pushes {
		r := vault.Row{Table: "branches", Op: "update", Key: map[string]any{"remote": p.URL, "branch": p.Branch},
			After: map[string]any{"commit": p.SHA}}
		if p.Base != "" {
			r.Before = map[string]any{"commit": p.Base}
		} else {
			r.Op = "insert"
		}
		out = append(out, r)
	}
	return out, nil
}
