package kube

import (
	"encoding/json"
	"fmt"

	"undolayer/internal/vault"
)

// DescribeRows lists every Kubernetes object a task created, changed or deleted, with the
// object as it was before (and, for a deleted namespace, the objects it held).
func (c *Connector) DescribeRows(raw json.RawMessage) ([]vault.Row, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	var out []vault.Row
	for _, e := range rec.Entries {
		r := vault.Row{Table: e.Ref.APIVersion + "/" + e.Ref.Kind,
			Key: map[string]any{"namespace": e.Ref.Namespace, "name": e.Ref.Name}, Before: e.Before, After: e.After}
		switch e.Kind {
		case "created":
			r.Op = "insert"
		case "deleted":
			r.Op = "delete"
		default:
			r.Op = "update"
		}
		out = append(out, r)
		for _, o := range e.Roots {
			md, _ := o["metadata"].(map[string]any)
			out = append(out, vault.Row{Table: fmt.Sprint(o["apiVersion"]) + "/" + fmt.Sprint(o["kind"]), Op: "delete",
				Key: map[string]any{"namespace": md["namespace"], "name": md["name"]}, Before: o})
		}
	}
	return out, nil
}
