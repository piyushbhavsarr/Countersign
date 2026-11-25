// Package harness runs do-then-undo round trips for registry entries against a sandbox
// account: read the test state, perform the action in a real transaction, abort it
// (running the stored undo or cancelling the queued effect), read the state again and
// require it identical. Only then is the entry's hash recorded in verified.json.
package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"undolayer/internal/connectors/api"
	"undolayer/internal/creds"
	"undolayer/internal/policy"
	"undolayer/internal/registry"
	"undolayer/internal/tx"
)

type Result struct {
	Action  string   `json:"action"`
	Kind    string   `json:"kind"`
	OK      bool     `json:"ok"`
	Changed bool     `json:"changed_state"`
	Errors  []string `json:"errors"`
}

func strip(v any, ignore map[string]bool) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if !ignore[k] {
				out[k] = strip(e, ignore)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = strip(e, ignore)
		}
		return out
	}
	return v
}

func RoundTrip(tool *registry.Tool, c creds.Store, tr api.Transport, record bool) []Result {
	conn := api.New(tool, c, tr)
	conn.RequireVerified = false
	var out []Result
	for _, name := range tool.ActionNames() {
		a := tool.Actions[name]
		if a.Kind == "read" || a.Test == nil {
			continue
		}
		res := Result{Action: name, Kind: a.Kind}
		ignore := map[string]bool{}
		if l, ok := a.Test["ignore"].([]any); ok {
			for _, x := range l {
				ignore[fmt.Sprint(x)] = true
			}
		}
		state, _ := a.Test["state"].(map[string]any)
		sargs, _ := state["args"].(map[string]any)
		read := func() (any, error) {
			v, err := conn.Invoke(fmt.Sprint(state["call"]), sargs, "")
			b, _ := json.Marshal(v)
			var n any
			_ = json.Unmarshal(b, &n)
			return strip(n, ignore), err
		}
		err := func() error {
			s0, err := read()
			if err != nil {
				return err
			}
			dir, _ := os.MkdirTemp("", "undolayer-harness-")
			defer os.RemoveAll(dir)
			m, err := tx.NewManager(dir, policy.Empty())
			if err != nil {
				return err
			}
			m.Register(conn)
			t := m.Begin("round trip " + tool.Name + "." + name)
			args, _ := a.Test["args"].(map[string]any)
			if _, err := t.Call(tool.Name, name, args); err != nil {
				return err
			}
			mid, _ := read()
			res.Changed = !reflect.DeepEqual(mid, s0)
			rb, err := t.Rollback("round trip")
			if err != nil {
				return err
			}
			res.Errors = append(res.Errors, rb.Errors...)
			s1, err := read()
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(s0, s1) {
				res.Errors = append(res.Errors, fmt.Sprintf("state differs after undo: before %v, after %v", s0, s1))
			}
			if (a.Kind == "reversible" || a.Kind == "compensable") && !res.Changed {
				res.Errors = append(res.Errors, "the action did not change the test state, so the round trip proves nothing")
			}
			return nil
		}()
		if err != nil {
			res.Errors = append(res.Errors, err.Error())
		}
		res.OK = len(res.Errors) == 0
		if res.OK && record {
			_ = registry.MarkVerified(tool, name)
		}
		out = append(out, res)
	}
	return out
}
