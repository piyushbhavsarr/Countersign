package bench

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"undolayer/internal/registry"
	"undolayer/internal/tx"
)

// Declarative scenarios (docs/scenario-spec.md), so authors who have never seen the
// implementation can write them.
type DSLScenario struct {
	ID          string           `json:"id"`
	Kind        string           `json:"kind"`
	Description string           `json:"description"`
	Steps       []map[string]any `json:"steps"`
	Check       map[string]any   `json:"check"`
}

func LoadDSL(path, suite string) ([]Scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []DSLScenario
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	var out []Scenario
	for _, d := range raw {
		d := d
		if d.Kind != "harmful" && d.Kind != "benign" {
			return nil, fmt.Errorf("%s: kind must be harmful or benign", d.ID)
		}
		if seen[d.ID] {
			return nil, fmt.Errorf("duplicate id %s", d.ID)
		}
		seen[d.ID] = true
		if err := validateCheck(d.Check); err != nil {
			return nil, fmt.Errorf("%s: %w", d.ID, err)
		}
		out = append(out, Scenario{ID: d.ID, Kind: d.Kind, Suite: suite, Source: d.Description,
			Run:   func(w *World, t *tx.Tx) error { return runSteps(w, t, d.Steps) },
			Check: func(w *World) bool { return evalCheck(w, d.Check) }})
	}
	return out, nil
}

func worldVars(w *World) map[string]any {
	return map[string]any{"home": w.Home, "state": w.State, "db": w.DB, "ws": w.WS, "tmp": w.Tmp, "internet": w.inetURL}
}

// fill replaces {{step.N.path}} and {{world.x}} in every string of v.
func fill(v any, ctx map[string]any) any {
	switch x := v.(type) {
	case string:
		var b strings.Builder
		for {
			i := strings.Index(x, "{{")
			if i < 0 {
				b.WriteString(x)
				break
			}
			j := strings.Index(x[i:], "}}")
			if j < 0 {
				b.WriteString(x)
				break
			}
			b.WriteString(x[:i])
			val, err := registry.Lookup(ctx, strings.TrimSpace(x[i+2:i+j]))
			if err == nil {
				if s, ok := val.(string); ok {
					b.WriteString(s)
				} else {
					enc, _ := json.Marshal(val)
					b.Write(enc)
				}
			}
			x = x[i+j+2:]
		}
		return b.String()
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = fill(e, ctx)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = fill(e, ctx)
		}
		return out
	}
	return v
}

func runSteps(w *World, t *tx.Tx, steps []map[string]any) error {
	results := []any{}
	for _, st := range steps {
		if st["crash"] == true {
			return ErrCrash
		}
		if msg, ok := st["fail"].(string); ok {
			return agentError{msg}
		}
		tool, _ := st["tool"].(string)
		conn, op, err := route(t, tool)
		if err != nil {
			return agentError{err.Error()}
		}
		args, _ := fill(st["args"], map[string]any{"step": results, "world": worldVars(w)}).(map[string]any)
		r, err := t.Call(conn, op, args)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(r)
		var norm any
		_ = json.Unmarshal(b, &norm)
		results = append(results, norm)
	}
	return nil
}

func route(t *tx.Tx, tool string) (string, string, error) {
	best := ""
	for name, c := range t.Mgr.Connectors() {
		if strings.HasPrefix(tool, name+"_") {
			if _, ok := c.Operations()[tool[len(name)+1:]]; ok && len(name) > len(best) {
				best = name
			}
		}
	}
	if best == "" {
		return "", "", fmt.Errorf("unknown tool %q", tool)
	}
	return best, tool[len(best)+1:], nil
}

var checkKeys = map[string]bool{"sql_count": true, "table_exists": true, "file": true, "file_exists": true,
	"outside_file_exists": true, "home_file_missing": true, "leaked": true, "cli_ran": true, "aws_mutations": true,
	"net_charges": true, "tickets": true, "messages_sent": true, "remote_branch_exists": true, "remote_main_changed": true,
	"all": true, "any": true, "not": true}

func validateCheck(c map[string]any) error {
	if len(c) != 1 {
		return errors.New("a check has exactly one key")
	}
	for k, v := range c {
		if !checkKeys[k] {
			return fmt.Errorf("unknown check %q", k)
		}
		switch k {
		case "all", "any":
			l, _ := v.([]any)
			for _, e := range l {
				m, _ := e.(map[string]any)
				if err := validateCheck(m); err != nil {
					return err
				}
			}
		case "not":
			m, _ := v.(map[string]any)
			return validateCheck(m)
		}
	}
	return nil
}

func compare(n float64, spec any) bool {
	m, _ := spec.(map[string]any)
	v, _ := m["value"].(float64)
	switch m["op"] {
	case "lt":
		return n < v
	case "le":
		return n <= v
	case "eq":
		return n == v
	case "ne":
		return n != v
	case "ge":
		return n >= v
	case "gt":
		return n > v
	}
	return false
}

func evalCheck(w *World, c map[string]any) bool {
	for k, v := range c {
		switch k {
		case "all":
			for _, e := range v.([]any) {
				if !evalCheck(w, e.(map[string]any)) {
					return false
				}
			}
			return true
		case "any":
			for _, e := range v.([]any) {
				if evalCheck(w, e.(map[string]any)) {
					return true
				}
			}
			return false
		case "not":
			return !evalCheck(w, v.(map[string]any))
		case "sql_count":
			m := v.(map[string]any)
			where, _ := m["where"].(string)
			return compare(float64(w.Count(fmt.Sprint(m["table"]), where)), m)
		case "table_exists":
			return w.TableExists(fmt.Sprint(v))
		case "file":
			m := v.(map[string]any)
			f, ok := w.File(fmt.Sprint(m["path"]))
			return ok && f == fmt.Sprint(m["equals"])
		case "file_exists":
			_, ok := w.File(fmt.Sprint(v))
			return ok
		case "outside_file_exists":
			_, err := os.Stat(filepath.Join(w.Tmp, fmt.Sprint(v)))
			return err == nil
		case "home_file_missing":
			_, err := os.Stat(filepath.Join(w.Home, fmt.Sprint(v)))
			return err != nil
		case "leaked":
			return w.Leaked(fmt.Sprint(v))
		case "cli_ran":
			return w.CLIRan(fmt.Sprint(v))
		case "aws_mutations":
			return compare(float64(w.AWSMutations()), v)
		case "net_charges":
			return compare(float64(w.NetCharges()), v)
		case "tickets":
			return compare(float64(len(w.API.Tickets)), v)
		case "messages_sent":
			return compare(float64(len(w.Sent)), v)
		case "remote_branch_exists":
			return w.RemoteHead(fmt.Sprint(v)) != ""
		case "remote_main_changed":
			return (w.RemoteHead("main") != w.MainSHA) == (v == true)
		}
	}
	return false
}
