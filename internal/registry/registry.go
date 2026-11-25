// Package registry: what each tool action does and how to undo it, as data.
//
// One file per tool (TOML, JSON or YAML). See registry/*.toml for the format. Lanes:
// read, reversible (before/after captured, exact inverse), compensable (fix recipe from
// the response), deferrable (queued; undo = delete from the queue), irreversible
// (human approval). Templates: a string that is exactly "$args.x", "$before.x",
// "$after.x", "$response.x", "$tx.id" or "$step.key" is replaced by the value (type
// kept); "{args.x}" inside a string is interpolated.
//
// An entry is trusted in its declared lane only after a do-then-undo round trip passed
// (undolayer registry test); its hash is then recorded in verified.json next to the
// file. Unverified reversible/compensable entries run in the irreversible lane.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

var Kinds = []string{"read", "reversible", "compensable", "deferrable", "irreversible"}

// Duration parses "90s", "15m", "24h", "30d", "1w" (or a bare number of seconds).
func Duration(v any) (float64, error) {
	switch x := v.(type) {
	case nil:
		return 0, nil
	case int64:
		return float64(x), nil
	case float64:
		return x, nil
	case int:
		return float64(x), nil
	case string:
		s := strings.TrimSpace(x)
		units := map[byte]float64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
		if n := len(s); n > 1 {
			if u, ok := units[s[n-1]]; ok {
				f, err := strconv.ParseFloat(s[:n-1], 64)
				if err == nil {
					return f * u, nil
				}
			}
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f, nil
		}
	}
	return 0, fmt.Errorf("bad duration %v (use e.g. 90s, 15m, 24h, 30d)", v)
}

// Lookup resolves a dotted path in a context.
func Lookup(ctx any, path string) (any, error) {
	cur := ctx
	for _, part := range strings.Split(path, ".") {
		switch c := cur.(type) {
		case map[string]any:
			v, ok := c[part]
			if !ok {
				return nil, fmt.Errorf("template reference $%s has no value", path)
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(c) {
				return nil, fmt.Errorf("template reference $%s has no value", path)
			}
			cur = c[i]
		default:
			return nil, fmt.Errorf("template reference $%s has no value", path)
		}
	}
	return cur, nil
}

func interpolate(s string, ctx map[string]any) (string, error) { return interpolateWith(s, ctx, nil) }

func interpolateWith(s string, ctx map[string]any, escape func(string) string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			b.WriteByte(s[i])
			continue
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return "", fmt.Errorf("unclosed { in template %q", s)
		}
		v, err := Lookup(ctx, s[i+1:i+j])
		if err != nil {
			return "", err
		}
		if escape != nil {
			b.WriteString(escape(fmt.Sprint(v)))
		} else {
			b.WriteString(fmt.Sprint(v))
		}
		i += j
	}
	return b.String(), nil
}

// RenderPath fills a URL path template: every value becomes exactly one path segment
// (escaped), so no argument can add segments, climb with "..", or start a query.
func RenderPath(t any, ctx map[string]any) (string, error) {
	x, ok := t.(string)
	if !ok {
		return "", fmt.Errorf("a request path must be a string")
	}
	seg := func(v string) string {
		if v == "." || v == ".." {
			return strings.ReplaceAll(v, ".", "%2E")
		}
		return url.PathEscape(v)
	}
	if strings.HasPrefix(x, "$") && !strings.Contains(x, " ") {
		v, err := Lookup(ctx, x[1:])
		if err != nil {
			return "", err
		}
		return "/" + seg(fmt.Sprint(v)), nil
	}
	return interpolateWith(x, ctx, seg)
}

// Render fills a template from ctx.
func Render(t any, ctx map[string]any) (any, error) {
	switch x := t.(type) {
	case string:
		if strings.HasPrefix(x, "$") && !strings.Contains(x, " ") {
			return Lookup(ctx, x[1:])
		}
		if strings.Contains(x, "{") {
			return interpolate(x, ctx)
		}
		return x, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			r, err := Render(v, ctx)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			r, err := Render(v, ctx)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	}
	return t, nil
}

// References lists the top-level contexts a template reads.
func References(t any) map[string]bool {
	out := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if strings.HasPrefix(x, "$") {
				out[strings.SplitN(x[1:], ".", 2)[0]] = true
			}
			for rest := x; ; {
				i := strings.IndexByte(rest, '{')
				if i < 0 {
					break
				}
				j := strings.IndexByte(rest[i:], '}')
				if j < 0 {
					break
				}
				out[strings.SplitN(rest[i+1:i+j], ".", 2)[0]] = true
				rest = rest[i+j:]
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(t)
	return out
}

type Action struct {
	Tool, Name, Kind, Description, Risk string
	Request                             map[string]any
	Params                              map[string]any
	Required                            []string
	CaptureBefore, Undo, LookupSpec     map[string]any
	Audience, Test                      map[string]any
	UndoWindow, Delay                   float64
	SideEffects, Compare                []string
	// Destinations names the arguments that say where an effect goes (recipients, URL,
	// account, venue). A destination the user's request does not name needs approval.
	Destinations []string
	Raw          map[string]any
}

func (a *Action) Digest() string {
	b, _ := json.Marshal(a.Raw)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

func (a *Action) validate() []string {
	var errs []string
	known := false
	for _, k := range Kinds {
		known = known || k == a.Kind
	}
	if !known {
		errs = append(errs, fmt.Sprintf("kind must be one of %v", Kinds))
	}
	if a.Request["method"] == nil || a.Request["path"] == nil {
		errs = append(errs, "request needs method and path")
	}
	if (a.Kind == "reversible" || a.Kind == "compensable") && a.Undo == nil {
		errs = append(errs, a.Kind+" action needs an undo recipe")
	}
	if a.Kind == "reversible" && a.CaptureBefore == nil {
		errs = append(errs, "reversible action needs capture_before")
	}
	if a.Kind == "compensable" && a.Undo != nil && References(a.Undo["args"])["before"] {
		errs = append(errs, "compensable undo cannot use $before (nothing is captured)")
	}
	for i := range errs {
		errs[i] = a.Tool + "." + a.Name + ": " + errs[i]
	}
	return errs
}

type Tool struct {
	Name, BaseURL, Credential, IdempotencyHeader, Encoding, AuthScheme, SuccessField string
	Actions                                                                          map[string]*Action
	Source                                                                           string
	Verified                                                                         map[string]string
}

func (t *Tool) IsVerified(a *Action) bool { return t.Verified[a.Name] == a.Digest() }

func (t *Tool) ActionNames() []string {
	out := make([]string, 0, len(t.Actions))
	for n := range t.Actions {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// normalize converts YAML/TOML decoded values into JSON-shaped values.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalize(e)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[fmt.Sprint(k)] = normalize(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	case int:
		return float64(x)
	case int64:
		return float64(x)
	}
	return v
}

func decodeFile(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	switch filepath.Ext(path) {
	case ".toml":
		_, err = toml.Decode(string(b), &data)
	case ".json":
		err = json.Unmarshal(b, &data)
	case ".yaml", ".yml":
		err = yaml.Unmarshal(b, &data)
	default:
		return nil, fmt.Errorf("%s: unsupported registry format", path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m, _ := normalize(data).(map[string]any)
	return m, nil
}

func str(m map[string]any, k, def string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return def
}

func mapOf(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }

func strList(m map[string]any, k string) []string {
	var out []string
	if l, ok := m[k].([]any); ok {
		for _, e := range l {
			out = append(out, fmt.Sprint(e))
		}
	}
	return out
}

func VerifiedPath(src string) string { return filepath.Join(filepath.Dir(src), "verified.json") }

func LoadTool(path string) (*Tool, error) {
	data, err := decodeFile(path)
	if err != nil {
		return nil, err
	}
	t := mapOf(data, "tool")
	if t == nil {
		return nil, fmt.Errorf("%s: missing [tool]", path)
	}
	tool := &Tool{Name: str(t, "name", ""), BaseURL: strings.TrimRight(str(t, "base_url", ""), "/"),
		Credential: str(t, "credential", ""), IdempotencyHeader: str(t, "idempotency_header", "Idempotency-Key"),
		Encoding: str(t, "encoding", "json"), AuthScheme: str(t, "auth_scheme", "Bearer"),
		SuccessField: str(t, "success_field", ""), Actions: map[string]*Action{}, Source: path, Verified: map[string]string{}}
	var errs []string
	for name, raw := range mapOf(data, "action") {
		a, _ := raw.(map[string]any)
		uw, err1 := Duration(a["undo_window"])
		dl, err2 := Duration(a["delay"])
		for _, e := range []error{err1, err2} {
			if e != nil {
				errs = append(errs, tool.Name+"."+name+": "+e.Error())
			}
		}
		act := &Action{Tool: tool.Name, Name: name, Kind: str(a, "kind", "irreversible"), Description: str(a, "description", ""),
			Risk: str(a, "risk", "low"), Request: mapOf(a, "request"), Params: mapOf(a, "params"), Required: strList(a, "required"),
			CaptureBefore: mapOf(a, "capture_before"), Undo: mapOf(a, "undo"), LookupSpec: mapOf(a, "lookup"),
			Audience: mapOf(a, "audience"), Test: mapOf(a, "test"), UndoWindow: uw, Delay: dl,
			SideEffects: strList(a, "side_effects"), Compare: strList(a, "compare"),
			Destinations: strList(a, "destinations"), Raw: a}
		if act.Params == nil {
			act.Params = map[string]any{}
		}
		tool.Actions[name] = act
		errs = append(errs, act.validate()...)
	}
	for _, a := range tool.Actions {
		for _, spec := range []map[string]any{a.CaptureBefore, a.Undo, a.LookupSpec, a.Audience} {
			if c, ok := spec["call"].(string); ok && tool.Actions[c] == nil {
				errs = append(errs, fmt.Sprintf("%s.%s: refers to unknown action %q", tool.Name, a.Name, c))
			}
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("invalid registry:\n  %s", strings.Join(errs, "\n  "))
	}
	if b, err := os.ReadFile(VerifiedPath(path)); err == nil {
		var all map[string]map[string]string
		if json.Unmarshal(b, &all) == nil && all[tool.Name] != nil {
			tool.Verified = all[tool.Name]
		}
	}
	return tool, nil
}

func LoadDir(path string) ([]*Tool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	files := []string{path}
	if st.IsDir() {
		files = nil
		ents, _ := os.ReadDir(path)
		for _, e := range ents {
			ext := filepath.Ext(e.Name())
			if (ext == ".toml" || ext == ".json" || ext == ".yaml" || ext == ".yml") && e.Name() != "verified.json" {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(files)
	}
	var tools []*Tool
	for _, f := range files {
		t, err := LoadTool(f)
		if err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}
	return tools, nil
}

// MarkVerified records that an action passed its round trip.
func MarkVerified(t *Tool, action string) error {
	vp := VerifiedPath(t.Source)
	all := map[string]map[string]string{}
	if b, err := os.ReadFile(vp); err == nil {
		_ = json.Unmarshal(b, &all)
	}
	if all[t.Name] == nil {
		all[t.Name] = map[string]string{}
	}
	all[t.Name][action] = t.Actions[action].Digest()
	t.Verified[action] = all[t.Name][action]
	b, _ := json.MarshalIndent(all, "", "  ")
	return os.WriteFile(vp, append(b, '\n'), 0o644)
}
