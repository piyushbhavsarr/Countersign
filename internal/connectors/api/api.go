// Package api is the gateway connector for any HTTP tool described in the registry.
// The agent never holds the tool's credential and cannot add headers. Per lane:
// reversible (before/after captured, exact inverse stored), compensable (fix recipe
// filled from the response), deferrable (outbox), irreversible (approval). Every call
// and every undo carries an idempotency key.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"undolayer/internal/creds"
	"undolayer/internal/model"
	"undolayer/internal/registry"
	"undolayer/internal/taint"
	"undolayer/internal/tx"
)

// Transport sends one HTTP request (swappable in tests).
type Transport func(method, url string, headers map[string]string, body []byte) (int, []byte, error)

func HTTPTransport(method, u string, headers map[string]string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

type APIError struct {
	Status int
	Body   any
}

func (e *APIError) Error() string { return fmt.Sprintf("HTTP %d: %.500v", e.Status, e.Body) }

var laneEffect = map[string]model.Effect{"read": model.Read, "reversible": model.Compensable, "compensable": model.Compensable,
	"deferrable": model.Deferrable, "irreversible": model.Irreversible}

type Connector struct {
	tx.Base
	Tool            *registry.Tool
	Creds           creds.Store
	Transport       Transport
	RequireVerified bool
}

func New(tool *registry.Tool, c creds.Store, tr Transport) *Connector {
	if tr == nil {
		tr = HTTPTransport
	}
	return &Connector{Base: tx.Base{ConnName: tool.Name}, Tool: tool, Creds: c, Transport: tr, RequireVerified: true}
}

func (*Connector) Egress() bool { return true }

func (c *Connector) Lane(a *registry.Action) string {
	switch a.Kind {
	case "read", "irreversible", "deferrable":
		return a.Kind // deferrable needs no recipe: undoing it is deleting it from the queue
	}
	if c.RequireVerified && !c.Tool.IsVerified(a) {
		return "irreversible" // an undo recipe nobody round-trip tested is not trusted
	}
	return a.Kind
}

func (c *Connector) Operations() map[string]tx.OpSchema {
	out := map[string]tx.OpSchema{}
	for name, a := range c.Tool.Actions {
		d := a.Description
		if d == "" {
			d = name
		}
		d += " [" + c.Lane(a)
		if len(a.SideEffects) > 0 {
			d += "; side effects: " + strings.Join(a.SideEffects, ", ")
		}
		out[name] = tx.OpSchema{Description: d + "]", Properties: a.Params, Required: a.Required}
	}
	return out
}

func (c *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	a := c.Tool.Actions[op]
	lane := c.Lane(a)
	unknown := []string{}
	if len(a.Params) > 0 {
		for k := range args {
			if _, ok := a.Params[k]; !ok {
				unknown = append(unknown, k)
			}
		}
		sort.Strings(unknown)
	}
	var dests []string
	for _, d := range a.Destinations {
		collectStrings(args[d], &dests)
	}
	f := model.Facts{"tool": c.Tool.Name, "action": op, "lane": lane, "destinations": dests, "address_fields": a.Destinations, "declared_lane": a.Kind, "verified": c.Tool.IsVerified(a),
		"risk": a.Risk, "side_effects": a.SideEffects, "unknown_args": unknown, "delay": a.Delay}
	if a.Audience != nil {
		spec := map[string]any{}
		for k, v := range a.Audience {
			if k != "field" {
				spec[k] = v
			}
		}
		f["audience"], f["audience_known"] = 0, false
		if r, err := registry.Render(spec, map[string]any{"args": args}); err == nil {
			rm := r.(map[string]any)
			callArgs, _ := rm["args"].(map[string]any)
			if res, err := c.Invoke(fmt.Sprint(rm["call"]), callArgs, ""); err == nil {
				if v, err := registry.Lookup(res, fmt.Sprint(a.Audience["field"])); err == nil {
					if n, ok := model.Num(v); ok {
						f["audience"], f["audience_known"] = n, true
					}
				}
			}
		}
	}
	return laneEffect[lane], f, nil
}

func collectStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		if strings.TrimSpace(x) != "" {
			*out = append(*out, x)
		}
	case []any:
		for _, e := range x {
			collectStrings(e, out)
		}
	case float64:
		*out = append(*out, fmt.Sprint(x))
	}
}

func (c *Connector) ContributeSensitive(t *tx.Tx, idx *taint.Index) { c.Creds.Contribute(idx) }

// Invoke performs one registry action for real.
func (c *Connector) Invoke(action string, args map[string]any, key string) (any, error) {
	a, ok := c.Tool.Actions[action]
	if !ok {
		return nil, fmt.Errorf("%s has no action %s", c.Tool.Name, action)
	}
	if args == nil {
		args = map[string]any{}
	}
	ctx := map[string]any{"args": args}
	method := strings.ToUpper(fmt.Sprint(a.Request["method"]))
	p, err := registry.RenderPath(a.Request["path"], ctx)
	if err != nil {
		return nil, err
	}
	u := c.Tool.BaseURL + p
	if base, err1 := url.Parse(c.Tool.BaseURL); err1 == nil {
		got, err2 := url.Parse(u)
		if err2 != nil || got.Scheme != base.Scheme || got.Host != base.Host {
			return nil, fmt.Errorf("%s.%s: the request would leave %s", c.Tool.Name, action, base.Host)
		}
	}
	if qt, ok := a.Request["query"]; ok && qt != nil {
		qv, err := registry.Render(qt, ctx)
		if err != nil {
			return nil, err
		}
		vals := url.Values{}
		for k, v := range qv.(map[string]any) {
			if v != nil {
				vals.Set(k, scalar(v))
			}
		}
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u += sep + vals.Encode()
	}
	var bodyT any = a.Request["body"]
	if _, has := a.Request["body"]; !has && method != "GET" && method != "HEAD" && method != "DELETE" {
		bodyT = "$args"
	}
	headers := map[string]string{"Accept": "application/json", "User-Agent": "undolayer"}
	var body []byte
	if bodyT != nil {
		bv, err := registry.Render(bodyT, ctx)
		if err != nil {
			return nil, err
		}
		if m, ok := bv.(map[string]any); ok {
			for k, v := range m {
				if v == nil {
					delete(m, k)
				}
			}
		}
		if c.Tool.Encoding == "form" {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
			vals := url.Values{}
			flattenForm(bv, "", vals)
			body = []byte(vals.Encode())
		} else {
			headers["Content-Type"] = "application/json"
			body, _ = json.Marshal(bv)
		}
	}
	if c.Tool.Credential != "" {
		pu, _ := url.Parse(u)
		sec, err := c.Creds.Resolve(c.Tool.Credential, pu.Hostname())
		if err != nil {
			return nil, err
		}
		headers["Authorization"] = c.Tool.AuthScheme + " " + sec
	}
	if key != "" && c.Tool.IdempotencyHeader != "" {
		headers[c.Tool.IdempotencyHeader] = key
	}
	status, raw, err := c.Transport(method, u, headers, body)
	if err != nil {
		return nil, err
	}
	var parsed any
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		if dec.Decode(&parsed) != nil {
			s := string(raw)
			if len(s) > 5000 {
				s = s[:5000]
			}
			parsed = s
		}
	}
	if status >= 400 {
		return nil, &APIError{Status: status, Body: parsed}
	}
	if f := c.Tool.SuccessField; f != "" {
		if m, ok := parsed.(map[string]any); ok && m[f] != true {
			return nil, &APIError{Status: status, Body: parsed}
		}
	}
	return parsed, nil
}

func scalar(v any) string {
	switch x := v.(type) {
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprint(int64(x))
		}
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return fmt.Sprint(v)
}

func flattenForm(v any, prefix string, out url.Values) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			name := k
			if prefix != "" {
				name = prefix + "[" + k + "]"
			}
			flattenForm(x[k], name, out)
		}
	case []any:
		for i, e := range x {
			flattenForm(e, fmt.Sprintf("%s[%d]", prefix, i), out)
		}
	case nil:
	default:
		out.Add(prefix, scalar(x))
	}
}

type Recipe struct {
	Tool        string         `json:"tool"`
	Action      string         `json:"action"`
	Kind        string         `json:"kind"`
	Call        string         `json:"call"`
	Args        map[string]any `json:"args"`
	Key         string         `json:"key"`
	Expires     float64        `json:"expires,omitempty"`
	CheckCall   string         `json:"check_call,omitempty"`
	CheckArgs   map[string]any `json:"check_args,omitempty"`
	After       any            `json:"after,omitempty"`
	Compare     []string       `json:"compare,omitempty"`
	SideEffects []string       `json:"side_effects,omitempty"`
}

func subset(obj any, fields []string) any {
	m, ok := obj.(map[string]any)
	if len(fields) == 0 || !ok {
		return obj
	}
	out := map[string]any{}
	for _, f := range fields {
		v, err := registry.Lookup(m, f)
		if err != nil {
			v = nil
		}
		out[f] = v
	}
	return out
}

func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func (c *Connector) recipe(a *registry.Action, ctx map[string]any, key string, check map[string]any) (*Recipe, error) {
	u, err := registry.Render(a.Undo, ctx)
	if err != nil {
		return nil, err
	}
	um := u.(map[string]any)
	args, _ := um["args"].(map[string]any)
	r := &Recipe{Tool: c.Tool.Name, Action: a.Name, Kind: c.Lane(a), Call: fmt.Sprint(um["call"]), Args: args,
		Key: key + "-undo", SideEffects: a.SideEffects}
	if a.UndoWindow > 0 {
		r.Expires = model.Now() + a.UndoWindow
	}
	if check != nil {
		fields := a.Compare
		if len(fields) == 0 {
			if am, ok := ctx["args"].(map[string]any); ok {
				for k := range am {
					fields = append(fields, k)
				}
				sort.Strings(fields)
			}
		}
		r.CheckCall = fmt.Sprint(check["call"])
		r.CheckArgs, _ = check["args"].(map[string]any)
		r.After, r.Compare = normalize(subset(ctx["after"], fields)), fields
	}
	return r, nil
}

func (c *Connector) Stage(t *tx.Tx, act *model.Action) (any, error) {
	a := c.Tool.Actions[act.Operation]
	lane, _ := act.Facts["lane"].(string)
	key := t.ID + "-" + act.ID
	ctx := map[string]any{"args": act.Args, "tx": map[string]any{"id": t.ID}, "step": map[string]any{"key": key}}
	switch lane {
	case "read":
		return c.Invoke(a.Name, act.Args, "")
	case "reversible":
		ck, err := registry.Render(a.CaptureBefore, ctx)
		if err != nil {
			return nil, err
		}
		check := ck.(map[string]any)
		cargs, _ := check["args"].(map[string]any)
		if ctx["before"], err = c.Invoke(fmt.Sprint(check["call"]), cargs, ""); err != nil {
			return nil, err
		}
		if ctx["response"], err = c.Invoke(a.Name, act.Args, key); err != nil {
			return nil, err
		}
		if ctx["after"], err = c.Invoke(fmt.Sprint(check["call"]), cargs, ""); err != nil {
			return nil, err
		}
		r, err := c.recipe(a, ctx, key, check)
		if err != nil {
			return nil, err
		}
		return &tx.Staged{Result: map[string]any{"response": ctx["response"], "before": ctx["before"]},
			Comp: &tx.Compensation{Kind: "reversible", Record: r, SideEffects: a.SideEffects}}, nil
	case "compensable":
		var err error
		if ctx["response"], err = c.Invoke(a.Name, act.Args, key); err != nil {
			return nil, err
		}
		r, err := c.recipe(a, ctx, key, nil)
		if err != nil {
			return nil, err
		}
		return &tx.Staged{Result: map[string]any{"response": ctx["response"]},
			Comp: &tx.Compensation{Kind: "compensable", Record: r, SideEffects: a.SideEffects}}, nil
	}
	return nil, fmt.Errorf("%s actions are never staged eagerly", lane)
}

func (c *Connector) RunDeferred(t *tx.Tx, act *model.Action) (any, error) {
	a := c.Tool.Actions[act.Operation]
	key, _ := act.Facts["idempotency_key"].(string)
	resp, err := c.Invoke(a.Name, act.Args, key)
	if err != nil {
		return nil, err
	}
	out := &tx.Staged{Result: map[string]any{"response": resp}}
	if a.Undo != nil && !registry.References(a.Undo)["before"] {
		ctx := map[string]any{"args": act.Args, "response": resp, "tx": map[string]any{"id": t.ID}, "step": map[string]any{"key": key}}
		if r, err := c.recipe(a, ctx, key, nil); err == nil {
			out.Comp = &tx.Compensation{Kind: "compensable", Record: r, SideEffects: a.SideEffects}
		}
	}
	return out, nil
}

func (c *Connector) Compensate(raw json.RawMessage) error {
	var r Recipe
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	if r.Expires > 0 && model.Now() > r.Expires {
		return &model.NotUndoable{Msg: r.Tool + "." + r.Action + ": undo window expired"}
	}
	if r.CheckCall != "" {
		now, err := c.Invoke(r.CheckCall, r.CheckArgs, "")
		if err != nil {
			return err
		}
		if got := normalize(subset(now, r.Compare)); !reflect.DeepEqual(got, r.After) {
			return model.Conflict("%s.%s: changed since the agent acted (expected %v, found %v); not overwriting",
				r.Tool, r.Action, r.After, got)
		}
	}
	_, err := c.Invoke(r.Call, r.Args, r.Key)
	return err
}

// Reconcile: after a crash, did a step logged "about to run" happen?
func (c *Connector) Reconcile(t *tx.Tx, act *model.Action, key string) (tx.Reconciled, error) {
	a := c.Tool.Actions[act.Operation]
	if a.LookupSpec == nil {
		return tx.Reconciled{Status: "unknown", Reason: a.Name + " has no lookup in the registry"}, nil
	}
	ctx := map[string]any{"args": act.Args, "step": map[string]any{"key": key}, "tx": map[string]any{"id": t.ID}}
	var found any
	var err error
	if a.LookupSpec["replay"] == true {
		found, err = c.Invoke(a.Name, act.Args, key) // the tool deduplicates by key and replays the original result
	} else {
		lq, rerr := registry.Render(a.LookupSpec, ctx)
		if rerr != nil {
			return tx.Reconciled{}, rerr
		}
		m := lq.(map[string]any)
		largs, _ := m["args"].(map[string]any)
		found, err = c.Invoke(fmt.Sprint(m["call"]), largs, "")
	}
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == 404 {
		return tx.Reconciled{Status: "not_run"}, nil
	}
	if err != nil {
		return tx.Reconciled{}, err
	}
	if found == nil {
		return tx.Reconciled{Status: "not_run"}, nil
	}
	res := tx.Reconciled{Status: "done"}
	if a.Undo != nil && c.Lane(a) == "compensable" {
		ctx["response"] = found
		if r, err := c.recipe(a, ctx, key, nil); err == nil {
			res.Comp = &tx.Compensation{Kind: "compensable", Record: r, SideEffects: a.SideEffects}
		}
	}
	return res, nil
}
