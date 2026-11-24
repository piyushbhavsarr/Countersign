// Package effects: generic HTTP through the gateway, and messaging (the deferrable lane).
//
// http.request: methods HTTP defines as safe (GET, HEAD, OPTIONS; RFC 9110 9.2.1) run
// now; anything else has no known inverse, so it is irreversible (approval, runs on
// commit). The agent cannot set headers beyond an allow-list; credentials are injected
// for the hosts they are scoped to; other hosts are refused.
//
// effect.email/sms/slack/webhook: queued, sent on commit after an optional "undo send"
// delay. Audience size is a fact (recipients, or the operator's resolver for channels);
// unknown audience means approval.
package effects

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"undolayer/internal/connectors/api"
	"undolayer/internal/creds"
	"undolayer/internal/model"
	"undolayer/internal/taint"
	"undolayer/internal/tx"
)

var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

type HTTP struct {
	tx.Base
	Creds          creds.Store
	Transport      api.Transport
	AllowHosts     []string
	AllowedHeaders []string
}

func NewHTTP(c creds.Store, tr api.Transport) *HTTP {
	if tr == nil {
		tr = api.HTTPTransport
	}
	return &HTTP{Base: tx.Base{ConnName: "http"}, Creds: c, Transport: tr, AllowedHeaders: []string{"accept", "content-type"}}
}

func (*HTTP) Egress() bool { return true }

func (h *HTTP) Operations() map[string]tx.OpSchema {
	return map[string]tx.OpSchema{"request": {Description: "Call an external HTTP API through the gateway. Name a delegated " +
		"credential handle; never pass tokens. GET/HEAD run now; other methods need approval and run on commit.",
		Properties: map[string]any{"method": map[string]any{"type": "string"}, "url": map[string]any{"type": "string"},
			"json": map[string]any{"type": "object"}, "headers": map[string]any{"type": "object"},
			"credential": map[string]any{"type": "string"}}, Required: []string{"method", "url"}}}
}

func (h *HTTP) allowedHeader(k string) bool {
	for _, a := range h.AllowedHeaders {
		if strings.EqualFold(a, k) {
			return true
		}
	}
	return false
}

func (h *HTTP) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	method := strings.ToUpper(fmt.Sprint(args["method"]))
	if method == "<NIL>" || method == "" {
		method = "GET"
	}
	u, _ := url.Parse(fmt.Sprint(args["url"]))
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	bad := []string{}
	if hd, ok := args["headers"].(map[string]any); ok {
		for k := range hd {
			if !h.allowedHeader(k) {
				bad = append(bad, k)
			}
		}
	}
	allowed := false
	if c, ok := args["credential"].(string); ok && c != "" {
		allowed = h.Creds.Covers(c, host)
	} else {
		for _, p := range h.AllowHosts {
			if m, _ := path.Match(p, host); m {
				allowed = true
			}
		}
	}
	f := model.Facts{"method": method, "host": host, "agent_headers": bad, "host_allowed": allowed}
	if safeMethods[method] {
		return model.Read, f, nil
	}
	return model.Irreversible, f, nil
}

func (h *HTTP) ContributeSensitive(t *tx.Tx, idx *taint.Index) { h.Creds.Contribute(idx) }

func (h *HTTP) send(args map[string]any, key string) (any, error) {
	u := fmt.Sprint(args["url"])
	pu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"Content-Type": "application/json", "User-Agent": "undolayer"}
	if hd, ok := args["headers"].(map[string]any); ok {
		for k, v := range hd {
			if h.allowedHeader(k) {
				headers[k] = fmt.Sprint(v)
			}
		}
	}
	if c, ok := args["credential"].(string); ok && c != "" {
		sec, err := h.Creds.Resolve(c, pu.Hostname())
		if err != nil {
			return nil, err
		}
		headers["Authorization"] = "Bearer " + sec
	}
	if key != "" {
		headers["Idempotency-Key"] = key
	}
	var body []byte
	if j, ok := args["json"]; ok && j != nil {
		body, _ = json.Marshal(j)
	}
	method := strings.ToUpper(fmt.Sprint(args["method"]))
	status, raw, err := h.Transport(method, u, headers, body)
	if err != nil {
		return nil, err
	}
	var parsed any
	if json.Unmarshal(raw, &parsed) != nil {
		parsed = string(raw)
	}
	if status >= 400 {
		return nil, &api.APIError{Status: status, Body: parsed}
	}
	return map[string]any{"status": status, "body": parsed}, nil
}

func (h *HTTP) Stage(t *tx.Tx, a *model.Action) (any, error) { return h.send(a.Args, "") }

func (h *HTTP) RunDeferred(t *tx.Tx, a *model.Action) (any, error) {
	k, _ := a.Facts["idempotency_key"].(string)
	return h.send(a.Args, k)
}

// ====================================================================== messaging

type Sender func(payload map[string]any) (any, error)

// Audience returns how many people a message reaches, or ok=false if unknown.
type Audience func(op string, args map[string]any) (n float64, ok bool)

type Effect struct {
	tx.Base
	Senders    map[string]Sender
	OrgDomains []string
	Audience   Audience
	Delays     map[string]float64
	OutboxFile string
	// WebhookHosts are destinations the operator trusts (globs); others are external.
	WebhookHosts []string
}

func NewEffect() *Effect {
	return &Effect{Base: tx.Base{ConnName: "effect"}, Senders: map[string]Sender{}, Delays: map[string]float64{}}
}

func (*Effect) Egress() bool { return true }

func (e *Effect) Operations() map[string]tx.OpSchema {
	s := map[string]any{"type": "string"}
	arr := map[string]any{"type": "array", "items": s}
	held := " Queued; sent only when the transaction commits."
	return map[string]tx.OpSchema{
		"email":   {Description: "Send an email." + held, Properties: map[string]any{"to": arr, "subject": s, "body": s}, Required: []string{"to", "subject", "body"}},
		"slack":   {Description: "Post a chat message." + held, Properties: map[string]any{"channel": s, "text": s}, Required: []string{"channel", "text"}},
		"sms":     {Description: "Send an SMS." + held, Properties: map[string]any{"to": arr, "body": s}, Required: []string{"to", "body"}},
		"webhook": {Description: "POST to a webhook." + held, Properties: map[string]any{"url": s, "json": map[string]any{"type": "object"}}, Required: []string{"url"}},
	}
}

func recipients(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := []string{}
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case []string:
		return x
	}
	return nil
}

func (e *Effect) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	to := recipients(args["to"])
	f := model.Facts{"channel_kind": op, "delay": e.Delays[op], "address_fields": []string{"to", "channel", "url"}}
	switch op {
	case "email", "sms":
		f["audience"], f["audience_known"] = len(to), true
	case "webhook":
		f["audience"], f["audience_known"] = 1, true
		host := ""
		if u, err := url.Parse(fmt.Sprint(args["url"])); err == nil {
			host = u.Hostname()
		}
		trusted := false
		for _, p := range e.WebhookHosts {
			if m, _ := path.Match(p, host); m {
				trusted = true
			}
		}
		f["host"], f["external_destination"] = host, !trusted
	default:
		n, ok := 0.0, false
		if e.Audience != nil {
			n, ok = e.Audience(op, args)
		}
		f["audience"], f["audience_known"] = n, ok
	}
	if op == "email" {
		ext := 0
		for _, addr := range to {
			dom := strings.ToLower(addr[strings.LastIndex(addr, "@")+1:])
			internal := false
			for _, d := range e.OrgDomains {
				internal = internal || strings.EqualFold(d, dom)
			}
			if !internal {
				ext++
			}
		}
		f["external_recipients"] = ext
	}
	return model.Deferrable, f, nil
}

func (e *Effect) RunDeferred(t *tx.Tx, a *model.Action) (any, error) {
	p := map[string]any{}
	for k, v := range a.Args {
		p[k] = v
	}
	p["idempotency_key"] = a.Facts["idempotency_key"]
	if s := e.Senders[a.Operation]; s != nil {
		return s(p)
	}
	if e.OutboxFile != "" {
		f, err := os.OpenFile(e.OutboxFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		p["kind"] = a.Operation
		b, _ := json.Marshal(p)
		_, err = f.Write(append(b, '\n'))
		return map[string]any{"delivered_to": e.OutboxFile}, err
	}
	return nil, fmt.Errorf("no transport configured for %s", a.Operation)
}

// SlackAudience resolves channel sizes with Slack's conversations.info.
func SlackAudience(tokenEnv string, tr api.Transport) Audience {
	if tr == nil {
		tr = api.HTTPTransport
	}
	return func(op string, args map[string]any) (float64, bool) {
		ch := strings.TrimPrefix(fmt.Sprint(args["channel"]), "#")
		u := "https://slack.com/api/conversations.info?" + url.Values{"channel": {ch}, "include_num_members": {"true"}}.Encode()
		status, raw, err := tr("GET", u, map[string]string{"Authorization": "Bearer " + os.Getenv(tokenEnv)}, nil)
		if err != nil || status >= 400 {
			return 0, false
		}
		var body struct {
			OK      bool `json:"ok"`
			Channel struct {
				NumMembers *float64 `json:"num_members"`
			} `json:"channel"`
		}
		if json.Unmarshal(raw, &body) != nil || !body.OK || body.Channel.NumMembers == nil {
			return 0, false
		}
		return *body.Channel.NumMembers, true
	}
}
