// Package mcp serves the gateway over the Model Context Protocol (JSON-RPC 2.0, one
// message per line) on stdio or on a Unix socket. Every connector operation becomes a
// tool named <connector>_<operation>; undolayer_begin/preview/commit/rollback manage the
// session's transaction. The agent can never approve: approvals are HMAC tokens from a
// key the agent cannot read, bound to the preview hash.
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"undolayer/internal/model"
	"undolayer/internal/tx"
)

const ProtocolVersion = "2025-06-18"

var supported = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true, "2025-11-25": true}

const Instructions = baseInstructions + approvalAtCommit

const baseInstructions = "All tools from this server run inside a transaction. File, shell and SQL writes are staged and " +
	"invisible to anyone until undolayer_commit. API actions that can be undone run now with their undo recorded; " +
	"messages and other sends are queued and go out on commit; actions that cannot be undone wait for a human. " +
	"Before committing, call undolayer_preview and check the diff. Values shown as [REDACTED:...] are secrets you do " +
	"not need; the gateway's tools hold the credentials. If a tool is denied, do not try to reach the same effect " +
	"another way; tell the user what you wanted to do. "

type Session struct {
	mgr     *tx.Manager
	tx      *tx.Tx
	version string
}

// instructions tells the agent how approval works with this gateway's settings.
func (s *Session) instructions() string {
	if s.mgr.ApprovalWait <= 0 {
		return Instructions
	}
	return baseInstructions + waitingApproval(s.mgr.ApprovalWait)
}

const approvalAtCommit = "If preview says approval is required, stop and ask the user " +
	"to run the approval command, then commit."

func waitingApproval(d time.Duration) string {
	return fmt.Sprintf("If preview says approval is required, call undolayer_commit anyway: a human reviewer is asked "+
		"about the exact preview, and the commit waits up to %s for their decision. If they decline, roll back and tell "+
		"the user what was declined; do not retry it another way.", d)
}

func NewSession(m *tx.Manager, version string) *Session { return &Session{mgr: m, version: version} }

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func (s *Session) Tools() []tool {
	obj := func(p map[string]any) map[string]any {
		if p == nil {
			p = map[string]any{}
		}
		return map[string]any{"type": "object", "properties": p}
	}
	out := []tool{
		{Name: "undolayer_begin", Description: "Start a new transaction for a task. Rolls back any open one.",
			InputSchema: obj(map[string]any{"task": map[string]any{"type": "string"}})},
		{Name: "undolayer_preview", Description: "Show every staged change, held effect and whether approval is needed.",
			InputSchema: obj(nil), Annotations: map[string]any{"readOnlyHint": true}},
		{Name: "undolayer_commit", Description: "Commit all staged changes and release held effects, as one unit.",
			InputSchema: obj(nil), Annotations: map[string]any{"destructiveHint": true}},
		{Name: "undolayer_cancel", Description: "Drop held actions (by action_id) before commit; they never run.",
			InputSchema: obj(map[string]any{"action_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}})},
		{Name: "undolayer_rollback", Description: "Discard all staged changes, undo eager steps, cancel held effects.",
			InputSchema: obj(map[string]any{"reason": map[string]any{"type": "string"}})},
	}
	conns := s.mgr.Connectors()
	names := make([]string, 0, len(conns))
	for n := range conns {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, cn := range names {
		if h, ok := conns[cn].(tx.Hidden); ok && h.Hidden() {
			continue
		}
		ops := conns[cn].Operations()
		opn := make([]string, 0, len(ops))
		for o := range ops {
			opn = append(opn, o)
		}
		sort.Strings(opn)
		for _, o := range opn {
			op := ops[o]
			schema := obj(op.Properties)
			req := op.Required
			if req == nil {
				req = []string{}
			}
			schema["required"] = req
			out = append(out, tool{Name: cn + "_" + o, Description: op.Description + " [transactional]", InputSchema: schema})
		}
	}
	return out
}

func (s *Session) route(name string) (string, string, error) {
	best := ""
	for cn, c := range s.mgr.Connectors() {
		if h, ok := c.(tx.Hidden); ok && h.Hidden() {
			continue // never callable by an agent
		}
		if strings.HasPrefix(name, cn+"_") {
			if _, ok := c.Operations()[name[len(cn)+1:]]; ok && len(cn) > len(best) {
				best = cn
			}
		}
	}
	if best == "" {
		return "", "", fmt.Errorf("unknown tool %s", name)
	}
	return best, name[len(best)+1:], nil
}

func (s *Session) current() *tx.Tx {
	if s.tx == nil || s.tx.State != model.Open {
		s.tx = s.mgr.Begin("mcp session")
	}
	return s.tx
}

// CallTool returns (payload, isError).
func (s *Session) CallTool(name string, args map[string]any) (any, bool) {
	res, err := s.call(name, args)
	if err == nil {
		return res, false
	}
	var pv *model.PolicyViolation
	var ar *model.ApprovalRequired
	var cc *model.CommitConflict
	var no *model.NotOwner
	switch {
	case errors.As(err, &pv):
		return map[string]any{"denied": true, "decision": pv.Action.Decision, "reasons": pv.Action.Reasons,
			"guidance": "This action is blocked by policy. Do not retry it or work around it; tell the user."}, true
	case errors.As(err, &ar):
		return map[string]any{"approval_required": true, "message": ar.Msg}, true
	case errors.As(err, &cc):
		return map[string]any{"conflict": true, "message": cc.Msg, "rolled_back": true}, true
	case errors.As(err, &no):
		s.tx = nil
		return map[string]any{"error": no.Msg, "note": "start a new transaction with undolayer_begin"}, true
	}
	return map[string]any{"error": err.Error()}, true
}

func (s *Session) call(name string, args map[string]any) (any, error) {
	switch name {
	case "undolayer_begin":
		if s.tx != nil && s.tx.State == model.Open {
			_, _ = s.tx.Rollback("new transaction started")
		}
		task, _ := args["task"].(string)
		s.tx = s.mgr.Begin(task)
		return map[string]any{"tx": s.tx.ID}, nil
	case "undolayer_preview":
		pv := s.current().Preview()
		if pv["approval_required"] == true && pv["approved"] != true {
			if s.mgr.ApprovalWait > 0 {
				pv["next_step"] = "Call undolayer_commit: it asks a human reviewer and waits for their decision."
			} else {
				pv["next_step"] = "Ask the user to run: undolayer approve " + s.current().ID + " ; then call undolayer_commit."
			}
		}
		return pv, nil
	case "undolayer_commit":
		r, err := s.current().Commit()
		if err == nil {
			s.tx = nil
		}
		return r, err
	case "undolayer_cancel":
		var ids []string
		if l, ok := args["action_ids"].([]any); ok {
			for _, x := range l {
				ids = append(ids, fmt.Sprint(x))
			}
		}
		return map[string]any{"cancelled": ids}, s.current().Cancel(ids...)
	case "undolayer_rollback":
		reason, _ := args["reason"].(string)
		if reason == "" {
			reason = "agent requested"
		}
		r, err := s.current().Rollback(reason)
		s.tx = nil
		return r, err
	}
	cn, op, err := s.route(name)
	if err != nil {
		return nil, err
	}
	t := s.current()
	r, err := t.Call(cn, op, args)
	if err != nil {
		return nil, err
	}
	return map[string]any{"tx": t.ID, "result": r}, nil
}

// Close rolls back an open transaction (client disconnected).
func (s *Session) Close() {
	if s.tx != nil && s.tx.State == model.Open {
		_, _ = s.tx.Rollback("client disconnected")
	}
}

type rpc struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (s *Session) Handle(line []byte) []byte {
	var m rpc
	if err := json.Unmarshal(line, &m); err != nil {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error"}})
		return b
	}
	if len(m.ID) == 0 || string(m.ID) == "null" {
		return nil // notification
	}
	reply := func(result any) []byte {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		return b
	}
	switch m.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(m.Params, &p)
		v := ProtocolVersion
		if supported[p.ProtocolVersion] {
			v = p.ProtocolVersion
		}
		return reply(map[string]any{"protocolVersion": v, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo": map[string]any{"name": "undolayer", "version": s.version}, "instructions": s.instructions()})
	case "ping":
		return reply(map[string]any{})
	case "tools/list":
		return reply(map[string]any{"tools": s.Tools()})
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		_ = json.Unmarshal(m.Params, &p)
		payload, isErr := s.CallTool(p.Name, p.Arguments)
		b, _ := json.Marshal(payload)
		var structured any
		_ = json.Unmarshal(b, &structured)
		if _, ok := structured.(map[string]any); !ok {
			structured = map[string]any{"result": structured}
		}
		return reply(map[string]any{"content": []any{map[string]any{"type": "text", "text": string(b)}},
			"structuredContent": structured, "isError": isErr})
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32601, "message": "method not found: " + m.Method}})
	return b
}

// Serve runs one session over a stream until it closes.
func (s *Session) Serve(r io.Reader, w io.Writer) {
	defer s.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var mu sync.Mutex
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if out := s.Handle(line); out != nil {
			mu.Lock()
			_, _ = w.Write(append(out, '\n'))
			mu.Unlock()
		}
	}
}

// Worker releases delayed effects whose window passed, until stop is closed.
func Worker(m *tx.Manager, every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.FlushDue()
		}
	}
}

// ListenUnix serves one session per connection on a Unix socket.
func ListenUnix(m *tx.Manager, path, version string) (net.Listener, error) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				NewSession(m, version).Serve(c, c)
			}()
		}
	}()
	return l, nil
}
