// Package mcpproxy puts other MCP servers behind the gateway. Their tools become the
// gateway's tools (<server>_<tool>), and every call goes through the same transaction,
// policy, approval, vault and audit as any other action: the agent never talks to the
// server directly.
//
// Lanes. A tool's own annotations are hints from the server, not facts, so by default
// every tool that is not declared otherwise is irreversible: it is held, and runs on
// commit after a person approves it. The operator declares lanes per tool (read, deferrable,
// irreversible, or compensable with the tool call that undoes it, filled in from the
// response), or chooses to trust a server's readOnlyHint.
//
// Pinning. Each tool's definition (description, input schema, annotations) is pinned the
// first time the gateway sees the server. A tool whose definition changes later (a server
// that rewrites a tool to steer agents, a "rug pull") or that appears later is refused until
// an operator reviews and pins it again with `undolayer mcp pin <server>`.
//
// URLs in arguments are classified like http.request destinations, so a fetch-style tool
// cannot be pointed at a cloud metadata service or a private network.
package mcpproxy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"undolayer/internal/model"
	"undolayer/internal/netguard"
	"undolayer/internal/registry"
	"undolayer/internal/tx"
)

// ToolRule is the operator's declaration for one tool.
type ToolRule struct {
	Lane string         `toml:"lane"` // read | compensable | deferrable | irreversible
	Undo map[string]any `toml:"undo"` // compensable: {tool = "...", args = {...}} with $args / $response
	// Destinations: argument names that address people or places (checked like messages).
	Destinations []string `toml:"destinations"`
}

// Server configures one downstream MCP server.
type Server struct {
	Name             string              `toml:"name"`
	Command          []string            `toml:"command"` // stdio
	Env              map[string]string   `toml:"env"`
	URL              string              `toml:"url"`     // streamable HTTP
	Headers          map[string]string   `toml:"headers"` // e.g. Authorization (the agent never sees them)
	TrustAnnotations bool                `toml:"trust_annotations"`
	Tools            map[string]ToolRule `toml:"tools"`
	// AllowPrivateHosts: URL arguments that may point at these hosts on private networks.
	AllowPrivateHosts []string `toml:"allow_private_hosts"`
	Timeout           string   `toml:"timeout"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func (d toolDef) hash() string {
	b, _ := json.Marshal(map[string]any{"description": d.Description, "inputSchema": d.InputSchema, "annotations": d.Annotations})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Connector is one downstream server.
type Connector struct {
	tx.Base
	S        Server
	StateDir string

	mu      sync.Mutex
	client  client
	tools   map[string]toolDef
	pins    map[string]string
	loadErr error
	timeout time.Duration
}

// New connects lazily: the server is started (or reached) on first use.
func New(s Server, stateDir string) (*Connector, error) {
	if s.Name == "" || strings.ContainsAny(s.Name, "_ /") {
		return nil, fmt.Errorf("mcp server name %q: use letters, digits and dashes", s.Name)
	}
	if (len(s.Command) == 0) == (s.URL == "") {
		return nil, fmt.Errorf("mcp server %s: give either command or url", s.Name)
	}
	for tool, r := range s.Tools {
		switch r.Lane {
		case "", "read", "deferrable", "irreversible":
		case "compensable":
			if fmt.Sprint(r.Undo["tool"]) == "" || r.Undo["tool"] == nil {
				return nil, fmt.Errorf("mcp server %s tool %s: a compensable tool needs undo = { tool = ..., args = ... }", s.Name, tool)
			}
		default:
			return nil, fmt.Errorf("mcp server %s tool %s: unknown lane %q", s.Name, tool, r.Lane)
		}
	}
	c := &Connector{Base: tx.Base{ConnName: s.Name}, S: s, StateDir: stateDir, timeout: 60 * time.Second}
	if s.Timeout != "" {
		d, err := time.ParseDuration(s.Timeout)
		if err != nil {
			return nil, fmt.Errorf("mcp server %s timeout: %v", s.Name, err)
		}
		c.timeout = d
	}
	return c, nil
}

func (c *Connector) pinFile() string { return filepath.Join(c.StateDir, "mcp-pins", c.S.Name+".json") }

// load starts the server, lists its tools and pins them on first sight.
func (c *Connector) load() error {
	if c.tools != nil || c.loadErr != nil {
		return c.loadErr
	}
	if err := c.connect(); err != nil {
		c.loadErr = err
		return err
	}
	defs, err := c.list()
	if err != nil {
		c.loadErr = err
		return err
	}
	c.tools = map[string]toolDef{}
	for _, d := range defs {
		c.tools[d.Name] = d
	}
	c.pins = map[string]string{}
	if b, err := os.ReadFile(c.pinFile()); err == nil {
		_ = json.Unmarshal(b, &c.pins)
	} else if os.IsNotExist(err) { // trust on first use
		for n, d := range c.tools {
			c.pins[n] = d.hash()
		}
		if err := c.savePins(); err != nil {
			c.loadErr = err
			return err
		}
	}
	return nil
}

func (c *Connector) savePins() error {
	if err := os.MkdirAll(filepath.Dir(c.pinFile()), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c.pins, "", "  ")
	tmp := c.pinFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.pinFile())
}

// Pin accepts the server's current tool definitions (after an operator reviewed them).
func (c *Connector) Pin() ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tools, c.loadErr = nil, nil
	if err := c.load(); err != nil {
		return nil, err
	}
	var changed []string
	for n, d := range c.tools {
		if c.pins[n] != d.hash() {
			changed = append(changed, n)
		}
		c.pins[n] = d.hash()
	}
	sort.Strings(changed)
	return changed, c.savePins()
}

func (c *Connector) Egress() bool { return true }

func (c *Connector) Operations() map[string]tx.OpSchema {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.load(); err != nil {
		return map[string]tx.OpSchema{}
	}
	out := map[string]tx.OpSchema{}
	for n, d := range c.tools {
		props, _ := d.InputSchema["properties"].(map[string]any)
		var req []string
		if l, ok := d.InputSchema["required"].([]any); ok {
			for _, r := range l {
				req = append(req, fmt.Sprint(r))
			}
		}
		desc := d.Description
		if c.pins[n] != d.hash() {
			desc = "[changed since pinned: refused until reviewed] " + desc
		}
		out[n] = tx.OpSchema{Description: desc, Properties: props, Required: req}
	}
	return out
}

func (c *Connector) lane(name string, d toolDef) model.Effect {
	switch c.S.Tools[name].Lane {
	case "read":
		return model.Read
	case "compensable":
		return model.Compensable
	case "deferrable":
		return model.Deferrable
	case "irreversible":
		return model.Irreversible
	}
	if c.S.TrustAnnotations && d.Annotations["readOnlyHint"] == true {
		return model.Read
	}
	return model.Irreversible
}

func (c *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	c.mu.Lock()
	err := c.load()
	d, ok := c.tools[op]
	pinned, known := c.pins[op]
	c.mu.Unlock()
	if err != nil {
		return "", nil, err
	}
	if !ok {
		return "", nil, fmt.Errorf("%s has no tool %s", c.S.Name, op)
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.Sum256([]byte(op + "(" + strings.Join(keys, ",") + ")"))
	f := model.Facts{"mcp_server": c.S.Name, "tool": op, "annotations": d.Annotations,
		"tool_pinned": known, "tool_changed": known && pinned != d.hash(), "request_shape": hex.EncodeToString(h[:8])}
	// URLs anywhere in the arguments: where would this tool be sent?
	worst, allowed, n := "", true, 0
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case string:
			if i := strings.Index(x, "://"); i > 0 && i < 10 {
				uf := netguard.Inspect("GET", x, nil, c.S.AllowPrivateHosts)
				n++
				if worst == "" {
					worst = uf.Network
				} else {
					worst = netguard.Worst(worst, uf.Network)
				}
				if uf.Network != netguard.Public && uf.Network != netguard.Unresolved && !uf.PrivateAllowed {
					allowed = false
				}
			}
		}
	}
	walk(args)
	if n > 0 {
		f["url_args_network"], f["url_args_private_allowed"] = worst, allowed
	}
	if r := c.S.Tools[op]; len(r.Destinations) > 0 {
		var dests []string
		for _, k := range r.Destinations {
			if s, ok := args[k].(string); ok {
				dests = append(dests, s)
			}
		}
		f["destinations"], f["address_fields"] = dests, r.Destinations
	}
	return c.lane(op, d), f, nil
}

func (c *Connector) Stage(t *tx.Tx, a *model.Action) (any, error) {
	res, err := c.call(a.Operation, a.Args)
	if err != nil {
		return nil, err
	}
	if a.Effect == model.Compensable {
		return &tx.Staged{Result: res, Comp: &tx.Compensation{Kind: "compensable",
			Record: compRecord{Tool: a.Operation, Args: a.Args, Response: res}}}, nil
	}
	return res, nil
}

func (c *Connector) RunDeferred(t *tx.Tx, a *model.Action) (any, error) {
	res, err := c.call(a.Operation, a.Args)
	if err != nil {
		return nil, err
	}
	if c.S.Tools[a.Operation].Lane == "compensable" {
		return &tx.Staged{Result: res, Comp: &tx.Compensation{Kind: "compensable",
			Record: compRecord{Tool: a.Operation, Args: a.Args, Response: res}}}, nil
	}
	return res, nil
}

type compRecord struct {
	Tool     string         `json:"tool"`
	Args     map[string]any `json:"args"`
	Response any            `json:"response"`
}

// Compensate calls the tool the operator declared as the way back, filled in from the
// original call's arguments and response.
func (c *Connector) Compensate(raw json.RawMessage) error {
	var r compRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	undo := c.S.Tools[r.Tool].Undo
	if undo == nil {
		return &model.NotUndoable{Msg: c.S.Name + "." + r.Tool + " has no undo declared"}
	}
	ctx := map[string]any{"args": r.Args, "response": r.Response}
	argsAny, err := registry.Render(undo["args"], ctx)
	if err != nil {
		return err
	}
	args, _ := argsAny.(map[string]any)
	_, err = c.call(fmt.Sprint(undo["tool"]), args)
	return err
}

// Contained: a tool call reaches the server, outside this process.
func (c *Connector) Contained(string) bool { return false }

func (c *Connector) closeClient() {
	if c.client != nil {
		c.client.close()
		c.client = nil
	}
}

// Close stops the server process.
func (c *Connector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeClient()
}

// call runs one tool. A result marked isError is an error.
func (c *Connector) call(tool string, args map[string]any) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.load(); err != nil {
		return nil, err
	}
	if d, ok := c.tools[tool]; ok && c.pins[tool] != d.hash() {
		return nil, fmt.Errorf("%s.%s changed since it was pinned; review it and run: undolayer mcp pin %s", c.S.Name, tool, c.S.Name)
	}
	if args == nil {
		args = map[string]any{}
	}
	raw, err := c.rpc("tools/call", map[string]any{"name": tool, "arguments": args})
	if err != nil {
		c.closeClient() // a broken connection is restarted on the next call
		return nil, err
	}
	var res struct {
		Content           []map[string]any `json:"content"`
		StructuredContent any              `json:"structuredContent"`
		IsError           bool             `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	out := map[string]any{"content": res.Content}
	if res.StructuredContent != nil {
		out["structured"] = res.StructuredContent
	}
	if res.IsError {
		b, _ := json.Marshal(res.Content)
		return nil, fmt.Errorf("%s.%s: %s", c.S.Name, tool, b)
	}
	return out, nil
}

// ---------------------------------------------------------------- JSON-RPC

type client interface {
	request(method string, params any, timeout time.Duration) (json.RawMessage, error)
	notify(method string, params any) error
	close()
}

func (c *Connector) connect() error {
	if c.client != nil {
		return nil
	}
	var cl client
	var err error
	if c.S.URL != "" {
		cl = &httpClient{url: c.S.URL, headers: c.S.Headers}
	} else if cl, err = startStdio(c.S.Command, c.S.Env); err != nil {
		return fmt.Errorf("starting mcp server %s: %v", c.S.Name, err)
	}
	if _, err := cl.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "countersign", "version": "1"}}, c.timeout); err != nil {
		cl.close()
		return fmt.Errorf("mcp server %s: initialize: %v", c.S.Name, err)
	}
	_ = cl.notify("notifications/initialized", map[string]any{})
	c.client = cl
	return nil
}

func (c *Connector) list() ([]toolDef, error) {
	var out []toolDef
	cursor := ""
	for i := 0; i < 100; i++ {
		p := map[string]any{}
		if cursor != "" {
			p["cursor"] = cursor
		}
		raw, err := c.client.request("tools/list", p, c.timeout)
		if err != nil {
			return nil, err
		}
		var r struct {
			Tools      []toolDef `json:"tools"`
			NextCursor string    `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		out = append(out, r.Tools...)
		if r.NextCursor == "" {
			return out, nil
		}
		cursor = r.NextCursor
	}
	return nil, errors.New("tools/list did not end")
}

func (c *Connector) rpc(method string, params any) (json.RawMessage, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c.client.request(method, params, c.timeout)
}

type rpcResp struct {
	ID     any             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Method string `json:"method"`
}

func (r *rpcResp) value() (json.RawMessage, error) {
	if r.Error != nil {
		return nil, fmt.Errorf("mcp error %d: %s", r.Error.Code, r.Error.Message)
	}
	return r.Result, nil
}

// stdio: newline-delimited JSON-RPC over the process's stdin and stdout.
type stdioClient struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Reader
	n    int
	dead bool
}

func startStdio(command []string, env map[string]string) (*stdioClient, error) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &stdioClient{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20)}, nil
}

func (s *stdioClient) write(v any) error {
	b, _ := json.Marshal(v)
	_, err := s.in.Write(append(b, '\n'))
	return err
}

func (s *stdioClient) notify(method string, params any) error {
	return s.write(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

func (s *stdioClient) request(method string, params any, timeout time.Duration) (json.RawMessage, error) {
	if s.dead {
		return nil, errors.New("server exited")
	}
	s.n++
	id := s.n
	if err := s.write(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		s.dead = true
		return nil, err
	}
	type res struct {
		r   *rpcResp
		err error
	}
	ch := make(chan res, 1)
	go func() {
		for {
			line, err := s.out.ReadBytes('\n')
			if err != nil {
				ch <- res{nil, err}
				return
			}
			var r rpcResp
			if json.Unmarshal(line, &r) != nil || r.Method != "" { // server requests and notifications are ignored
				continue
			}
			if fmt.Sprint(r.ID) == fmt.Sprint(id) {
				ch <- res{&r, nil}
				return
			}
		}
	}()
	select {
	case got := <-ch:
		if got.err != nil {
			s.dead = true
			return nil, got.err
		}
		return got.r.value()
	case <-time.After(timeout):
		s.dead = true // the reader may still be blocked: this connection is not reused
		return nil, fmt.Errorf("%s timed out after %s", method, timeout)
	}
}

func (s *stdioClient) close() {
	if s == nil || s.cmd == nil {
		return
	}
	_ = s.in.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.cmd.Wait()
	s.dead = true
}

// streamable HTTP: each request is a POST; the answer is JSON or an event stream.
type httpClient struct {
	url     string
	headers map[string]string
	session string
	n       int
}

func (h *httpClient) post(body any, timeout time.Duration) (*http.Response, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", h.url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if h.session != "" {
		req.Header.Set("Mcp-Session-Id", h.session)
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return (&http.Client{Timeout: timeout}).Do(req)
}

func (h *httpClient) notify(method string, params any) error {
	resp, err := h.post(map[string]any{"jsonrpc": "2.0", "method": method, "params": params}, 30*time.Second)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func (h *httpClient) request(method string, params any, timeout time.Duration) (json.RawMessage, error) {
	h.n++
	id := h.n
	resp, err := h.post(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}, timeout)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
		h.session = s
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64<<10), 64<<20)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			var r rpcResp
			if json.Unmarshal([]byte(strings.TrimSpace(line[5:])), &r) == nil && r.Method == "" && fmt.Sprint(r.ID) == fmt.Sprint(id) {
				return r.value()
			}
		}
		return nil, errors.New("the event stream ended without an answer")
	}
	var r rpcResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&r); err != nil {
		return nil, err
	}
	return r.value()
}

func (h *httpClient) close() {}
