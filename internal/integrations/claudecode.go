// Package integrations: per-host conveniences. These are NOT the barrier - the barrier is
// `undolayer run`, which confines the agent so the gateway is its only path out. The
// Claude Code hook makes the host's own tools fail early with a useful message instead
// of failing inside the sandbox.
package integrations

import (
	"encoding/json"
	"io"
	"path"
)

var Defaults = map[string][]string{
	"deny":  {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "mcp__*"},
	"allow": {"Read", "Grep", "Glob", "LS", "TodoWrite", "Task", "mcp__undolayer__*"},
}

var replacement = map[string]string{"Bash": "shell_run", "Write": "fs_write", "Edit": "fs_write",
	"MultiEdit": "fs_write", "NotebookEdit": "fs_write", "WebFetch": "http_request"}

func match(tool string, pats []string) bool {
	for _, p := range pats {
		if ok, _ := path.Match(p, tool); ok {
			return true
		}
	}
	return false
}

func Decision(event map[string]any, cfg map[string][]string) map[string]any {
	deny, allow := Defaults["deny"], Defaults["allow"]
	if cfg["deny"] != nil {
		deny = cfg["deny"]
	}
	if cfg["allow"] != nil {
		allow = cfg["allow"]
	}
	tool, _ := event["tool_name"].(string)
	if match(tool, allow) || !match(tool, deny) {
		return nil
	}
	hint := "this tool is not routed through the undolayer gateway"
	if alt, ok := replacement[tool]; ok {
		hint = "use mcp__undolayer__" + alt + " instead, which stages the change in a transaction"
	}
	return map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse",
		"permissionDecision": "deny", "permissionDecisionReason": tool + " acts outside the undo layer; " + hint + "."}}
}

func Hook(in io.Reader, out io.Writer, cfg map[string][]string) error {
	var ev map[string]any
	if err := json.NewDecoder(in).Decode(&ev); err != nil {
		return err
	}
	if d := Decision(ev, cfg); d != nil {
		return json.NewEncoder(out).Encode(d)
	}
	return nil
}
