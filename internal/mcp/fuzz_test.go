package mcp

import (
	"path/filepath"
	"testing"

	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

// Whatever an agent sends, the gateway answers or ignores it; it never crashes.
func FuzzHandle(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"undolayer_begin","arguments":{"task":"x"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"undolayer_cancel","arguments":{"action_ids":[1,{"a":null}]}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"undolayer_commit"}}`,
		`{"id":null}`, `[]`, `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`, `not json`,
	} {
		f.Add([]byte(s))
	}
	m, err := tx.NewManager(filepath.Join(f.TempDir(), "state"), policy.Default())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		s := NewSession(m, "fuzz")
		_ = s.Handle(line)
		s.Close()
	})
}
