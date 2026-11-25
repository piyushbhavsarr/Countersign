package kube

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

// Values from the agent are names, never kubectl options. A fake kubectl records its
// arguments, so this runs without a cluster.
func TestAgentValuesNeverBecomeKubectlFlags(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	fake := filepath.Join(dir, "kubectl")
	_ = os.WriteFile(fake, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> "+log+"; done\necho '{}'\n"), 0o755)
	m, _ := tx.NewManager(filepath.Join(dir, "state"), policy.Default())
	c := New()
	c.Kubectl, c.Context = fake, "test"
	m.Register(c)
	for _, args := range []map[string]any{
		{"kind": "deployment", "name": "--kubeconfig=/tmp/evil"},
		{"kind": "--server=https://attacker", "name": "x"},
		{"kind": "pod", "name": "x", "namespace": "--token=stolen"},
		{"kind": "pod", "selector": "app=x --server=https://attacker"},
	} {
		x := m.Begin("look")
		_, _ = x.Call("kube", "get", args)
		_, _ = x.Call("kube", "delete", args)
		_, _ = x.Rollback("t")
	}
	b, _ := os.ReadFile(log)
	for _, line := range strings.Split(string(b), "\n") {
		for _, bad := range []string{"--kubeconfig=/tmp/evil", "--server=https://attacker", "--token=stolen"} {
			if line == bad {
				t.Fatalf("an agent value reached kubectl as an option: %q", line)
			}
		}
	}
}
