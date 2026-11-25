package cloud

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

func TestAgentValuesNeverBecomeAWSCLIOptions(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	fake := filepath.Join(dir, "aws")
	_ = os.WriteFile(fake, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> "+log+"; done\necho '{}'\n"), 0o755)
	m, _ := tx.NewManager(filepath.Join(dir, "state"), policy.Default())
	c := New(filepath.Join(dir, "state"))
	c.AWSBin, c.ViewProfile, c.ReadProfile = fake, "view", "read"
	m.Register(c)
	for _, args := range []map[string]any{
		{"service": "--endpoint-url=http://127.0.0.1:9", "action": "ListBuckets"},
		{"service": "s3", "action": "--endpoint-url=http://127.0.0.1:9"},
		{"service": "s3 --debug", "action": "ListBuckets"},
	} {
		x := m.Begin("look")
		_, _ = x.Call("cloud", "aws", args)
		_, _ = x.Rollback("t")
	}
	b, _ := os.ReadFile(log)
	if strings.Contains(string(b), "--endpoint-url") || strings.Contains(string(b), "--debug") {
		t.Fatalf("an agent value reached the AWS CLI as an option:\n%s", b)
	}
}

// terraform plan runs code from the configuration (external data sources, providers): it
// must never run what the agent wrote and nobody has accepted.
func TestTerraformRunsOnlyCommittedCode(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "ws")
	_ = os.MkdirAll(filepath.Join(root, "infra"), 0o755)
	m, _ := tx.NewManager(filepath.Join(dir, "state"), policy.Default())
	c := New(filepath.Join(dir, "state"))
	c.WorkspaceRoot = root
	c.Terraform = "/bin/echo" // never really reached in this test
	m.Register(c)
	for _, d := range []string{"/tmp", "../", "infra/../../", filepath.Join(dir, "state")} {
		x := m.Begin("plan")
		if _, err := x.Call("cloud", "terraform_plan", map[string]any{"dir": d}); err == nil {
			t.Fatalf("terraform_plan ran in %q, outside the real workspace", d)
		}
		_, _ = x.Rollback("t")
	}
}
