package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The gateway runs git outside the sandbox with the real credentials. Nothing the agent
// puts in its copy of the repository (hooks, config, remotes) may run or redirect there.
func TestTheAgentsRepoConfigCannotRunCodeInTheGateway(t *testing.T) {
	w := world(t)
	marker := filepath.Join(t.TempDir(), "PWNED")
	x := w.Mgr.Begin("fix the app and push it")
	call(t, x, "fs", "write", map[string]any{"path": "app.py", "content": "print('v1.1')\n"})
	// a hook, a fsmonitor hook and a pager, all pointing at code that leaves a marker
	cmd := fmt.Sprintf(`printf '#!/bin/sh\ntouch %s\n' > .git/hooks/pre-push && chmod +x .git/hooks/pre-push && `+
		`cp .git/hooks/pre-push .git/hooks/reference-transaction && `+
		`git config core.fsmonitor .git/hooks/pre-push && git config core.sshCommand .git/hooks/pre-push && `+
		`git commit -q -am fix`, marker)
	call(t, x, "shell", "run", map[string]any{"command": cmd})
	_, _ = x.Call("git", "push", map[string]any{"branch": "main"})
	_, _ = x.Commit()
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("code from the agent's repository ran in the gateway (outside the sandbox)")
	}
}

func TestTheAgentCannotRedirectWhereAPushGoes(t *testing.T) {
	w := world(t)
	elsewhere := filepath.Join(t.TempDir(), "attacker.git")
	x := w.Mgr.Begin("push the fix")
	call(t, x, "fs", "write", map[string]any{"path": "app.py", "content": "print('v1.1')\n"})
	call(t, x, "shell", "run", map[string]any{"command": "git init -q --bare " + elsewhere + " 2>/dev/null; " +
		"git remote set-url origin " + elsewhere + " && git commit -q -am fix"})
	_, _ = x.Call("git", "push", map[string]any{"branch": "main"})
	_, _ = x.Commit()
	if out, _ := exec.Command("git", "-C", elsewhere, "for-each-ref").Output(); len(out) > 0 {
		t.Fatalf("the agent redirected the push to a remote of its choosing: %s", out)
	}
	for _, branch := range []string{"--upload-pack=touch /tmp/x", "-f", "main..x", "refs/../../x"} {
		y := w.Mgr.Begin("push")
		if _, err := y.Call("git", "push", map[string]any{"branch": branch}); err == nil {
			t.Fatalf("branch name %q was accepted", branch)
		}
		_, _ = y.Rollback("t")
	}
}
