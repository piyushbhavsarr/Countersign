package e2e

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"undolayer/internal/model"
	"undolayer/internal/review"
	"undolayer/internal/tx"
)

// reviewers sets up alice (engineering) and bob (finance) with their own SSH keys, and the
// requester "dev". Their private keys are outside the runtime's state directory.
func reviewers(t *testing.T, m *tx.Manager, rules []map[string]any) map[string]string {
	t.Helper()
	keys := map[string]string{}
	revs := map[string]map[string]any{}
	for name, role := range map[string]string{"alice": "engineering", "bob": "finance"} {
		p := filepath.Join(t.TempDir(), name)
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", p).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		pub, _ := os.ReadFile(p + ".pub")
		keys[name] = p
		revs[name] = map[string]any{"key": strings.TrimSpace(string(pub)), "roles": []any{role}, "users": []any{name}}
	}
	cfg, err := review.FromMap(revs, rules, false)
	if err != nil {
		t.Fatal(err)
	}
	m.Review, m.Requester = cfg, "dev"
	return keys
}

func TestWithReviewersTheStateDirectoryCannotApprove(t *testing.T) {
	w := world(t)
	reviewers(t, w.Mgr, nil)
	x := w.Mgr.Begin("clear the orders")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders"})

	// the agent read everything in the state directory, including approver.key, and
	// writes an approval exactly as single-user mode would accept it
	if err := x.Approve("agent", w.Mgr.ApprovalToken(x.ID, x.PreviewHash())); err != nil {
		t.Fatal(err)
	}
	var ar *model.ApprovalRequired
	if _, err := x.Commit(); !errors.As(err, &ar) {
		t.Fatalf("an approval made with the state directory's key was accepted: %v", err)
	}
	if w.Count("orders", "") == 0 {
		t.Fatal("orders deleted")
	}
}

func TestSignedApprovalCommits(t *testing.T) {
	w := world(t)
	keys := reviewers(t, w.Mgr, nil)
	x := w.Mgr.Begin("clear the orders")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders"})
	x.Preview()                 // the agent shows the change and asks for approval
	reviewer := w.MakeManager() // the reviewer's own process
	reviewer.Review, reviewer.Requester = w.Mgr.Review, "someone-else"
	rx, _ := reviewer.Get(x.ID)
	if _, err := reviewer.SignDecision(rx, "", "approve", "alice", keys["bob"]); err == nil {
		t.Fatal("bob's key signed as alice")
	}
	o, err := reviewer.SignDecision(rx, "", "approve", "alice", keys["alice"])
	if err != nil || !o.Approved {
		t.Fatalf("alice's approval: %v %+v", err, o)
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if w.Count("orders", "") != 0 {
		t.Fatal("not committed")
	}
}

func TestRulesNeedTheRightPeopleAndNotTheRequester(t *testing.T) {
	w := world(t)
	keys := reviewers(t, w.Mgr, []map[string]any{
		{"id": "mass-change", "connector": "commit", "when": map[string]any{"max_table_fraction_changed": map[string]any{"gt": 0.5}},
			"roles": []any{"finance"}},
	})
	w.Mgr.Requester = "bob" // bob asked for this task
	x := w.Mgr.Begin("clear the orders")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders"})

	o, err := w.Mgr.SignDecision(x, "", "approve", "alice", keys["alice"])
	if err != nil || o.Approved {
		t.Fatalf("engineering approved what needs finance: %+v %v", o, err)
	}
	o, _ = w.Mgr.SignDecision(x, "", "approve", "bob", keys["bob"])
	if o.Approved || !strings.Contains(strings.Join(o.Invalid, " "), "asked for this task") {
		t.Fatalf("the requester approved their own task: %+v", o)
	}
	var ar *model.ApprovalRequired
	if _, err := x.Commit(); !errors.As(err, &ar) {
		t.Fatalf("committed without a valid approval: %v", err)
	}
}

func TestSignedDecisionDuringTheTask(t *testing.T) {
	w := world(t)
	keys := reviewers(t, w.Mgr, nil)
	w.Mgr.ApprovalWait = 5 * time.Second
	x := w.Mgr.Begin("clear the orders")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders"})
	reviewer := w.MakeManager()
	reviewer.Review, reviewer.Requester = w.Mgr.Review, "someone-else"
	go func() {
		for i := 0; i < 100; i++ {
			for _, p := range reviewer.Pending() {
				if p.Kind == "commit" && len(p.Needs) > 0 {
					rx, _ := reviewer.Get(p.Tx)
					_, _ = reviewer.SignDecision(rx, "", "decline", "bob", keys["bob"])
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	if _, err := x.Commit(); err == nil || !strings.Contains(err.Error(), "declined by bob") {
		t.Fatalf("a signed decline did not stop the commit: %v", err)
	}
	if w.Count("orders", "") == 0 {
		t.Fatal("declined change landed")
	}
}
