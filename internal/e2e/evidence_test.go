package e2e

import (
	"fmt"
	"testing"
)

// What a reviewer approved is kept after the task commits, and after it is undone.
func TestApprovalEvidenceOutlivesTheTask(t *testing.T) {
	w := world(t)
	x := w.Mgr.Begin("clear the orders")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders"})
	if err := x.Approve("alice", w.Mgr.ApprovalToken(x.ID, x.PreviewHash())); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Undo(""); err != nil {
		t.Fatal(err)
	}
	ev, err := w.Mgr.Evidence(x.ID)
	if err != nil || len(ev) != 1 {
		t.Fatalf("evidence: %v %d", err, len(ev))
	}
	e := ev[0]
	if e["decision"] != "approve" || e["by"] != "alice" || e["kind"] != "commit" || e["task"] != "clear the orders" {
		t.Fatalf("evidence record: %v", e)
	}
	content, _ := e["content"].(map[string]any)
	if content == nil || fmt.Sprint(content["changes"]) == "" || content["changes"] == nil {
		t.Fatalf("the approved preview was not kept: %v", e)
	}
	if ok, why := w.Mgr.Audit.Verify(); !ok {
		t.Fatalf("audit chain: %s", why)
	}
}

func TestDeclinedCommitKeepsWhatWasShown(t *testing.T) {
	w := world(t)
	x := w.Mgr.Begin("clear the orders")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders"})
	if err := w.Mgr.DeclineCommit(x, "bob"); err != nil {
		t.Fatal(err)
	}
	ev, _ := w.Mgr.Evidence(x.ID)
	if len(ev) != 1 || ev[0]["decision"] != "decline" || ev[0]["content"] == nil {
		t.Fatalf("decline evidence: %v", ev)
	}
}
