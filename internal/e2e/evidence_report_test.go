package e2e

import (
	"encoding/json"
	"testing"
)

// After an approved task is committed and undone, its full record is still one JSON
// document: the approval with what was shown, the before-state, and an intact audit chain.
func TestEvidenceReportAfterCommitAndUndo(t *testing.T) {
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
	rx, err := w.MakeManager().Get(x.ID) // another process, after the fact
	if err != nil {
		t.Fatal(err)
	}
	rep, err := w.Mgr.EvidenceReport(rx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	var doc struct {
		State       string           `json:"state"`
		Actions     []map[string]any `json:"actions"`
		Approvals   []map[string]any `json:"approvals"`
		UndoRecords []map[string]any `json:"undo_records"`
		Applied     []map[string]any `json:"applied_undo_records"`
		Events      []map[string]any `json:"events"`
		AuditChain  struct {
			Intact bool `json:"intact"`
		} `json:"audit_chain"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.State != "undone" || len(doc.Actions) != 1 || len(doc.Approvals) != 1 || len(doc.Applied) == 0 {
		t.Fatalf("report: state=%s actions=%d approvals=%d applied undo=%d", doc.State, len(doc.Actions), len(doc.Approvals), len(doc.Applied))
	}
	seen := map[string]bool{}
	for _, e := range doc.Events {
		seen[e["event"].(string)] = true
	}
	for _, want := range []string{"begin", "approve", "commit", "undo"} {
		if !seen[want] {
			t.Fatalf("event %s missing from %v", want, seen)
		}
	}
	if !doc.AuditChain.Intact {
		t.Fatal("audit chain reported broken")
	}
}
