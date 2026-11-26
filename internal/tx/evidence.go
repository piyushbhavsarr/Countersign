package tx

import (
	"encoding/json"

	"undolayer/internal/model"
)

// Approval evidence. A decision is only as good as what the reviewer was shown, so every
// approval and decline keeps a copy of exactly that: the action with its arguments and
// facts, or the whole preview of the task. The copy goes into the audit chain, which is
// append-only and tamper-evident, and it stays there after the task commits, is undone or
// fails. If something goes wrong later, the record shows what was asked, what the
// reviewer saw, who decided, and when.

const evidenceEvent = "approval_evidence"

// recordEvidence keeps what a reviewer decided on, exactly as it was shown to them.
func (m *Manager) recordEvidence(t *Tx, kind, subject, decision, by string, content any) {
	m.audit(evidenceEvent, map[string]any{
		"tx": t.ID, "task": t.Task, "requester": t.Requester,
		"kind": kind, "subject": subject, "decision": decision, "by": by,
		"content": content,
	})
}

// actionEvidence is the action as a reviewer sees it.
func actionEvidence(a *model.Action) map[string]any {
	return map[string]any{
		"id": a.ID, "connector": a.Connector, "operation": a.Operation, "args": a.Args,
		"effect": a.Effect, "facts": a.Facts, "decision": a.Decision, "reasons": a.Reasons,
	}
}

// Evidence returns the approval evidence of one transaction, oldest first.
func (m *Manager) Evidence(id string) ([]map[string]any, error) {
	var out []map[string]any
	err := m.Store.AuditLines(func(line []byte) error {
		var r map[string]any
		if json.Unmarshal(line, &r) != nil {
			return nil
		}
		if r["event"] == evidenceEvent && r["tx"] == id {
			delete(r, "prev")
			delete(r, "mac")
			out = append(out, r)
		}
		return nil
	})
	return out, err
}
