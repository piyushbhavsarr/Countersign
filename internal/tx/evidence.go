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

// EvidenceReport is everything known about one task, as a single document: what was
// asked, every action with its facts and decision, what each reviewer approved or declined
// and exactly what they were shown, the recorded before-state that undo restores, the
// outbox, the steps that ran, the task's audit events, and whether the audit chain is
// intact. It is built from what the runtime keeps anyway, so it is available whatever
// happened to the task: committed, undone, declined or failed.
func (m *Manager) EvidenceReport(t *Tx) (map[string]any, error) {
	approvals, err := m.Evidence(t.ID)
	if err != nil {
		return nil, err
	}
	events := []map[string]any{}
	err = m.Store.AuditLines(func(line []byte) error {
		var r map[string]any
		if json.Unmarshal(line, &r) == nil && r["tx"] == t.ID && r["event"] != evidenceEvent {
			delete(r, "prev")
			delete(r, "mac")
			events = append(events, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	intact, detail := m.Audit.Verify()
	return map[string]any{
		"tx": t.ID, "task": t.Task, "requester": t.Requester, "state": t.State, "created": t.Created,
		"actions":      t.Actions,
		"approvals":    approvals,
		"undo_records": t.UndoRecords,
		// before-state already restored by an undo, kept on record
		"applied_undo_records": t.AppliedUndo,
		"compensations":        t.Compensations,
		"outbox":               t.Outbox,
		"steps":                t.Steps,
		"events":               events,
		"audit_chain":          map[string]any{"intact": intact, "detail": detail},
		"exported_at":          model.Now(),
	}, nil
}
