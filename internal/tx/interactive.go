package tx

import (
	"strings"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"undolayer/internal/model"
)

// Interactive approval: an action that needs approval can wait, inside the tool call,
// for a reviewer's decision on that single action. Approved, it proceeds through its
// lane at once (a held read is fetched, a message is pre-approved for commit); declined,
// it never runs; no decision before the timeout, it stays held for commit-time approval.
//
// A decision is an HMAC over (transaction, action, arguments) with the approver key the
// agent cannot read, written to tx/<id>.approvals.jsonl by the reviewer's process.

// ActionToken binds a decision to one action and its exact arguments.
func (m *Manager) ActionToken(txID string, a *model.Action, decision string) string {
	args, _ := json.Marshal(a.Args)
	h := hmac.New(sha256.New, m.approvalKey)
	h.Write([]byte(fmt.Sprintf("%s:%s:%s.%s:%s:%s", txID, a.ID, a.Connector, a.Operation, args, decision)))
	return hex.EncodeToString(h.Sum(nil))
}

// DecideAction records a reviewer's decision ("approve" or "decline") for one pending action.
func (m *Manager) DecideAction(t *Tx, actionID, approver, decision string) error {
	var a *model.Action
	for _, x := range t.Actions {
		if x.ID == actionID {
			a = x
		}
	}
	if a == nil {
		return fmt.Errorf("no action %s in %s", actionID, t.ID)
	}
	if decision != "approve" && decision != "decline" {
		return fmt.Errorf("decision must be approve or decline")
	}
	if err := m.addApproval(t.ID, map[string]any{"action_id": actionID, "decision": decision, "approver": approver,
		"token": m.ActionToken(t.ID, a, decision), "ts": model.Now()}); err != nil {
		return err
	}
	m.audit("action_decision", map[string]any{"tx": t.ID, "action_id": actionID, "decision": decision, "approver": approver})
	return nil
}

func (m *Manager) actionDecision(t *Tx, a *model.Action) (string, string) {
	if m.Review.Enabled() {
		o := t.actionOutcome(a)
		switch {
		case o.DeclinedBy != "":
			return "decline", o.DeclinedBy
		case o.Approved:
			return "approve", strings.Join(o.ApprovedBy, ", ")
		}
		return "", ""
	}
	for _, r := range m.approvals(t.ID) {
		if r["action_id"] != a.ID {
			continue
		}
		d, _ := r["decision"].(string)
		tok, _ := r["token"].(string)
		if hmac.Equal([]byte(tok), []byte(m.ActionToken(t.ID, a, d))) {
			who, _ := r["approver"].(string)
			return d, who
		}
	}
	return "", ""
}

// Pending lists actions currently waiting for an interactive decision.
type PendingAction struct {
	Tx   string `json:"tx"`
	Task string `json:"task"`
	// Kind is "action" (one action, decided with --action) or "commit" (the whole preview).
	Kind        string             `json:"kind"`
	PreviewHash string             `json:"preview_hash,omitempty"`
	Totals      map[string]float64 `json:"totals,omitempty"`
	Action      *model.Action      `json:"action,omitempty"`
	Since       float64            `json:"since"`
	Reasons     []string           `json:"reasons"`
	Facts       map[string]any     `json:"facts"`
	// Needs says who can decide it (with reviewers configured); Missing what is still needed.
	Needs   []string `json:"needs,omitempty"`
	Missing []string `json:"missing,omitempty"`
}

func (m *Manager) Pending() []PendingAction {
	var out []PendingAction
	for _, s := range m.List() {
		if s.State != string(model.Open) {
			continue
		}
		t, err := m.Get(s.ID)
		if err != nil {
			continue
		}
		for _, a := range t.Actions {
			if a.Facts["awaiting_decision"] == true {
				if d, _ := m.actionDecision(t, a); d == "" {
					p := PendingAction{Tx: t.ID, Task: t.Task, Kind: "action", Action: a, Since: a.TS, Reasons: a.Reasons, Facts: a.Facts}
					if m.Review.Enabled() {
						rules := m.Review.Requirements([]*model.Action{a}, nil)
						p.Needs, p.Missing = m.Review.Describe(rules), t.actionOutcome(a).Missing
					}
					out = append(out, p)
				}
			}
		}
		if c := t.AwaitingCommit; c != nil && !t.approved(c.Hash) {
			if d, _ := t.commitDecision(c.Hash, c.Since); d == "" {
				p := PendingAction{Tx: t.ID, Task: t.Task, Kind: "commit", PreviewHash: c.Hash, Totals: c.Totals,
					Since: c.Since, Reasons: c.Reasons}
				if m.Review.Enabled() {
					p.Needs, p.Missing = m.Review.Describe(t.commitRules()), t.commitOutcome(c.Hash, 0).Missing
				}
				out = append(out, p)
			}
		}
	}
	return out
}

// CommitRequest is a commit waiting for a reviewer's decision on its exact preview.
type CommitRequest struct {
	Hash    string             `json:"preview_hash"`
	Reasons []string           `json:"reasons"`
	Totals  map[string]float64 `json:"totals"`
	Since   float64            `json:"since"`
}

func (m *Manager) commitToken(txID, hash, decision string) string {
	if decision == "approve" {
		return m.ApprovalToken(txID, hash)
	}
	h := hmac.New(sha256.New, m.approvalKey)
	h.Write([]byte(txID + ":" + hash + ":" + decision))
	return hex.EncodeToString(h.Sum(nil))
}

// DeclineCommit records a reviewer's refusal of the transaction's current preview.
func (m *Manager) DeclineCommit(t *Tx, approver string) error {
	h := t.PreviewHash()
	if err := m.addApproval(t.ID, map[string]any{"commit_decision": "decline", "preview_hash": h, "approver": approver,
		"token": m.commitToken(t.ID, h, "decline"), "ts": model.Now()}); err != nil {
		return err
	}
	m.audit("commit_declined", map[string]any{"tx": t.ID, "approver": approver, "preview_hash": h})
	return nil
}

// commitDecision returns the first valid decision on this preview made at or after since.
func (t *Tx) commitDecision(hash string, since float64) (string, string) {
	m, txID := t.Mgr, t.ID
	if m.Review.Enabled() {
		o := t.commitOutcome(hash, since)
		switch {
		case o.DeclinedBy != "":
			return "decline", o.DeclinedBy
		case o.Approved:
			return "approve", strings.Join(o.ApprovedBy, ", ")
		}
		return "", ""
	}
	for _, r := range m.approvals(txID) {
		if ts, _ := model.Num(r["ts"]); r["preview_hash"] != hash || ts < since {
			continue
		}
		tok, _ := r["token"].(string)
		who, _ := r["approver"].(string)
		d := "approve"
		if r["commit_decision"] == "decline" {
			d = "decline"
		}
		if hmac.Equal([]byte(tok), []byte(m.commitToken(txID, hash, d))) {
			return d, who
		}
	}
	return "", ""
}

// awaitCommitDecision blocks (up to the manager's timeout) for a decision on the whole
// preview. Called with the operation lock held, so the preview cannot change meanwhile.
func (t *Tx) awaitCommitDecision(hash string, reasons []string) (string, string) {
	if t.Mgr.ApprovalWait <= 0 {
		return "", ""
	}
	req := &CommitRequest{Hash: hash, Reasons: reasons, Totals: t.Totals(), Since: model.Now()}
	t.AwaitingCommit = req
	t.Mgr.Journal(t)
	t.Mgr.audit("commit_approval_requested", map[string]any{"tx": t.ID, "preview_hash": hash, "reasons": reasons})
	if t.Mgr.Notify != nil {
		p := PendingAction{Tx: t.ID, Task: t.Task, Kind: "commit", PreviewHash: hash, Totals: req.Totals, Since: req.Since, Reasons: reasons}
		if t.Mgr.Review.Enabled() {
			p.Needs = t.Mgr.Review.Describe(t.commitRules())
		}
		go t.Mgr.Notify(t.redactedRequest(p))
	}
	defer func() { t.AwaitingCommit = nil; t.Mgr.Journal(t) }()
	deadline := time.Now().Add(t.Mgr.ApprovalWait)
	for time.Now().Before(deadline) {
		if d, who := t.commitDecision(hash, req.Since); d != "" {
			return d, who
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", ""
}

// awaitDecision blocks (up to the manager's timeout) for a reviewer's decision.
func (t *Tx) awaitDecision(a *model.Action) (string, string) {
	if t.Mgr.ApprovalWait <= 0 {
		return "", ""
	}
	a.Facts["awaiting_decision"] = true
	t.Mgr.Journal(t) // make the request visible to reviewers
	t.Mgr.audit("approval_requested", map[string]any{"tx": t.ID, "action": a})
	if t.Mgr.OnApprovalRequest != nil {
		go t.Mgr.OnApprovalRequest(t.ID, a)
	}
	if t.Mgr.Notify != nil {
		p := PendingAction{Tx: t.ID, Task: t.Task, Kind: "action", Action: a, Since: a.TS, Reasons: a.Reasons, Facts: a.Facts}
		if t.Mgr.Review.Enabled() {
			p.Needs = t.Mgr.Review.Describe(t.Mgr.Review.Requirements([]*model.Action{a}, nil))
		}
		go t.Mgr.Notify(t.redactedRequest(p))
	}
	deadline := time.Now().Add(t.Mgr.ApprovalWait)
	for time.Now().Before(deadline) {
		if d, who := t.Mgr.actionDecision(t, a); d != "" {
			delete(a.Facts, "awaiting_decision")
			return d, who
		}
		time.Sleep(100 * time.Millisecond)
	}
	delete(a.Facts, "awaiting_decision")
	return "", ""
}

// redactedRequest removes secret values before a request leaves the runtime.
func (t *Tx) redactedRequest(p PendingAction) PendingAction {
	b, _ := json.Marshal(p)
	var v any
	_ = json.Unmarshal(b, &v)
	r, _ := t.Sensitive().Redact(v)
	rb, _ := json.Marshal(r)
	var out PendingAction
	if json.Unmarshal(rb, &out) != nil {
		return PendingAction{Tx: p.Tx, Kind: p.Kind, Reasons: []string{"(details withheld: could not redact)"}}
	}
	return out
}
