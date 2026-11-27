package tx

import (
	"encoding/json"
	"fmt"

	"undolayer/internal/model"
	"undolayer/internal/review"
)

// Signed approvals (reviewers configured): a decision is a statement signed with the
// reviewer's own SSH key; the runtime only verifies. See package review.

func (m *Manager) signedDecisions(txID string) []review.Signed {
	var out []review.Signed
	for _, r := range m.approvals(txID) {
		if _, ok := r["statement"]; !ok {
			continue // single-user HMAC records do not count when reviewers are configured
		}
		b, _ := json.Marshal(r)
		var s review.Signed
		if json.Unmarshal(b, &s) == nil {
			out = append(out, s)
		}
	}
	return out
}

func (t *Tx) actionOutcome(a *model.Action) review.Outcome {
	rules := t.Mgr.Review.Requirements([]*model.Action{a}, nil)
	return t.Mgr.Review.Decide(t.ID, review.ActionSubject(a), t.Requester, rules, t.Mgr.signedDecisions(t.ID), 0)
}

// commitRules: the rules of every action still needing approval, and of the commit's totals.
func (t *Tx) commitRules() []review.Rule {
	var need []*model.Action
	for _, a := range t.Actions {
		if a.Decision == model.RequireApproval && !t.cancelled(a.ID) {
			need = append(need, a)
		}
	}
	return t.Mgr.Review.Requirements(need, t.Totals())
}

func (t *Tx) commitOutcome(hash string, since float64) review.Outcome {
	return t.Mgr.Review.Decide(t.ID, review.CommitSubject(hash), t.Requester, t.commitRules(), t.Mgr.signedDecisions(t.ID), since)
}

// SignDecision signs and records a reviewer's decision, on one action (actionID) or on the
// transaction's current preview (actionID empty). keyPath is the reviewer's SSH key.
func (m *Manager) SignDecision(t *Tx, actionID, decision, reviewer, keyPath string) (review.Outcome, error) {
	if !m.Review.Enabled() {
		return review.Outcome{}, fmt.Errorf("no reviewers are configured")
	}
	if decision != "approve" && decision != "decline" {
		return review.Outcome{}, fmt.Errorf("decision must be approve or decline")
	}
	var subject string
	var check func() review.Outcome
	var shown func() any // what the reviewer decided on, kept as evidence
	if actionID != "" {
		var a *model.Action
		for _, x := range t.Actions {
			if x.ID == actionID {
				a = x
			}
		}
		if a == nil {
			return review.Outcome{}, fmt.Errorf("no action %s in %s", actionID, t.ID)
		}
		subject, check = review.ActionSubject(a), func() review.Outcome { return t.actionOutcome(a) }
		shown = func() any { return actionEvidence(a) }
	} else {
		h := t.PreviewHash()
		subject, check = review.CommitSubject(h), func() review.Outcome { return t.commitOutcome(h, 0) }
		shown = func() any { return t.Preview() }
	}
	st := review.Statement{V: 1, Tx: t.ID, Subject: subject, Decision: decision, Reviewer: reviewer, TS: model.Now()}
	sig, err := review.Sign(keyPath, st)
	if err != nil {
		return review.Outcome{}, err
	}
	if err := m.Review.Verify(st, sig); err != nil {
		return review.Outcome{}, fmt.Errorf("this key does not sign as %s: %v", reviewer, err)
	}
	if err := m.addApproval(t.ID, map[string]any{"statement": st, "signature": sig}); err != nil {
		return review.Outcome{}, err
	}
	m.audit("signed_decision", map[string]any{"tx": t.ID, "subject": subject, "decision": decision, "reviewer": reviewer})
	m.recordEvidence(t, kindOf(actionID), subject, decision, reviewer, shown())
	return check(), nil
}

func kindOf(actionID string) string {
	if actionID != "" {
		return "action"
	}
	return "commit"
}
