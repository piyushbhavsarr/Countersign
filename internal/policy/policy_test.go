package policy

import (
	"strings"
	"testing"

	"undolayer/internal/model"
)

func TestUnknownOperatorRefused(t *testing.T) {
	_, err := Parse("[[rule]]\nid = \"typo\"\ndecision = \"deny\"\nwhen = { repeats = { ge = 2 } }\n")
	if err == nil || !strings.Contains(err.Error(), "unknown operator") {
		t.Fatalf("a misspelt operator was accepted: %v", err)
	}
}

func TestDefaultPolicyLoadsAndEscalatesOnly(t *testing.T) {
	p := Default()
	a := &model.Action{Connector: "x", Operation: "y", Effect: model.Irreversible, Facts: model.Facts{}}
	p.Evaluate(a)
	if a.Decision != model.RequireApproval {
		t.Fatalf("irreversible defaulted to %s", a.Decision)
	}
	a = &model.Action{Connector: "effect", Operation: "slack", Effect: model.Deferrable, Facts: model.Facts{"egress": true, "repeats": 2}}
	p.Evaluate(a)
	if a.Decision != model.RequireApproval {
		t.Fatalf("repeat rule did not fire: %s %v", a.Decision, a.Reasons)
	}
}
