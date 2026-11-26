package policy

import (
	"testing"

	"undolayer/internal/model"
	"undolayer/internal/risk"
)

func trained(t *testing.T) *risk.Model {
	t.Helper()
	var ex []risk.Example
	for i := 0; i < 10; i++ {
		ex = append(ex,
			risk.Example{Action: model.Action{Connector: "kube", Operation: "delete", Effect: model.Reversible, Facts: model.Facts{"namespace": "prod"}}, Label: 1},
			risk.Example{Action: model.Action{Connector: "kube", Operation: "scale", Effect: model.Reversible, Facts: model.Facts{"namespace": "staging"}}, Label: 0})
	}
	m, err := risk.Train(ex, risk.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The score is a fact; a rule on it can only escalate the decision.
func TestRiskScoreIsAFactRulesCanEscalateOn(t *testing.T) {
	p, err := Parse(`[[rule]]
id = "learned-risk"
decision = "require_approval"
reason = "reviewers have declined actions like this"
when = { risk_score = { gt = 0.8 } }
`)
	if err != nil {
		t.Fatal(err)
	}
	p = Default().Extend(p)
	p.Risk = trained(t)

	risky := &model.Action{Connector: "kube", Operation: "delete", Effect: model.Reversible, Facts: model.Facts{"namespace": "prod"}}
	p.Evaluate(risky)
	if risky.Decision != model.RequireApproval {
		t.Fatalf("learned risk did not escalate: %s %v (score %v)", risky.Decision, risky.Reasons, risky.Facts["risk_score"])
	}
	if sig, _ := risky.Facts["risk_signals"].([]string); len(sig) == 0 {
		t.Fatal("no signals explain the score")
	}

	fine := &model.Action{Connector: "kube", Operation: "scale", Effect: model.Reversible, Facts: model.Facts{"namespace": "staging"}}
	p.Evaluate(fine)
	if s, _ := model.Num(fine.Facts["risk_score"]); s > 0.2 || fine.Decision != model.Allow {
		t.Fatalf("fine action: score %v decision %s", fine.Facts["risk_score"], fine.Decision)
	}

	// without a model nothing changes
	q := Default()
	plain := &model.Action{Connector: "kube", Operation: "delete", Effect: model.Reversible, Facts: model.Facts{}}
	q.Evaluate(plain)
	if _, ok := plain.Facts["risk_score"]; ok {
		t.Fatal("scored without a model")
	}
}
