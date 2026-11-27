package risk

import (
	"path/filepath"
	"reflect"
	"testing"

	"undolayer/internal/model"
)

func act(conn, op string, effect model.Effect, facts model.Facts) model.Action {
	return model.Action{Connector: conn, Operation: op, Effect: effect, Facts: facts}
}

// examples: reviewers declined mass deletes and payments to unrequested recipients, and
// approved small updates, reads and messages to known people.
func examples() []Example {
	var out []Example
	for i := 0; i < 12; i++ {
		out = append(out,
			Example{act("sql", "execute", model.Reversible, model.Facts{"rows_affected": 5000 + i*100, "table_fraction_changed": 0.97}), 1},
			Example{act("payments", "charge", model.Irreversible, model.Facts{"destination_untrusted": true, "amount_cents": 900000}), 1},
			Example{act("sql", "execute", model.Reversible, model.Facts{"rows_affected": 1 + i%3, "table_fraction_changed": 0.01}), 0},
			Example{act("sql", "query", model.Read, model.Facts{}), 0},
			Example{act("slack", "post", model.Deferrable, model.Facts{"destination_untrusted": false, "audience": 4}), 0},
		)
	}
	return out
}

func TestLearnsWhatReviewersDeclined(t *testing.T) {
	m, err := Train(examples(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if acc := m.Accuracy(examples(), 0.5); acc < 0.99 {
		t.Fatalf("training accuracy %.2f", acc)
	}
	mass := act("sql", "execute", model.Reversible, model.Facts{"rows_affected": 7000, "table_fraction_changed": 0.9})
	small := act("sql", "execute", model.Reversible, model.Facts{"rows_affected": 2, "table_fraction_changed": 0.02})
	pm, sig := m.Score(&mass)
	ps, _ := m.Score(&small)
	if pm < 0.8 || ps > 0.2 {
		t.Fatalf("mass delete %.3f, small update %.3f", pm, ps)
	}
	if len(sig) == 0 || sig[0].Weight <= 0 {
		t.Fatalf("no explanation for a risky score: %+v", sig)
	}
}

func TestUnseenFactsAndScoreFactsAreSafe(t *testing.T) {
	m, err := Train(examples(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	a := act("kube", "delete", model.Reversible, model.Facts{"some_new_fact": true, "risk_score": 0.99, "_internal": 1})
	f := Features(&a)
	for k := range f {
		if k == "num:risk_score" || k == "num:_internal" {
			t.Fatalf("model reads its own output or internal facts: %s", k)
		}
	}
	if p, _ := m.Score(&a); p < 0 || p > 1 {
		t.Fatalf("score out of range: %v", p)
	}
}

func TestTrainingIsDeterministicAndSaves(t *testing.T) {
	a, _ := Train(examples(), Options{Epochs: 120})
	b, _ := Train(examples(), Options{Epochs: 120})
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same data gave different models")
	}
	p := filepath.Join(t.TempDir(), "m.json")
	if err := a.Save(p); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || !reflect.DeepEqual(a, c) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestTrainingNeedsBothLabels(t *testing.T) {
	if _, err := Train([]Example{{act("sql", "query", model.Read, nil), 0}}, Options{}); err == nil {
		t.Fatal("trained on one class")
	}
	if _, err := Train([]Example{{act("sql", "query", model.Read, nil), 2}}, Options{}); err == nil {
		t.Fatal("accepted label 2")
	}
}
