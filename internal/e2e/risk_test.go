package e2e

import (
	"testing"

	"undolayer/internal/risk"
)

// Reviewer decisions become training data, and the trained model separates them.
func TestRiskModelLearnsFromReviewerDecisions(t *testing.T) {
	w := world(t)
	for i := 0; i < 4; i++ {
		x := w.Mgr.Begin("clear the orders")
		call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders"})
		if err := w.Mgr.DecideAction(x, x.Actions[0].ID, "bob", "decline"); err != nil {
			t.Fatal(err)
		}
		y := w.Mgr.Begin("look at an order")
		call(t, y, "sql", "query", map[string]any{"sql": "SELECT * FROM orders LIMIT 1"})
		if err := w.Mgr.DecideAction(y, y.Actions[0].ID, "bob", "approve"); err != nil {
			t.Fatal(err)
		}
	}
	ex, err := w.Mgr.ReviewedExamples()
	if err != nil || len(ex) != 8 {
		t.Fatalf("examples: %v %d", err, len(ex))
	}
	m, err := risk.Train(ex, risk.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if acc := m.Accuracy(ex, 0.5); acc < 1 {
		t.Fatalf("accuracy %.2f", acc)
	}
}
