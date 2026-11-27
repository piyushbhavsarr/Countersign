package tx

import (
	"encoding/json"

	"undolayer/internal/model"
	"undolayer/internal/risk"
)

// ReviewedExamples turns the approval evidence of every task into training examples for
// the risk model: an action a reviewer declined is risky (1), one they approved is fine
// (0). The model learns from the same facts the reviewer was shown.
func (m *Manager) ReviewedExamples() ([]risk.Example, error) {
	var out []risk.Example
	err := m.Store.AuditLines(func(line []byte) error {
		var r struct {
			Event    string `json:"event"`
			Kind     string `json:"kind"`
			Decision string `json:"decision"`
			Content  struct {
				Connector string       `json:"connector"`
				Operation string       `json:"operation"`
				Effect    model.Effect `json:"effect"`
				Facts     model.Facts  `json:"facts"`
			} `json:"content"`
		}
		if json.Unmarshal(line, &r) != nil || r.Event != evidenceEvent || r.Kind != "action" {
			return nil
		}
		label := 0
		switch r.Decision {
		case "decline":
			label = 1
		case "approve":
		default:
			return nil
		}
		a := model.Action{Connector: r.Content.Connector, Operation: r.Content.Operation, Effect: r.Content.Effect, Facts: r.Content.Facts}
		out = append(out, risk.Example{Action: a, Label: label})
		return nil
	})
	return out, err
}
