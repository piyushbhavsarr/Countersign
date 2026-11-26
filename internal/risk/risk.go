// Package risk is a small, explainable risk-classification model for actions.
//
// It is logistic regression over features derived from an action as the runtime sees it:
// its lane, connector and operation, and every fact the connectors measured (rows a
// statement touched, whether a destination was requested, whether data is destroyed, and
// so on). It learns from labelled examples, for instance the decisions reviewers made on
// past actions, and scores a new action in microseconds, the same score for the same
// action every time.
//
// The score is reported to policy as the fact risk_score, like any other fact. What
// happens next is decided by policy rules, and rules only escalate, so the model can add
// caution where reviewers have been cautious before, but it can never remove a check.
package risk

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"undolayer/internal/model"
)

// Example is one labelled action: Label 1 means risky (a reviewer declined it, or it was
// denied), 0 means it was fine.
type Example struct {
	Action model.Action `json:"action"`
	Label  int          `json:"label"`
}

// Model is a trained logistic-regression classifier.
type Model struct {
	Version   int                `json:"version"`
	Bias      float64            `json:"bias"`
	Weights   map[string]float64 `json:"weights"`
	TrainedOn int                `json:"trained_on"`
	Positives int                `json:"positives"`
}

// Signal is one feature's contribution to a score.
type Signal struct {
	Feature string  `json:"feature"`
	Weight  float64 `json:"weight"`
}

// ScoreFacts are the facts the model itself writes; they are never model inputs.
var ScoreFacts = map[string]bool{"risk_score": true, "risk_signals": true}

const maxStringFact = 48

// Features turns an action into named numeric features. Every fact is used generically by
// its type, so a fact a connector adds later is learned from without code changes.
func Features(a *model.Action) map[string]float64 {
	f := map[string]float64{
		"lane=" + string(a.Effect): 1,
		"connector=" + a.Connector: 1,
		"op=" + a.Connector + "/" + a.Operation: 1,
	}
	for k, v := range a.Facts {
		if strings.HasPrefix(k, "_") || ScoreFacts[k] {
			continue
		}
		addFact(f, k, v)
	}
	return f
}

func addFact(f map[string]float64, k string, v any) {
	switch x := v.(type) {
	case nil:
	case bool:
		f[fmt.Sprintf("%s=%t", k, x)] = 1
	case string:
		if x != "" && len(x) <= maxStringFact {
			f[k+"="+x] = 1
		} else if x != "" {
			f["has:"+k] = 1
		}
	case []string:
		if len(x) > 0 {
			f["has:"+k] = 1
			f["count:"+k] = math.Log1p(float64(len(x)))
		}
	case []any:
		if len(x) > 0 {
			f["has:"+k] = 1
			f["count:"+k] = math.Log1p(float64(len(x)))
		}
	case map[string]any:
		if len(x) > 0 {
			f["has:"+k] = 1
		}
	default:
		if n, ok := model.Num(v); ok {
			// log scale: 10 rows and 10,000 rows are far apart, 10,000 and 10,050 are not
			s := 1.0
			if n < 0 {
				s, n = -1, -n
			}
			f["num:"+k] = s * math.Log1p(n)
		}
	}
}

func sigmoid(z float64) float64 {
	if z >= 0 {
		return 1 / (1 + math.Exp(-z))
	}
	e := math.Exp(z)
	return e / (1 + e)
}

func (m *Model) logit(f map[string]float64) float64 {
	z := m.Bias
	for k, v := range f {
		z += m.Weights[k] * v
	}
	return z
}

// Score returns the probability that the action is risky, and the features that pushed
// the score up the most (strongest first).
func (m *Model) Score(a *model.Action) (float64, []Signal) {
	f := Features(a)
	p := sigmoid(m.logit(f))
	var sig []Signal
	for k, v := range f {
		if c := m.Weights[k] * v; c > 0 {
			sig = append(sig, Signal{Feature: k, Weight: round(c)})
		}
	}
	sort.Slice(sig, func(i, j int) bool {
		if sig[i].Weight != sig[j].Weight {
			return sig[i].Weight > sig[j].Weight
		}
		return sig[i].Feature < sig[j].Feature
	})
	if len(sig) > 3 {
		sig = sig[:3]
	}
	return round(p), sig
}

func round(x float64) float64 { return math.Round(x*1e4) / 1e4 }

// Options control training.
type Options struct {
	Epochs int     // passes over the data (default 400)
	Rate   float64 // learning rate (default 0.3)
	L2     float64 // weight decay (default 0.001)
}

// Train fits a model by batch gradient descent. Classes are weighted so a rare label
// (declines are usually rare) counts as much as a common one. Training is deterministic:
// the same examples give the same model.
func Train(examples []Example, o Options) (*Model, error) {
	if o.Epochs <= 0 {
		o.Epochs = 400
	}
	if o.Rate <= 0 {
		o.Rate = 0.3
	}
	if o.L2 < 0 {
		return nil, errors.New("l2 must not be negative")
	}
	if o.L2 == 0 {
		o.L2 = 0.001
	}
	pos := 0
	xs := make([]map[string]float64, len(examples))
	names := map[string]bool{}
	for i, e := range examples {
		if e.Label != 0 && e.Label != 1 {
			return nil, fmt.Errorf("example %d: label must be 0 or 1", i)
		}
		pos += e.Label
		a := e.Action
		xs[i] = Features(&a)
		for k := range xs[i] {
			names[k] = true
		}
	}
	n := len(examples)
	if pos == 0 || pos == n {
		return nil, errors.New("training needs both risky (1) and fine (0) examples")
	}
	order := make([]string, 0, len(names))
	for k := range names {
		order = append(order, k)
	}
	sort.Strings(order)
	cw := map[int]float64{1: float64(n) / (2 * float64(pos)), 0: float64(n) / (2 * float64(n-pos))}
	m := &Model{Version: 1, Weights: map[string]float64{}, TrainedOn: n, Positives: pos}
	grad := map[string]float64{}
	for epoch := 0; epoch < o.Epochs; epoch++ {
		for k := range grad {
			grad[k] = 0
		}
		gb := 0.0
		for i, x := range xs {
			err := (sigmoid(m.logit(x)) - float64(examples[i].Label)) * cw[examples[i].Label]
			gb += err
			for k, v := range x {
				grad[k] += err * v
			}
		}
		m.Bias -= o.Rate * gb / float64(n)
		for _, k := range order {
			m.Weights[k] -= o.Rate * (grad[k]/float64(n) + o.L2*m.Weights[k])
		}
	}
	for k, w := range m.Weights {
		if math.Abs(w) < 1e-6 {
			delete(m.Weights, k)
		} else {
			m.Weights[k] = round(w)
		}
	}
	m.Bias = round(m.Bias)
	return m, nil
}

// Accuracy is the share of examples the model labels correctly at the given threshold.
func (m *Model) Accuracy(examples []Example, threshold float64) float64 {
	if len(examples) == 0 {
		return 0
	}
	ok := 0
	for _, e := range examples {
		a := e.Action
		p, _ := m.Score(&a)
		if (p >= threshold) == (e.Label == 1) {
			ok++
		}
	}
	return float64(ok) / float64(len(examples))
}

// Load reads a model saved with Save.
func Load(path string) (*Model, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Model
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if m.Version != 1 || m.Weights == nil {
		return nil, fmt.Errorf("%s: not a risk model", path)
	}
	return &m, nil
}

// Save writes the model as JSON.
func (m *Model) Save(path string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
