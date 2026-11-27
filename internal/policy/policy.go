// Package policy decides, from measured facts, whether an action runs, waits, needs a
// human, or never runs. Rules only escalate (allow < hold < require_approval < deny):
// adding a rule can never make the system less safe.
//
// Fact predicates: a scalar means equality, a list means membership, a table means
// operators: gt, gte, lt, lte, eq, ne, in, glob, contains, exists, regex (regex exists
// for operator-written rules; no default rule uses it).
package policy

import (
	_ "embed"
	"fmt"
	"os"
	"path"
	"reflect"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"undolayer/internal/model"
	"undolayer/internal/risk"
)

//go:embed default_policy.toml
var defaultTOML string

var BudgetKeys = map[string]string{
	"max_rows_changed":           "rows_changed",
	"max_files_deleted":          "files_deleted",
	"max_files_changed":          "files_changed",
	"max_external_effects":       "external_effects",
	"max_spend_cents":            "spend_cents",
	"max_table_fraction_changed": "max_table_fraction_changed",
	"max_kube_objects_deleted":   "kube_objects_deleted",
	"max_kube_objects_changed":   "kube_objects_changed",
}

var defaultByEffect = map[model.Effect]model.Decision{
	model.Read: model.Allow, model.Reversible: model.Allow, model.Compensable: model.Allow,
	model.Deferrable: model.Hold, model.Irreversible: model.RequireApproval,
}

type Rule struct {
	ID        string
	Decision  model.Decision
	Reason    string
	Connector []string
	Operation []string
	Effect    []string
	When      map[string]any
}

type Settings struct {
	HoldIrreversible         bool
	RequireApprovalForCommit bool
	RedactResults            bool
	SensitiveMinLen          int
	LineageMinLen            int
	MaxEffectAttempts        int
}

type Policy struct {
	Rules    []Rule
	Budget   map[string]float64
	Settings Settings
	// Risk, when set, scores every action; the score is the fact risk_score (0 to 1) and
	// the features behind it are risk_signals. Rules decide what a score means.
	Risk *risk.Model
}

func strs(v any) []string {
	switch x := v.(type) {
	case nil:
		return []string{"*"}
	case string:
		return []string{x}
	case []any:
		out := []string{}
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return []string{fmt.Sprint(v)}
}

func FromMap(data map[string]any) (*Policy, error) {
	p := &Policy{Budget: map[string]float64{}, Settings: Settings{
		HoldIrreversible: true, RedactResults: true, SensitiveMinLen: 8, LineageMinLen: 4, MaxEffectAttempts: 12}}
	if s, ok := data["settings"].(map[string]any); ok {
		b := func(k string, d *bool) {
			if v, ok := s[k].(bool); ok {
				*d = v
			}
		}
		i := func(k string, d *int) {
			if v, ok := model.Num(s[k]); ok {
				*d = int(v)
			}
		}
		b("hold_irreversible", &p.Settings.HoldIrreversible)
		b("require_approval_for_commit", &p.Settings.RequireApprovalForCommit)
		b("redact_results", &p.Settings.RedactResults)
		i("sensitive_min_len", &p.Settings.SensitiveMinLen)
		i("lineage_min_len", &p.Settings.LineageMinLen)
		i("max_effect_attempts", &p.Settings.MaxEffectAttempts)
	}
	if b, ok := data["budget"].(map[string]any); ok {
		for k, v := range b {
			if _, known := BudgetKeys[k]; !known {
				return nil, fmt.Errorf("unknown budget key %q", k)
			}
			f, _ := model.Num(v)
			p.Budget[k] = f
		}
	}
	rules, _ := data["rule"].([]map[string]any)
	if rules == nil {
		if raw, ok := data["rule"].([]any); ok {
			for _, r := range raw {
				if m, ok := r.(map[string]any); ok {
					rules = append(rules, m)
				}
			}
		}
	}
	for _, r := range rules {
		when, _ := r["when"].(map[string]any)
		d := model.Decision(fmt.Sprint(r["decision"]))
		if _, ok := model.DecisionRank[d]; !ok {
			return nil, fmt.Errorf("rule %v: bad decision %q", r["id"], d)
		}
		reason, _ := r["reason"].(string)
		if err := validateWhen(when); err != nil {
			return nil, fmt.Errorf("rule %v: %w", r["id"], err)
		}
		p.Rules = append(p.Rules, Rule{ID: fmt.Sprint(r["id"]), Decision: d, Reason: reason,
			Connector: strs(r["connector"]), Operation: strs(r["operation"]), Effect: strs(r["effect"]), When: when})
	}
	return p, nil
}

func Parse(text string) (*Policy, error) {
	var data map[string]any
	if _, err := toml.Decode(text, &data); err != nil {
		return nil, err
	}
	return FromMap(data)
}

func Load(file string) (*Policy, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(string(b))
}

func Default() *Policy {
	p, err := Parse(defaultTOML)
	if err != nil {
		panic("default policy: " + err.Error())
	}
	return p
}

// Empty is a policy with no rules and no budgets (lanes only).
func Empty() *Policy { p, _ := FromMap(map[string]any{}); return p }

// Extend combines two policies; the result is at least as strict as either.
func (p *Policy) Extend(o *Policy) *Policy {
	out := &Policy{Rules: append(append([]Rule{}, p.Rules...), o.Rules...), Budget: map[string]float64{}, Settings: p.Settings, Risk: p.Risk}
	if o.Risk != nil {
		out.Risk = o.Risk
	}
	for k, v := range p.Budget {
		out.Budget[k] = v
	}
	for k, v := range o.Budget {
		if cur, ok := out.Budget[k]; !ok || v < cur {
			out.Budget[k] = v
		}
	}
	out.Settings.RequireApprovalForCommit = p.Settings.RequireApprovalForCommit || o.Settings.RequireApprovalForCommit
	out.Settings.HoldIrreversible = p.Settings.HoldIrreversible && o.Settings.HoldIrreversible
	out.Settings.RedactResults = p.Settings.RedactResults || o.Settings.RedactResults
	if o.Settings.SensitiveMinLen < out.Settings.SensitiveMinLen {
		out.Settings.SensitiveMinLen = o.Settings.SensitiveMinLen
	}
	return out
}

var operators = map[string]bool{"gt": true, "gte": true, "lt": true, "lte": true, "eq": true, "ne": true, "in": true,
	"glob": true, "contains": true, "exists": true, "regex": true}

// validateWhen refuses unknown operators: a misspelt operator would otherwise make its
// rule silently never match, which in a safety policy is the worst possible failure.
func validateWhen(when map[string]any) error {
	for fact, cond := range when {
		m, ok := cond.(map[string]any)
		if !ok {
			continue
		}
		for op, arg := range m {
			if !operators[op] {
				return fmt.Errorf("fact %q: unknown operator %q (use one of gt gte lt lte eq ne in glob contains exists regex)", fact, op)
			}
			if op == "regex" {
				if _, err := regexp.Compile(fmt.Sprint(arg)); err != nil {
					return fmt.Errorf("fact %q: bad regex: %w", fact, err)
				}
			}
		}
	}
	return nil
}

func glob(v string, pats []string) bool {
	for _, p := range pats {
		if ok, _ := path.Match(p, v); ok || p == "*" {
			return true
		}
	}
	return false
}

func (r Rule) Matches(a *model.Action) bool {
	if !glob(a.Connector, r.Connector) || !glob(a.Operation, r.Operation) || !glob(string(a.Effect), r.Effect) {
		return false
	}
	for k, cond := range r.When {
		v, present := a.Facts[k]
		if !match(v, present, cond) {
			return false
		}
	}
	return true
}

func list(v any) ([]any, bool) {
	rv := reflect.ValueOf(v)
	if v == nil || (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) {
		return nil, false
	}
	if _, isBytes := v.([]byte); isBytes {
		return nil, false
	}
	out := make([]any, rv.Len())
	for i := range out {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

func eq(a, b any) bool {
	if fa, ok := model.Num(a); ok {
		if fb, ok := model.Num(b); ok {
			return fa == fb
		}
	}
	la, oka := list(a)
	lb, okb := list(b)
	if oka && okb {
		if len(la) != len(lb) {
			return false
		}
		for i := range la {
			if !eq(la[i], lb[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

func match(v any, present bool, cond any) bool {
	if m, ok := cond.(map[string]any); ok {
		for op, arg := range m {
			if !operator(v, present, op, arg) {
				return false
			}
		}
		return true
	}
	if !present {
		return false
	}
	if opts, ok := list(cond); ok {
		if vals, ok := list(v); ok {
			for _, x := range vals {
				for _, o := range opts {
					if eq(x, o) {
						return true
					}
				}
			}
			return false
		}
		for _, o := range opts {
			if eq(v, o) {
				return true
			}
		}
		return false
	}
	if vals, ok := list(v); ok {
		for _, x := range vals {
			if eq(x, cond) {
				return true
			}
		}
		return false
	}
	return eq(v, cond)
}

func operator(v any, present bool, op string, arg any) bool {
	if op == "exists" {
		want, _ := arg.(bool)
		return present == want
	}
	if !present {
		return false
	}
	values, isList := list(v)
	if !isList {
		values = []any{v}
	}
	fv, vnum := model.Num(v)
	fa, anum := model.Num(arg)
	switch op {
	case "eq":
		return eq(v, arg)
	case "ne":
		return !eq(v, arg)
	case "gt":
		return vnum && anum && fv > fa
	case "gte":
		return vnum && anum && fv >= fa
	case "lt":
		return vnum && anum && fv < fa
	case "lte":
		return vnum && anum && fv <= fa
	case "in":
		opts, _ := list(arg)
		for _, x := range values {
			for _, o := range opts {
				if eq(x, o) {
					return true
				}
			}
		}
		return false
	case "glob":
		for _, x := range values {
			if ok, _ := path.Match(fmt.Sprint(arg), fmt.Sprint(x)); ok {
				return true
			}
		}
		return false
	case "contains":
		for _, x := range values {
			if strings.Contains(fmt.Sprint(x), fmt.Sprint(arg)) {
				return true
			}
		}
		return false
	case "regex":
		re, err := regexp.Compile("(?i)" + fmt.Sprint(arg))
		if err != nil {
			return false
		}
		for _, x := range values {
			if re.MatchString(fmt.Sprint(x)) {
				return true
			}
		}
		return false
	}
	return false
}

// Evaluate sets the action's decision and reasons.
func (p *Policy) Evaluate(a *model.Action) {
	if p.Risk != nil {
		if a.Facts == nil {
			a.Facts = model.Facts{}
		}
		score, signals := p.Risk.Score(a)
		a.Facts["risk_score"] = score
		names := []string{}
		for _, s := range signals {
			names = append(names, s.Feature)
		}
		a.Facts["risk_signals"] = names
	}
	d := defaultByEffect[a.Effect]
	if d == model.Hold && !p.Settings.HoldIrreversible {
		d = model.RequireApproval
	}
	reasons := []string{}
	if a.Effect == model.Irreversible {
		reasons = append(reasons, "irreversible: cannot be undone, so a human must approve it; it runs on commit")
	}
	for _, r := range p.Rules {
		if r.Matches(a) {
			reasons = append(reasons, strings.TrimSpace(fmt.Sprintf("[%s] %s", r.ID, r.Reason)))
			if model.DecisionRank[r.Decision] > model.DecisionRank[d] {
				d = r.Decision
			}
		}
	}
	if (a.Effect == model.Deferrable || a.Effect == model.Irreversible) && d == model.Allow {
		d = model.Hold
	}
	a.Decision, a.Reasons = d, reasons
}

func (p *Policy) CheckBudget(totals map[string]float64) []string {
	out := []string{}
	for k, limit := range p.Budget {
		metric := BudgetKeys[k]
		if totals[metric] > limit {
			out = append(out, fmt.Sprintf("budget %s=%v exceeded (%s=%v)", k, limit, metric, totals[metric]))
		}
	}
	return out
}

// ValidateWhen checks a `when` table with the same operators policy rules accept.
func ValidateWhen(when map[string]any) error { return validateWhen(when) }
