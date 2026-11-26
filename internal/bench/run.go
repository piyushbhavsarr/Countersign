package bench

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"runtime"
	"strings"
	"time"

	"undolayer/internal/model"
	"undolayer/internal/policy"
)

var jsonMarshal = json.Marshal

type Result struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Suite  string   `json:"suite"`
	OK     bool     `json:"ok"`
	Events []string `json:"events"`
	Error  string   `json:"error,omitempty"`
	Source string   `json:"source"`
}

// RunOne: worst case for the runtime. A denial stops the scenario like an agent that
// gives up on that step, then the agent still tries to commit whatever is left; an
// approval prompt is declined by the simulated human; an agent error rolls back; a crash
// drops the process (connections closed, ownership lock released by the kernel) and a
// new manager recovers - and the dead process's transaction object is then asked to
// commit anyway, to prove it cannot.
func RunOne(sc Scenario, pol *policy.Policy, useSandbox bool) (res Result) {
	res = Result{ID: sc.ID, Kind: sc.Kind, Suite: sc.Suite, Source: sc.Source}
	if res.Suite == "" {
		res.Suite = "core"
	}
	w := NewWorld(pol, useSandbox)
	defer w.Close()
	defer func() {
		if r := recover(); r != nil {
			res.OK, res.Error = false, fmt.Sprint("panic: ", r)
		}
	}()
	t := w.Mgr.Begin(sc.ID)
	crashed := false
	err := sc.Run(w, t)
	var pv *model.PolicyViolation
	switch {
	case err == nil:
	case errors.As(err, &pv):
		res.Events = append(res.Events, "denied")
		res.Error = err.Error()
	case errors.Is(err, ErrCrash):
		crashed = true
		res.Events = append(res.Events, "crashed")
		for k, h := range t.Handles {
			if c, ok := h.(interface{ Close() error }); ok {
				_ = c.Close()
			}
			closeLive(h)
			delete(t.Handles, k)
		}
		t.Release()
		w.MakeManager().Recover()
		res.Events = append(res.Events, "recovered")
		if _, err := t.Commit(); err != nil {
			res.Events = append(res.Events, "zombie_refused")
		} else {
			res.Events = append(res.Events, "zombie_committed")
		}
	default:
		res.Events = append(res.Events, "agent_error")
		res.Error = err.Error()
		_, _ = t.Rollback("agent error")
	}
	if t.State == model.Open && !crashed {
		r, err := t.Commit()
		var ar *model.ApprovalRequired
		var cc *model.CommitConflict
		switch {
		case err == nil:
			res.Events = append(res.Events, "committed")
			for _, o := range r.Outbox {
				if o.Status != "sent" {
					res.Events = append(res.Events, "outbox_"+o.Status)
				}
			}
		case errors.As(err, &ar):
			res.Events = append(res.Events, "approval_declined")
			_, _ = t.Rollback("human declined")
		case errors.As(err, &cc):
			res.Events = append(res.Events, "conflict")
		default:
			res.Events = append(res.Events, "commit_failed")
			if res.Error == "" {
				res.Error = err.Error()
			}
		}
	}
	outcome := sc.Check(w)
	if sc.Kind == "harmful" {
		res.OK = !outcome
	} else {
		res.OK = outcome
	}
	return res
}

// closeLive closes a connector's live handle the way process death would.
func closeLive(h any) {
	type closer interface{ CloseForCrash() }
	if c, ok := h.(closer); ok {
		c.CloseForCrash()
	}
}

func binomCDF(k, n int, p float64) float64 {
	s := 0.0
	for i := 0; i <= k; i++ {
		lc, _ := math.Lgamma(float64(n + 1))
		l1, _ := math.Lgamma(float64(i + 1))
		l2, _ := math.Lgamma(float64(n - i + 1))
		s += math.Exp(lc-l1-l2+float64(i)*math.Log(p)+float64(n-i)*math.Log(1-p)) * 1
	}
	return s
}

// ClopperPearson: exact 95% interval for k successes out of n.
func ClopperPearson(k, n int) (float64, float64) {
	if n == 0 {
		return 0, 1
	}
	solve := func(f func(float64) bool) float64 {
		lo, hi := 1e-12, 1-1e-12
		for i := 0; i < 80; i++ {
			mid := (lo + hi) / 2
			if f(mid) {
				lo = mid
			} else {
				hi = mid
			}
		}
		return (lo + hi) / 2
	}
	lower, upper := 0.0, 1.0
	if k > 0 {
		lower = solve(func(p float64) bool { return 1-binomCDF(k-1, n, p) < 0.025 })
	}
	if k < n {
		upper = solve(func(p float64) bool { return binomCDF(k, n, p) > 0.025 })
	}
	return lower, upper
}

type Rate struct {
	K, N        int
	Pct, Lo, Hi float64
}

func rate(rs []Result, kind string) Rate {
	r := Rate{}
	for _, x := range rs {
		if x.Kind == kind {
			r.N++
			if x.OK {
				r.K++
			}
		}
	}
	lo, hi := ClopperPearson(r.K, r.N)
	if r.N > 0 {
		r.Pct = 100 * float64(r.K) / float64(r.N)
	}
	r.Lo, r.Hi = 100*lo, 100*hi
	return r
}

func Main(args []string) int {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	pname := fs.String("policy", "default", "default | none")
	noSandbox := fs.Bool("no-sandbox", false, "disable the shell sandbox (ablation)")
	suite := fs.String("suite", "all", "core | heldout | fresh | all")
	only := fs.String("k", "", "only scenarios whose id contains this")
	extra := fs.String("scenarios", "", "JSON scenario file (docs/scenario-spec.md), run as suite \"fresh\"")
	_ = fs.Parse(args)
	all := Scenarios
	if *extra != "" {
		more, err := LoadDSL(*extra, "fresh")
		if err != nil {
			fmt.Println("scenarios:", err)
			return 2
		}
		all = append(append([]Scenario{}, Scenarios...), more...)
	}
	pol := policy.Default()
	if *pname == "none" {
		pol = policy.Empty()
	}
	start := time.Now()
	var results []Result
	for _, sc := range all {
		s := sc.Suite
		if s == "" {
			s = "core"
		}
		if (*suite != "all" && s != *suite) || (*only != "" && !strings.Contains(sc.ID, *only)) {
			continue
		}
		results = append(results, RunOne(sc, pol, !*noSandbox))
	}
	summary := map[string]any{"seconds": time.Since(start).Seconds(), "policy": *pname, "sandbox": !*noSandbox}
	for _, s := range []string{"core", "heldout", "fresh", "all"} {
		var sub []Result
		for _, r := range results {
			if s == "all" || r.Suite == s {
				sub = append(sub, r)
			}
		}
		if len(sub) > 0 {
			summary[s] = map[string]any{"harmful": rate(sub, "harmful"), "benign": rate(sub, "benign")}
		}
	}
	ok := true
	for _, r := range results {
		ok = ok && r.OK
	}
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]any{"summary": summary, "results": results}, "", "  ")
		fmt.Println(string(b))
	} else {
		for _, r := range results {
			mark := "PASS"
			if !r.OK {
				mark = "FAIL"
			}
			fmt.Printf("%s  %-7s %-8s %-30s %s\n", mark, r.Suite, r.Kind, r.ID, strings.Join(r.Events, ","))
			if !r.OK && r.Error != "" {
				fmt.Printf("      %.600s\n", r.Error)
			}
		}
		fmt.Println()
		for _, s := range []string{"core", "heldout", "fresh", "all"} {
			m, okk := summary[s].(map[string]any)
			if !okk {
				continue
			}
			h, b := m["harmful"].(Rate), m["benign"].(Rate)
			fmt.Printf("%-8s harmful contained %5.1f%% of %-3d(95%% CI %.1f-%.1f)   benign completed %5.1f%% of %-3d(95%% CI %.1f-%.1f)\n",
				s, h.Pct, h.N, h.Lo, h.Hi, b.Pct, b.N, b.Lo, b.Hi)
		}
		fmt.Printf("(%.1fs, policy=%s, sandbox=%v, %s)\n", time.Since(start).Seconds(), *pname, !*noSandbox, osName())
	}
	if !ok {
		return 1
	}
	return 0
}

func osName() string { return runtime.GOOS + "/" + runtime.GOARCH }
