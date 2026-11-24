package review

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"undolayer/internal/model"
)

func key(t *testing.T, name string) (path, pub string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	b, _ := os.ReadFile(path + ".pub")
	return path, strings.TrimSpace(string(b))
}

type team struct {
	cfg  *Config
	keys map[string]string
}

func newTeam(t *testing.T, rules []map[string]any, allowSelf bool) *team {
	tm := &team{keys: map[string]string{}}
	revs := map[string]map[string]any{}
	for name, roles := range map[string][]any{"alice": {"engineering"}, "bob": {"finance"}, "carol": {"finance", "engineering"}} {
		p, pub := key(t, name)
		tm.keys[name] = p
		revs[name] = map[string]any{"key": pub, "roles": roles, "users": []any{name + "-laptop"}}
	}
	cfg, err := FromMap(revs, rules, allowSelf)
	if err != nil {
		t.Fatal(err)
	}
	tm.cfg = cfg
	return tm
}

func (tm *team) sign(t *testing.T, who string, s Statement) Signed {
	t.Helper()
	s.Reviewer = who
	sig, err := Sign(tm.keys[who], s)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{Statement: s, Signature: sig}
}

var payment = &model.Action{ID: "act_1", Connector: "pay", Operation: "send", Args: map[string]any{"amount": 900},
	Facts: model.Facts{"amount_cents": 90000}}

func TestOnlyTheReviewersOwnSignatureCounts(t *testing.T) {
	tm := newTeam(t, nil, false)
	sub := ActionSubject(payment)
	s := Statement{V: 1, Tx: "tx1", Subject: sub, Decision: "approve", TS: 10}
	good := tm.sign(t, "alice", s)
	if err := tm.cfg.Verify(good.Statement, good.Signature); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	forged := good
	forged.Statement.Reviewer = "bob" // alice's signature presented as bob's
	if tm.cfg.Verify(forged.Statement, forged.Signature) == nil {
		t.Fatal("a signature was accepted for the wrong reviewer")
	}
	tampered := good
	tampered.Statement.Subject = ActionSubject(&model.Action{ID: "act_1", Connector: "pay", Operation: "send", Args: map[string]any{"amount": 90000}})
	if tm.cfg.Verify(tampered.Statement, tampered.Signature) == nil {
		t.Fatal("a signature was accepted for different arguments")
	}
	// the same key signing for another purpose (e.g. git) does not count
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-q", "-n", "git", "-f", tm.keys["alice"])
	cmd.Stdin = bytes.NewReader(s.Bytes())
	other, _ := cmd.Output()
	if tm.cfg.Verify(good.Statement, string(other)) == nil {
		t.Fatal("a signature from another namespace was accepted")
	}
	// someone with an unlisted key
	p, _ := key(t, "mallory")
	sig, _ := Sign(p, good.Statement)
	if tm.cfg.Verify(good.Statement, sig) == nil {
		t.Fatal("an unlisted key was accepted")
	}
}

func TestRulesNeedTheirRolesAndCounts(t *testing.T) {
	tm := newTeam(t, []map[string]any{
		{"id": "large-payments", "connector": "pay", "when": map[string]any{"amount_cents": map[string]any{"gt": 50000}},
			"roles": []any{"finance"}, "count": 2},
	}, false)
	rules := tm.cfg.Requirements([]*model.Action{payment}, nil)
	sub := ActionSubject(payment)
	st := Statement{V: 1, Tx: "tx1", Subject: sub, Decision: "approve", TS: 10}

	o := tm.cfg.Decide("tx1", sub, "dev", rules, []Signed{tm.sign(t, "alice", st)}, 0)
	if o.Approved || !strings.Contains(strings.Join(o.Invalid, ";"), "none of the roles") {
		t.Fatalf("engineering approved a finance decision: %+v", o)
	}
	o = tm.cfg.Decide("tx1", sub, "dev", rules, []Signed{tm.sign(t, "bob", st)}, 0)
	if o.Approved || len(o.Missing) == 0 {
		t.Fatalf("one approval passed a two-person rule: %+v", o)
	}
	o = tm.cfg.Decide("tx1", sub, "dev", rules, []Signed{tm.sign(t, "bob", st), tm.sign(t, "bob", st)}, 0)
	if o.Approved {
		t.Fatal("the same person counted twice")
	}
	o = tm.cfg.Decide("tx1", sub, "dev", rules, []Signed{tm.sign(t, "bob", st), tm.sign(t, "carol", st)}, 0)
	if !o.Approved {
		t.Fatalf("two finance approvals did not pass: %+v", o)
	}
	// a valid decline from an eligible reviewer wins
	dec := st
	dec.Decision = "decline"
	o = tm.cfg.Decide("tx1", sub, "dev", rules, []Signed{tm.sign(t, "bob", st), tm.sign(t, "carol", dec)}, 0)
	if o.Approved || o.DeclinedBy != "carol" {
		t.Fatalf("decline ignored: %+v", o)
	}
	// decisions made before the request are not counted
	o = tm.cfg.Decide("tx1", sub, "dev", rules, []Signed{tm.sign(t, "bob", st), tm.sign(t, "carol", st)}, 11)
	if o.Approved {
		t.Fatal("stale decisions counted")
	}
}

func TestTheRequesterCannotApproveTheirOwnTask(t *testing.T) {
	tm := newTeam(t, nil, false)
	sub := CommitSubject("abc")
	st := Statement{V: 1, Tx: "tx1", Subject: sub, Decision: "approve", TS: 1}
	rules := tm.cfg.Requirements(nil, map[string]float64{})
	if o := tm.cfg.Decide("tx1", sub, "alice-laptop", rules, []Signed{tm.sign(t, "alice", st)}, 0); o.Approved {
		t.Fatal("the requester approved their own task")
	}
	if o := tm.cfg.Decide("tx1", sub, "alice-laptop", rules, []Signed{tm.sign(t, "bob", st)}, 0); !o.Approved {
		t.Fatalf("another reviewer could not approve: %+v", o)
	}
	self := newTeam(t, nil, true)
	if o := self.cfg.Decide("tx1", sub, "alice-laptop", rules, []Signed{self.sign(t, "alice", st)}, 0); !o.Approved {
		t.Fatal("allow_self_approval had no effect")
	}
}

func TestMisconfiguredRulesAreRefusedAtLoad(t *testing.T) {
	_, pub := key(t, "a")
	revs := map[string]map[string]any{"a": {"key": pub, "roles": []any{"eng"}}}
	if _, err := FromMap(revs, []map[string]any{{"id": "x", "roles": []any{"finance"}}}, false); err == nil {
		t.Fatal("a rule nobody can satisfy was accepted")
	}
	if _, err := FromMap(revs, []map[string]any{{"id": "x", "count": 2}}, false); err == nil {
		t.Fatal("a two-person rule with one reviewer was accepted")
	}
	if _, err := FromMap(revs, []map[string]any{{"id": "x", "when": map[string]any{"a": map[string]any{"ge": 1}}}}, false); err == nil {
		t.Fatal("an unknown operator was accepted")
	}
	if _, err := FromMap(map[string]map[string]any{"a": {"key": "not a key"}}, nil, false); err == nil {
		t.Fatal("a bad key was accepted")
	}
}
