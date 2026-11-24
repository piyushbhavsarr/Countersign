// Package review decides who may approve what, from signatures only.
//
// Each reviewer has their own SSH key. The gateway holds only the public keys, so neither
// the agent nor anyone who can read the runtime's state can approve: a decision counts
// only if it carries a valid OpenSSH signature (ssh-keygen -Y sign, PROTOCOL.sshsig) over
// the exact statement, by a key listed for that reviewer. Signing is done by ssh-keygen,
// so a key can live in a file, in ssh-agent (ssh-add -c asks for confirmation each time)
// or on a FIDO security key (ed25519-sk: a touch per signature). A key that needs a touch
// or a confirmation is what stops an agent running as the same OS user from signing.
//
// Approval rules say whose signatures a decision needs. They match an action's facts with
// the same conditions policy rules use; rules with connector = "commit" match a whole
// commit's totals. Every matching rule must be satisfied (by its own count of distinct
// reviewers holding one of its roles); with no matching rule, any one reviewer will do.
// The person who asked for the task cannot approve it unless allow_self_approval is set.
// A valid decline by any reviewer eligible under a matching rule declines.
package review

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"undolayer/internal/model"
	"undolayer/internal/policy"
)

// Namespace binds signatures to this purpose: an undolayer signature is not valid for git,
// files or anything else signed with the same key, and vice versa.
const Namespace = "undolayer-approval-v1"

type Reviewer struct {
	Name  string
	Keys  []ssh.PublicKey
	Roles []string
	Users []string // OS accounts or requester identities that are this person
}

type Rule struct {
	ID     string
	Match  policy.Rule // connector / operation / effect / when, as in policy rules
	Roles  []string    // any of these roles (empty: any reviewer)
	Count  int         // distinct reviewers needed (default 1)
	Reason string
}

type Config struct {
	Reviewers         map[string]*Reviewer
	Rules             []Rule
	AllowSelfApproval bool
}

// Enabled: with no reviewers configured, the runtime falls back to its single-user mode.
func (c *Config) Enabled() bool { return c != nil && len(c.Reviewers) > 0 }

// ---------------------------------------------------------------- configuration

// FromMap reads [reviewers.<name>] and [[approval_rule]] tables.
func FromMap(reviewers map[string]map[string]any, rules []map[string]any, allowSelf bool) (*Config, error) {
	c := &Config{Reviewers: map[string]*Reviewer{}, AllowSelfApproval: allowSelf}
	for name, r := range reviewers {
		rv := &Reviewer{Name: name, Roles: strs(r["roles"]), Users: strs(r["users"])}
		keys := strs(r["keys"])
		if k, ok := r["key"].(string); ok {
			keys = append(keys, k)
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("reviewer %s has no key", name)
		}
		for _, k := range keys {
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
			if err != nil {
				return nil, fmt.Errorf("reviewer %s: key is not an OpenSSH public key: %v", name, err)
			}
			rv.Keys = append(rv.Keys, pk)
		}
		c.Reviewers[name] = rv
	}
	roles := map[string]bool{}
	for _, r := range c.Reviewers {
		for _, x := range r.Roles {
			roles[x] = true
		}
	}
	for i, r := range rules {
		id := fmt.Sprint(r["id"])
		if r["id"] == nil {
			id = fmt.Sprintf("approval_rule[%d]", i)
		}
		when, _ := r["when"].(map[string]any)
		if err := policy.ValidateWhen(when); err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		n := 1
		if f, ok := model.Num(r["count"]); ok {
			n = int(f)
		}
		rule := Rule{ID: id, Roles: strs(r["roles"]), Count: n, Reason: str(r["reason"]),
			Match: policy.Rule{ID: id, Connector: orAll(strs(r["connector"])), Operation: orAll(strs(r["operation"])),
				Effect: orAll(strs(r["effect"])), When: when}}
		if rule.Count < 1 {
			return nil, fmt.Errorf("%s: count must be at least 1", id)
		}
		for _, x := range rule.Roles {
			if !roles[x] {
				return nil, fmt.Errorf("%s: no reviewer has role %q, so it could never be approved", id, x)
			}
		}
		if eligible := c.eligible(rule); len(eligible) < rule.Count {
			return nil, fmt.Errorf("%s needs %d reviewers but only %d can approve it", id, rule.Count, len(eligible))
		}
		c.Rules = append(c.Rules, rule)
	}
	return c, nil
}

func (c *Config) eligible(r Rule) []string {
	var out []string
	for name, rv := range c.Reviewers {
		if len(r.Roles) == 0 || overlap(rv.Roles, r.Roles) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- statements and signatures

// Statement is exactly what a reviewer signs.
type Statement struct {
	V        int     `json:"v"`
	Tx       string  `json:"tx"`
	Subject  string  `json:"subject"` // "action:<id>:<sha256 of its arguments>" or "commit:<preview hash>"
	Decision string  `json:"decision"`
	Reviewer string  `json:"reviewer"`
	TS       float64 `json:"ts"`
}

func (s Statement) Bytes() []byte {
	b, _ := json.Marshal(s) // struct field order is fixed: canonical
	return b
}

// ActionSubject names one action with its exact connector, operation and arguments.
func ActionSubject(a *model.Action) string {
	b, _ := json.Marshal(map[string]any{"c": a.Connector, "o": a.Operation, "a": a.Args})
	h := sha256.Sum256(b)
	return "action:" + a.ID + ":" + fmt.Sprintf("%x", h)
}

func CommitSubject(previewHash string) string { return "commit:" + previewHash }

// Sign runs ssh-keygen -Y sign with the reviewer's key (a private key file, or the public
// key of a key held by ssh-agent or a security key).
func Sign(keyPath string, s Statement) (string, error) {
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-q", "-n", Namespace, "-f", keyPath)
	cmd.Stdin = bytes.NewReader(s.Bytes())
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh-keygen could not sign: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// Verify checks an armored SSHSIG signature over the statement against the reviewer's keys.
func (c *Config) Verify(s Statement, armored string) error {
	rv := c.Reviewers[s.Reviewer]
	if rv == nil {
		return fmt.Errorf("%q is not a configured reviewer", s.Reviewer)
	}
	pub, ns, hashAlg, sig, err := parseSSHSIG(armored)
	if err != nil {
		return err
	}
	if ns != Namespace {
		return fmt.Errorf("signature is for namespace %q, not %q", ns, Namespace)
	}
	known := false
	for _, k := range rv.Keys {
		if bytes.Equal(k.Marshal(), pub.Marshal()) {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("signed with a key that is not %s's", s.Reviewer)
	}
	var digest []byte
	switch hashAlg {
	case "sha512":
		h := sha512.Sum512(s.Bytes())
		digest = h[:]
	case "sha256":
		h := sha256.Sum256(s.Bytes())
		digest = h[:]
	default:
		return fmt.Errorf("unsupported signature hash %q", hashAlg)
	}
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	for _, f := range [][]byte{[]byte(Namespace), nil, []byte(hashAlg), digest} {
		writeString(&signed, f)
	}
	return pub.Verify(signed.Bytes(), sig)
}

func parseSSHSIG(armored string) (ssh.PublicKey, string, string, *ssh.Signature, error) {
	const begin, end = "-----BEGIN SSH SIGNATURE-----", "-----END SSH SIGNATURE-----"
	i := strings.Index(armored, begin)
	if i < 0 {
		return nil, "", "", nil, errors.New("not an SSH signature")
	}
	body := armored[i+len(begin):]
	j := strings.Index(body, end) // the end marker after the begin marker, never overlapping it
	if j < 0 {
		return nil, "", "", nil, errors.New("not an SSH signature")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body[:j]), ""))
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("signature is not valid base64: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte("SSHSIG")) || len(raw) < 10 {
		return nil, "", "", nil, errors.New("not an SSHSIG blob")
	}
	rest := raw[6:]
	if binary.BigEndian.Uint32(rest) != 1 {
		return nil, "", "", nil, errors.New("unsupported SSHSIG version")
	}
	rest = rest[4:]
	var fields [5][]byte
	for k := range fields {
		var ok bool
		if fields[k], rest, ok = readString(rest); !ok {
			return nil, "", "", nil, errors.New("truncated SSHSIG blob")
		}
	}
	pub, err := ssh.ParsePublicKey(fields[0])
	if err != nil {
		return nil, "", "", nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(fields[4], &sig); err != nil {
		return nil, "", "", nil, fmt.Errorf("bad signature: %v", err)
	}
	return pub, string(fields[1]), string(fields[3]), &sig, nil
}

func readString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(len(b)-4) < uint64(n) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func writeString(w *bytes.Buffer, s []byte) {
	_ = binary.Write(w, binary.BigEndian, uint32(len(s)))
	w.Write(s)
}

// ---------------------------------------------------------------- decisions

// Signed is one recorded decision: the statement and its signature.
type Signed struct {
	Statement Statement `json:"statement"`
	Signature string    `json:"signature"`
}

// Outcome of checking the decisions on one subject.
type Outcome struct {
	Approved   bool     `json:"approved"`
	DeclinedBy string   `json:"declined_by,omitempty"`
	ApprovedBy []string `json:"approved_by,omitempty"`
	Missing    []string `json:"missing,omitempty"` // what is still needed, per rule
	Invalid    []string `json:"invalid,omitempty"` // decisions that were ignored, and why
}

// Requirements returns the rules a subject must satisfy: those matching any of the
// actions (for a commit, also those matching its totals as connector "commit").
func (c *Config) Requirements(actions []*model.Action, commitTotals map[string]float64) []Rule {
	var out []Rule
	seen := map[string]bool{}
	add := func(a *model.Action) {
		for _, r := range c.Rules {
			if !seen[r.ID] && r.Match.Matches(a) {
				seen[r.ID] = true
				out = append(out, r)
			}
		}
	}
	for _, a := range actions {
		add(a)
	}
	if commitTotals != nil {
		f := model.Facts{}
		for k, v := range commitTotals {
			f[k] = v
		}
		add(&model.Action{Connector: "commit", Operation: "commit", Facts: f})
	}
	if len(out) == 0 {
		out = []Rule{{ID: "any-reviewer", Count: 1, Reason: "any one reviewer"}}
	}
	return out
}

// Decide checks signed decisions on one subject against the rules. since: decisions made
// before it are not counted (a decision answers one request).
func (c *Config) Decide(txID, subject, requester string, rules []Rule, decisions []Signed, since float64) Outcome {
	var o Outcome
	approvers := map[string]bool{}
	for _, d := range decisions {
		s := d.Statement
		if s.Tx != txID || s.Subject != subject || s.TS < since {
			continue
		}
		if err := c.Verify(s, d.Signature); err != nil {
			o.Invalid = append(o.Invalid, fmt.Sprintf("%s: %v", s.Reviewer, err))
			continue
		}
		if !c.AllowSelfApproval && c.isRequester(s.Reviewer, requester) {
			o.Invalid = append(o.Invalid, fmt.Sprintf("%s asked for this task and cannot decide on it", s.Reviewer))
			continue
		}
		eligibleSomewhere := false
		for _, r := range rules {
			if contains(c.eligible(r), s.Reviewer) {
				eligibleSomewhere = true
			}
		}
		if !eligibleSomewhere {
			o.Invalid = append(o.Invalid, fmt.Sprintf("%s has none of the roles this needs", s.Reviewer))
			continue
		}
		switch s.Decision {
		case "decline":
			if o.DeclinedBy == "" {
				o.DeclinedBy = s.Reviewer
			}
		case "approve":
			approvers[s.Reviewer] = true
		}
	}
	if o.DeclinedBy != "" {
		return o
	}
	for n := range approvers {
		o.ApprovedBy = append(o.ApprovedBy, n)
	}
	sort.Strings(o.ApprovedBy)
	o.Approved = true
	for _, r := range rules {
		have := 0
		for _, n := range c.eligible(r) {
			if approvers[n] {
				have++
			}
		}
		if have < r.Count {
			o.Approved = false
			who := "any reviewer"
			if len(r.Roles) > 0 {
				who = "role " + strings.Join(r.Roles, " or ")
			}
			o.Missing = append(o.Missing, fmt.Sprintf("%s: %d more approval(s) from %s", r.ID, r.Count-have, who))
		}
	}
	return o
}

func (c *Config) isRequester(reviewer, requester string) bool {
	if requester == "" {
		return false
	}
	if reviewer == requester {
		return true
	}
	rv := c.Reviewers[reviewer]
	return rv != nil && contains(rv.Users, requester)
}

// Describe says, for a pending request, who can decide it.
func (c *Config) Describe(rules []Rule) []string {
	var out []string
	for _, r := range rules {
		who := c.eligible(r)
		if r.ID == "any-reviewer" {
			who = c.eligible(Rule{})
		}
		out = append(out, fmt.Sprintf("%s: %d of %s", r.ID, r.Count, strings.Join(who, ", ")))
	}
	return out
}

// ---------------------------------------------------------------- key generation

// Keygen creates a reviewer key with ssh-keygen and returns the public key line.
// hardware: an ed25519-sk key on a FIDO security key (a touch per signature).
func Keygen(path, comment string, hardware bool) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists", path)
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	typ := "ed25519"
	if hardware {
		typ = "ed25519-sk"
	}
	cmd := exec.Command("ssh-keygen", "-t", typ, "-C", comment, "-f", path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr // passphrase / touch prompts
	if err := cmd.Run(); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path + ".pub")
	return strings.TrimSpace(string(b)), err
}

// ---------------------------------------------------------------- helpers

func strs(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case string:
		return []string{x}
	}
	return nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// orAll: an omitted connector / operation / effect matches any, as in policy rules.
func orAll(l []string) []string {
	if len(l) == 0 {
		return []string{"*"}
	}
	return l
}

func overlap(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
