// Package cloud: AWS and Terraform, where the cloud itself decides what is dangerous.
//
// AWS: every call goes through the official CLI with named profiles, so IAM decides:
//   - view profile (e.g. ViewOnlyAccess) allows it: a metadata read, runs now;
//   - view refuses but read profile (ReadOnlyAccess) allows it: a data read - the result
//     may hold secrets, so its values are treated as sensitive (redacted, no egress).
//     secretsmanager:GetSecretValue, kms:Decrypt and ecr:GetAuthorizationToken are
//     always data reads (operator-extendable list);
//   - read profile refuses it: a mutation - held, needs approval, runs on commit with the
//     write profile. For EC2, the write profile's DryRun probe reports up front whether
//     it would be permitted.
//
// Terraform: plan saved into the transaction and read from Terraform's own JSON; apply
// runs that saved plan on commit. Any delete/replace makes it irreversible (approval).
package cloud

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"undolayer/internal/model"
	"undolayer/internal/tx"
)

// AWS API error codes that mean "this principal may not do this" (IAM / EC2 / STS).
var denied = map[string]bool{"AccessDenied": true, "AccessDeniedException": true, "UnauthorizedOperation": true,
	"UnauthorizedAccess": true, "AuthorizationError": true, "AuthorizationErrorException": true, "NotAuthorized": true}

// DefaultSensitiveReads: read actions that return secret material.
var DefaultSensitiveReads = []string{"secretsmanager:GetSecretValue", "kms:Decrypt", "ecr:GetAuthorizationToken"}

type Connector struct {
	tx.Base
	// Provider: aws (the default), azure or gcp. Azure and GCP connectors offer the
	// resource_* operations only.
	Provider       string
	StateDir       string
	AWSBin         string
	ViewProfile    string
	ReadProfile    string
	WriteProfile   string
	SensitiveReads []string
	Terraform      string
	// CC is the Cloud Control API for resource_* operations (set when profiles are).
	CC Resources
	// Shared keeps verification results where every node sees them (the state store).
	Shared SharedDocs
	// WorkspaceRoot: Terraform runs only in directories of the real workspace whose files
	// this task has not changed (plan executes configuration code: external data sources,
	// providers - so it must be code a person has already accepted by committing it).
	WorkspaceRoot string
}

// EnableResources turns on the resource_* operations through the AWS CLI.
func (c *Connector) EnableResources(timeout time.Duration) {
	c.CC = &CLIResources{c: c, Timeout: timeout}
}

func New(stateDir string) *Connector {
	return &Connector{Base: tx.Base{ConnName: "cloud"}, StateDir: stateDir, AWSBin: "aws", Terraform: "terraform",
		SensitiveReads: DefaultSensitiveReads}
}

func (*Connector) Egress() bool { return true }

var providerName = map[string]string{"azure": "Azure", "gcp": "Google Cloud"}

// NewResources is a connector for one cloud's resources (azure, gcp) through res.
func NewResources(provider, stateDir string, res Resources) *Connector {
	return &Connector{Base: tx.Base{ConnName: provider}, Provider: provider, StateDir: stateDir, CC: res}
}

func (c *Connector) Operations() map[string]tx.OpSchema {
	if c.Provider != "" && c.Provider != "aws" {
		ops := map[string]tx.OpSchema{}
		for k, v := range ccOperations() {
			v.Description = strings.ReplaceAll(strings.ReplaceAll(v.Description, "AWS", providerName[c.Provider]), " (Cloud Control)", "")
			ops[k] = v
		}
		return ops
	}
	s := map[string]any{"type": "string"}
	ops := map[string]tx.OpSchema{
		"terraform_plan":  {Description: "Plan Terraform changes for a directory (read-only).", Properties: map[string]any{"dir": s}, Required: []string{"dir"}},
		"terraform_apply": {Description: "Apply the plan saved by terraform_plan, on commit.", Properties: map[string]any{"dir": s}, Required: []string{"dir"}},
		"aws": {Description: "Call an AWS API action (e.g. service=rds action=DescribeDBInstances). Reads run now; anything AWS " +
			"refuses to read-only credentials is held for approval and runs on commit.",
			Properties: map[string]any{"service": s, "action": s, "params": map[string]any{"type": "object"}}, Required: []string{"service", "action"}},
	}
	if c.CC != nil {
		for k, v := range ccOperations() {
			ops[k] = v
		}
	}
	return ops
}

type Plan struct {
	File    string         `json:"file"`
	Summary map[string]any `json:"summary"`
}

type State struct {
	Plans map[string]*Plan `json:"plans"`
	CC    []*ccChange      `json:"cc,omitempty"`
}

// UndoRecord is the way back for a commit's resource changes.
type UndoRecord struct {
	CC []CCEntry `json:"cc"`
}

func (c *Connector) Prepare(t *tx.Tx) error { return c.prepareCC(t) }

func (c *Connector) Intent(t *tx.Tx) (any, error) {
	in, err := c.intentCC(t)
	if in == nil || err != nil {
		return nil, err
	}
	return in, nil
}

func (c *Connector) UndoInFlight(raw json.RawMessage) error {
	var in ccIntent
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	if c.CC == nil {
		return errors.New("AWS resources are not configured")
	}
	return c.undoInFlightCC(&in)
}

func (c *Connector) Commit(t *tx.Tx) (any, error) {
	done, err := c.commitCC(t)
	if err != nil || len(done) == 0 {
		return nil, err
	}
	return &UndoRecord{CC: done}, nil
}

func (c *Connector) Rollback(t *tx.Tx) error {
	if st := tx.PeekState[State](t, c.Name()); st != nil {
		st.CC = nil // nothing reached AWS: creates and updates run on commit
	}
	return nil
}

func (c *Connector) Recover(t *tx.Tx) error { return c.Rollback(t) }

func (c *Connector) Undo(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	if c.CC == nil {
		return errors.New("AWS resources are not configured")
	}
	return c.undoCC(rec.CC, true)
}

func kebab(action string) string {
	var b strings.Builder
	r := []rune(action)
	for i, ch := range r {
		if unicode.IsUpper(ch) && i > 0 && (unicode.IsLower(r[i-1]) || (i+1 < len(r) && unicode.IsLower(r[i+1]))) {
			b.WriteByte('-')
		}
		b.WriteRune(unicode.ToLower(ch))
	}
	return b.String()
}

// awsNames: a service is a lowercase CLI service name and an action an API operation name
// (as the AWS CLI itself names them), so neither can be read as a CLI option.
func awsNames(service, action string) error {
	ok := func(s string, lower bool) bool {
		if s == "" || s[0] == '-' {
			return false
		}
		for _, r := range s {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			case r == '-' && lower:
			case r >= 'A' && r <= 'Z' && !lower:
			default:
				return false
			}
		}
		return true
	}
	if !ok(service, true) {
		return fmt.Errorf("invalid AWS service name %q", service)
	}
	if !ok(action, false) {
		return fmt.Errorf("invalid AWS action name %q", action)
	}
	return nil
}

func (c *Connector) sensitiveRead(service, action string) bool {
	for _, s := range c.SensitiveReads {
		if strings.EqualFold(s, service+":"+action) {
			return true
		}
	}
	return false
}

func (c *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	if isCC(op) {
		return c.classifyCC(t, op, args)
	}
	switch op {
	case "terraform_plan":
		return model.Read, model.Facts{}, nil
	case "terraform_apply":
		dir, _ := args["dir"].(string)
		var plan *Plan
		if st := tx.PeekState[State](t, c.Name()); st != nil {
			plan = st.Plans[dir]
		}
		f := planFacts(plan)
		if plan == nil || f["destroy_count"].(int) > 0 {
			return model.Irreversible, f, nil
		}
		return model.Deferrable, f, nil
	case "aws":
		svc, _ := args["service"].(string)
		act, _ := args["action"].(string)
		if err := awsNames(svc, act); err != nil {
			return "", nil, err
		}
		f := model.Facts{"service": svc, "aws_action": act, "sensitive_read": c.sensitiveRead(svc, act)}
		if c.ReadProfile == "" {
			f["mutation"] = "unknown (no read-only profile configured)"
			return model.Irreversible, f, nil
		}
		return model.Read, f, nil // provisional: IAM decides in Stage
	}
	return "", nil, fmt.Errorf("unknown cloud operation %s", op)
}

func planFacts(p *Plan) model.Facts {
	f := model.Facts{"has_plan": p != nil, "destroy_count": 0, "destroys": []any{}}
	if p != nil {
		if d, ok := p.Summary["destroys"].([]any); ok {
			f["destroys"], f["destroy_count"] = d, len(d)
		}
	}
	return f
}

type awsErr struct{ Code, Msg string }

func (e *awsErr) Error() string { return e.Code + ": " + e.Msg }

// CallAWS runs one API call with a named profile. Errors carry the AWS error code.
func (c *Connector) CallAWS(profile, service, action string, params map[string]any, dryRun bool) (any, error) {
	args := []string{"--profile", profile, "--output", "json", service, kebab(action)}
	if len(params) > 0 {
		b, _ := json.Marshal(params)
		args = append(args, "--cli-input-json", string(b))
	}
	if dryRun {
		args = append(args, "--dry-run")
	}
	cmd := exec.Command(c.AWSBin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		// documented CLI error format: "An error occurred (Code) when calling the X operation: msg"
		s := errb.String()
		if i := strings.Index(s, "An error occurred ("); i >= 0 {
			rest := s[i+len("An error occurred ("):]
			if j := strings.IndexByte(rest, ')'); j > 0 {
				return nil, &awsErr{Code: rest[:j], Msg: strings.TrimSpace(rest[j+1:])}
			}
		}
		return nil, fmt.Errorf("aws %s %s: %v: %s", service, kebab(action), err, strings.TrimSpace(s))
	}
	var v any
	if out.Len() > 0 && json.Unmarshal(out.Bytes(), &v) != nil {
		v = out.String()
	}
	return v, nil
}

func code(err error) string {
	var e *awsErr
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func leaves(v any, fn func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			leaves(e, fn)
		}
	case []any:
		for _, e := range x {
			leaves(e, fn)
		}
	case string:
		fn(x)
	}
}

func (c *Connector) Stage(t *tx.Tx, a *model.Action) (any, error) {
	if a.Operation == "terraform_plan" {
		return c.plan(t, fmt.Sprint(a.Args["dir"]))
	}
	if isCC(a.Operation) {
		return c.stageCC(t, a)
	}
	svc, act := fmt.Sprint(a.Args["service"]), fmt.Sprint(a.Args["action"])
	params, _ := a.Args["params"].(map[string]any)
	return c.tieredRead(t, a, svc, act, params)
}

// tieredRead lets IAM decide what a call is: the view profile may make it (metadata); only
// the read profile may (data: values become sensitive); neither may (a change: deferred).
func (c *Connector) tieredRead(t *tx.Tx, a *model.Action, svc, act string, params map[string]any) (any, error) {
	dataRead := a.Facts["sensitive_read"] == true
	if c.ViewProfile != "" && !dataRead {
		res, err := c.CallAWS(c.ViewProfile, svc, act, params, false)
		if err == nil {
			return res, nil
		}
		if !denied[code(err)] {
			return nil, err
		}
		dataRead = true // view-only refused it: whatever it returns is data, not metadata
	}
	res, err := c.CallAWS(c.ReadProfile, svc, act, params, false)
	if err != nil {
		if !denied[code(err)] {
			return nil, err
		}
		f := model.Facts{"mutation": true, "aws_denied_read_only": code(err)}
		if svc == "ec2" && c.WriteProfile != "" {
			_, derr := c.CallAWS(c.WriteProfile, svc, act, params, true)
			switch code(derr) {
			case "DryRunOperation":
				f["dry_run"] = "would succeed"
			case "UnauthorizedOperation":
				f["dry_run"] = "would be refused (write credentials lack permission)"
			case "":
				// AWS answers a dry run with DryRunOperation or an error, never with success:
				// an endpoint that returns success ignored DryRun, and the call may have run.
				f["dry_run"] = "IGNORED by the endpoint: the call may have been executed; check before approving"
				f["dry_run_ignored"] = true
			default:
				f["dry_run"] = "would fail: " + derr.Error()
			}
		}
		return nil, &model.Defer{Facts: f, Reason: "refused to read-only credentials: this call changes something"}
	}
	if dataRead {
		a.Facts["sensitive_read"] = true
		idx := t.Sensitive()
		leaves(res, func(s string) {
			if len(s) >= idx.MinLen {
				idx.AddValue(s, "aws:"+svc+":"+act)
			}
		})
	}
	return res, nil
}

// StagedPaths is implemented by the workspace connector: what this task has changed.
type StagedPaths interface{ StagedPaths(t *tx.Tx) []string }

func (c *Connector) terraformDir(t *tx.Tx, dir string) (string, error) {
	if c.WorkspaceRoot == "" {
		return "", errors.New("terraform needs a [workspace]: it runs only on committed configuration in it")
	}
	root, err := filepath.EvalSymlinks(c.WorkspaceRoot)
	if err != nil {
		return "", err
	}
	abs := dir
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, dir)
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("no directory %s in the workspace", dir)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the workspace; terraform runs only on the workspace's configuration", dir)
	}
	if fs, err := t.Mgr.Connector("fs"); err == nil {
		if sp, ok := fs.(StagedPaths); ok {
			for _, p := range sp.StagedPaths(t) {
				if rel == "." || p == rel || strings.HasPrefix(p, rel+string(filepath.Separator)) {
					return "", fmt.Errorf("this task changed %s: terraform would run code nobody has accepted yet. "+
						"Commit the change first (a person sees the diff), then plan in a new task", p)
				}
			}
		}
	}
	return abs, nil
}

func (c *Connector) plan(t *tx.Tx, dir string) (any, error) {
	abs, err := c.terraformDir(t, dir)
	if err != nil {
		return nil, err
	}
	dir = abs
	if _, err := exec.LookPath(c.Terraform); err != nil {
		return nil, errors.New("terraform binary not found")
	}
	h := sha256.Sum256([]byte(abs))
	out := filepath.Join(c.StateDir, "plans", t.ID, hex.EncodeToString(h[:8])+".tfplan")
	_ = os.MkdirAll(filepath.Dir(out), 0o700)
	if b, err := exec.Command(c.Terraform, "-chdir="+dir, "plan", "-input=false", "-lock=true", "-out="+out).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("terraform plan failed: %s", lastN(string(b), 2000))
	}
	show, err := exec.Command(c.Terraform, "-chdir="+dir, "show", "-json", out).Output()
	if err != nil {
		return nil, err
	}
	var p map[string]any
	if err := json.Unmarshal(show, &p); err != nil {
		return nil, err
	}
	sum := Summarize(p)
	st := tx.GetState[State](t, c.Name())
	if st.Plans == nil {
		st.Plans = map[string]*Plan{}
	}
	st.Plans[dir] = &Plan{File: out, Summary: sum}
	return sum, nil
}

func lastN(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// Summarize reads Terraform's own action lists.
func Summarize(plan map[string]any) map[string]any {
	create, update, destroy, replace := []any{}, []any{}, []any{}, []any{}
	rcs, _ := plan["resource_changes"].([]any)
	for _, r := range rcs {
		rc, _ := r.(map[string]any)
		ch, _ := rc["change"].(map[string]any)
		acts := map[string]bool{}
		if l, ok := ch["actions"].([]any); ok {
			for _, x := range l {
				acts[fmt.Sprint(x)] = true
			}
		}
		addr := rc["address"]
		switch {
		case acts["delete"] && acts["create"]:
			replace = append(replace, addr)
		case acts["delete"]:
			destroy = append(destroy, addr)
		case acts["create"]:
			create = append(create, addr)
		case acts["update"]:
			update = append(update, addr)
		}
	}
	return map[string]any{"create": create, "update": update, "destroys": append(destroy, replace...), "replace": replace}
}

func (c *Connector) Preview(t *tx.Tx) map[string]any {
	st := tx.PeekState[State](t, c.Name())
	if st == nil || (len(st.Plans) == 0 && len(st.CC) == 0) {
		return nil
	}
	pv := map[string]any{}
	if len(st.Plans) > 0 {
		out := map[string]any{}
		for d, p := range st.Plans {
			out[d] = p.Summary
		}
		pv["terraform"] = out
	}
	if len(st.CC) > 0 {
		var l []any
		for _, ch := range st.CC {
			l = append(l, ccSummary(ch))
		}
		key := "aws_resources"
		if c.Provider != "" && c.Provider != "aws" {
			key = c.Provider + "_resources"
		}
		pv[key] = l
	}
	return pv
}

func (c *Connector) RunDeferred(t *tx.Tx, a *model.Action) (any, error) {
	if a.Operation == "terraform_apply" {
		dir := fmt.Sprint(a.Args["dir"])
		st := tx.GetState[State](t, c.Name())
		p := st.Plans[dir]
		if p == nil {
			return nil, fmt.Errorf("no saved plan for %s; run terraform_plan first", dir)
		}
		if b, err := exec.Command(c.Terraform, "-chdir="+dir, "apply", "-input=false", p.File).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("terraform apply failed: %s", lastN(string(b), 2000))
		}
		return map[string]any{"applied": dir, "summary": p.Summary}, nil
	}
	if isCC(a.Operation) {
		if c.CC == nil {
			return nil, errors.New("AWS resources are not configured")
		}
		return c.runDeferredCC(a)
	}
	if c.WriteProfile == "" {
		return nil, errors.New("no write profile configured for AWS")
	}
	params, _ := a.Args["params"].(map[string]any)
	return c.CallAWS(c.WriteProfile, fmt.Sprint(a.Args["service"]), fmt.Sprint(a.Args["action"]), params, false)
}

// Contained: resource creates and updates are staged until commit, plans are local files
// and reads change nothing; a raw AWS call that changes something is held, never run here.
func (c *Connector) Contained(op string) bool { return op != "terraform_apply" }
