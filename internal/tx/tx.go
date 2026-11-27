// Package tx implements semantic transactions: the unit of preview, commit, rollback
// and undo across every connector.
//
// Commit: gate (budgets, approvals bound to the exact preview) -> prepare (conflict
// checks) -> apply staged connectors in order, each returning an undo record (a failure
// undoes the applied ones) -> outbox (deferrable / approved irreversible effects, with
// idempotency keys, optional delays, bounded retries).
//
// The process that begins a transaction holds an exclusive flock on tx/<id>.lock until
// it reaches a terminal state; only the owner adds actions or commits, and recovery
// only touches transactions whose owner died. Approvals are written by the human's
// process to tx/<id>.approvals.jsonl and verified by the owner.
package tx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"undolayer/internal/model"
	"undolayer/internal/scanner"
	"undolayer/internal/store"
	"undolayer/internal/taint"
)

type OutboxItem struct {
	Action    model.Action `json:"action"`
	Key       string       `json:"idempotency_key"`
	Status    string       `json:"status"` // held scheduled sent failed cancelled dead
	Attempts  int          `json:"attempts"`
	Delay     float64      `json:"delay"`
	ReleaseAt float64      `json:"release_at,omitempty"`
	Result    any          `json:"result,omitempty"`
	Error     string       `json:"error,omitempty"`
}

type CompRecord struct {
	Connector   string          `json:"connector"`
	ActionID    string          `json:"action_id"`
	Kind        string          `json:"kind"`
	Record      json.RawMessage `json:"record"`
	SideEffects []string        `json:"side_effects,omitempty"`
	Done        bool            `json:"done"`
}

type UndoRecord struct {
	Connector string          `json:"connector"`
	Record    json.RawMessage `json:"record"`
	// InFlight: journaled before the connector's commit ran; it may be applied in part.
	InFlight bool `json:"in_flight,omitempty"`
}

type Step struct {
	ActionID  string  `json:"action_id"`
	Connector string  `json:"connector"`
	Status    string  `json:"status"` // about_to_run done failed not_run unknown
	Key       string  `json:"key"`
	TS        float64 `json:"ts"`
	Reason    string  `json:"reason,omitempty"`
}

type Tx struct {
	Mgr           *Manager
	ID            string
	Task          string
	State         model.TxState
	Created       float64
	Actions       []*model.Action
	Outbox        []*OutboxItem
	Compensations []*CompRecord
	UndoRecords   []*UndoRecord
	// AppliedUndo keeps every undo record after it was applied: the before-state of an
	// undone change stays on record (see EvidenceReport).
	AppliedUndo []*UndoRecord
	Steps       []*Step
	Handles     map[string]any
	// AwaitingCommit is set while Commit waits for a reviewer's decision on the whole preview.
	AwaitingCommit *CommitRequest
	// Requester is who asked for the task.
	Requester string
	// Node is the gateway node the task runs on (its node-local resources are there).
	Node string
	// CommittingConnector is set while a connector without write-ahead undo commits.
	CommittingConnector string

	journaled    time.Time // last journal write
	journalDirty bool      // contained calls since then

	mu         sync.Mutex // one operation at a time (public methods only)
	stMu       sync.Mutex // connector state maps
	sensOnce   sync.Once
	conn       map[string]any             // typed connector state
	raw        map[string]json.RawMessage // connector state loaded from disk, decoded on demand
	owner      store.Lock                 // ownership of this transaction, nil when not owned
	sensitive  *taint.Index
	lineage    map[string]string
	fromSQL    map[string]bool // values that came out of database query results
	fromWS     map[string]bool // lines that came out of the workspace (file reads, command output)
	readTokens map[string]bool // addresses (URLs, e-mails, domains) seen in data the agent read
}

// ---------------------------------------------------------------- connector state

// GetState returns the connector's typed state, creating it if needed.
func GetState[T any](t *Tx, name string) *T {
	t.stMu.Lock()
	defer t.stMu.Unlock()
	if v, ok := t.conn[name]; ok {
		return v.(*T)
	}
	s := new(T)
	if raw, ok := t.raw[name]; ok {
		_ = json.Unmarshal(raw, s)
		delete(t.raw, name)
	}
	t.conn[name] = s
	return s
}

// PeekState returns the state only if the connector touched this transaction.
func PeekState[T any](t *Tx, name string) *T {
	if !t.Touched(name) {
		return nil
	}
	return GetState[T](t, name)
}

func (t *Tx) Touched(name string) bool {
	t.stMu.Lock()
	defer t.stMu.Unlock()
	_, a := t.conn[name]
	_, b := t.raw[name]
	return a || b
}

func (t *Tx) touchedNames() []string {
	t.stMu.Lock()
	set := map[string]bool{}
	for k := range t.conn {
		set[k] = true
	}
	for k := range t.raw {
		set[k] = true
	}
	out := []string{}
	for k := range set {
		out = append(out, k)
	}
	t.stMu.Unlock()
	return t.Mgr.CommitOrder(out)
}

// ---------------------------------------------------------------- ownership

func (t *Tx) requireOwner() error {
	if t.owner == nil {
		return &model.NotOwner{Msg: fmt.Sprintf("transaction %s is not owned by this process", t.ID)}
	}
	if h, ok := t.owner.(interface{ Held() bool }); ok && !h.Held() {
		return &model.NotOwner{Msg: fmt.Sprintf("transaction %s: the connection holding its ownership was lost, so another node may have taken it over", t.ID)}
	}
	if disk := t.Mgr.journalState(t.ID); disk != "" && disk != string(t.State) {
		return &model.NotOwner{Msg: fmt.Sprintf("transaction %s is %s in the state store (recovered or changed by another process)", t.ID, disk)}
	}
	return nil
}

// Release drops ownership (what the kernel or the database does when the process dies).
func (t *Tx) Release() {
	if t.owner != nil {
		t.owner.Release()
		t.owner = nil
	}
}

func (t *Tx) Owned() bool { return t.owner != nil }

func (t *Tx) finish() {
	t.Mgr.Journal(t)
	if t.State.Terminal() {
		t.Release()
	}
}

// ---------------------------------------------------------------- sensitivity

func (t *Tx) Sensitive() *taint.Index {
	t.sensOnce.Do(func() {
		idx := taint.New(t.Mgr.Policy.Settings.SensitiveMinLen)
		for _, c := range t.Mgr.ordered() {
			c.ContributeSensitive(t, idx)
		}
		t.sensitive = idx
	})
	return t.sensitive
}

func (t *Tx) redact(v any) any {
	if !t.Mgr.Policy.Settings.RedactResults {
		return v
	}
	r, n := t.Sensitive().Redact(normalize(v))
	if m, ok := r.(map[string]any); ok && n > 0 {
		m["_redacted"] = n
	}
	return r
}

// normalize turns any value into plain JSON shapes (maps, slices, strings, numbers).
func normalize(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return v
	}
	return out
}

// ---------------------------------------------------------------- lineage

func (t *Tx) learnLineage(actionID string, result any) {
	min := t.Mgr.Policy.Settings.LineageMinLen
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case string:
			if len(x) >= min {
				if _, ok := t.lineage[x]; !ok {
					t.lineage[x] = actionID
				}
			}
		}
	}
	walk(normalize(result))
}

func (t *Tx) dependencies(args map[string]any) []string {
	if len(t.lineage) == 0 {
		return nil
	}
	b, _ := json.Marshal(args)
	blob := string(b)
	set := map[string]bool{}
	for v, id := range t.lineage {
		if strings.Contains(blob, v) {
			set[id] = true
		}
	}
	out := []string{}
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- actions

// Call runs one tool call through classify -> policy -> lane.
func (t *Tx) Call(connector, op string, args map[string]any) (any, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.call(connector, op, args)
}

// CallNested is for connectors issuing sub-calls while their own Stage runs (the
// caller already holds the operation lock), e.g. the statements of a SQL script.
func (t *Tx) CallNested(connector, op string, args map[string]any) (any, error) {
	return t.call(connector, op, args)
}

func (t *Tx) call(connector, op string, args map[string]any) (any, error) {
	if args == nil {
		args = map[string]any{}
	}
	if t.State != model.Open {
		return nil, fmt.Errorf("transaction %s is %s", t.ID, t.State)
	}
	if err := t.requireOwner(); err != nil {
		return nil, err
	}
	c, err := t.Mgr.Connector(connector)
	if err != nil {
		return nil, err
	}
	if _, ok := c.Operations()[op]; !ok {
		return nil, fmt.Errorf("%s has no operation %q", connector, op)
	}
	effect, facts, err := c.Classify(t, op, args)
	if err != nil {
		return nil, err
	}
	if facts == nil {
		facts = model.Facts{}
	}
	if shape, _ := facts["query_shape"].(string); shape != "" {
		facts["shape_new"] = !t.Mgr.shapeBook().Known(t.Requester, connector, shape)
	}
	blobB, _ := json.Marshal(args)
	blob := string(blobB)
	labels := t.Sensitive().LabelsIn(blob)
	facts["contains_sensitive"] = len(labels) > 0
	if len(labels) > 0 {
		facts["sensitive_sources"] = labels
	}
	facts["egress"] = c.Egress() && effect != model.Read
	if facts["egress"] == true {
		flagged := t.Sensitive().FlaggedIn(blob)
		for _, f := range scanner.ScanText(blob) {
			flagged = append(flagged, "gitleaks:"+f.RuleID)
		}
		facts["contains_flagged"] = len(flagged) > 0
		if len(flagged) > 0 {
			facts["flagged_by"] = uniq(flagged)
		}
	}
	if dl, ok := facts["destinations"].([]string); ok && len(dl) > 0 {
		var untrusted []string
		req := normDest(t.Task)
		for _, d := range dl {
			if nd := normDest(d); nd == "" || !strings.Contains(req, nd) {
				untrusted = append(untrusted, d)
			}
		}
		facts["destination_untrusted"] = len(untrusted) > 0
		if len(untrusted) > 0 {
			facts["untrusted_destinations"] = untrusted
		}
	}
	if deps := t.dependencies(args); len(deps) > 0 {
		facts["depends_on"] = deps
	}
	if facts["egress"] == true {
		// how much database content this would carry off the box
		n := 0
		for v := range t.fromSQL {
			if strings.Contains(blob, v) {
				n += len(v)
			}
		}
		facts["egress_db_bytes"] = n
		w := 0
		for v := range t.fromWS {
			if strings.Contains(blob, v) {
				w += len(v)
			}
		}
		facts["egress_workspace_bytes"] = w
		// an identical side effect issued again (retry storms, duplicate sends)
		rep := 0
		for _, prev := range t.Actions {
			if prev.Connector == connector && prev.Operation == op && prev.Decision != model.Deny {
				if pb, _ := json.Marshal(prev.Args); string(pb) == blob {
					rep++
				}
			}
		}
		facts["repeats"] = rep
		content := map[string]any{} // the message itself, not its addressing (that is the destination rule's job)
		skip := map[string]bool{}
		if af, ok := facts["address_fields"].([]string); ok {
			for _, k := range af {
				skip[k] = true
			}
		}
		for k, v := range args {
			if !skip[k] {
				content[k] = v
			}
		}
		cb, _ := json.Marshal(content)
		if addrs := t.untrustedAddresses(string(cb)); len(addrs) > 0 {
			facts["content_untrusted_addresses"] = addrs
		}
	}
	a := &model.Action{ID: model.NewID("act"), TS: model.Now(), Connector: connector, Operation: op,
		Args: args, Effect: effect, Facts: facts}
	pol := t.Mgr.Policy
	pol.Evaluate(a)
	t.Actions = append(t.Actions, a)
	if a.Decision == model.Deny {
		return nil, t.deny(a, false)
	}
	if a.Decision == model.RequireApproval {
		switch d, who := t.awaitDecision(a); d {
		case "approve": // proceeds through its lane now; it no longer needs approval at commit
			a.Decision = model.Allow
			a.Reasons = append(a.Reasons, "[approved during the task by "+who+"]")
		case "decline":
			a.Reasons = append(a.Reasons, "[declined by "+who+"]")
			return nil, t.deny(a, false)
		}
	}
	// Anything that would act on the outside world for real waits for its approval: an
	// eager lane (a charge, an API write) needing approval is held, not run-then-compensated.
	if a.Decision == model.Hold || effect == model.Deferrable || effect == model.Irreversible ||
		(a.Decision == model.RequireApproval && (effect == model.Compensable || (effect == model.Read && c.Egress()))) {
		return t.hold(a), nil
	}
	var step *Step
	contained := false
	if cc, ok := c.(Contained); ok {
		contained = cc.Contained(op)
	}
	if effect != model.Read {
		step = &Step{ActionID: a.ID, Connector: connector, Status: "about_to_run", Key: t.ID + "-" + a.ID, TS: model.Now()}
		t.Steps = append(t.Steps, step)
		if !contained {
			t.Mgr.Journal(t) // intent first: this step can reach the world
		}
	}
	res, err := c.Stage(t, a)
	if err != nil {
		var d *model.Defer
		var pv *model.PolicyViolation
		switch {
		case errors.As(err, &d):
			if step != nil {
				step.Status = "not_run"
			}
			a.Effect = model.Irreversible
			for k, v := range d.Facts {
				a.Facts[k] = v
			}
			pol.Evaluate(a)
			if a.Decision == model.Deny {
				return nil, t.deny(a, false)
			}
			return t.hold(a), nil
		case errors.As(err, &pv):
			t.Mgr.audit("deny", map[string]any{"tx": t.ID, "action": a})
			t.Mgr.Journal(t)
			return nil, err
		default:
			a.Error = err.Error()
			if step != nil {
				step.Status = "failed"
			}
			t.Mgr.audit("error", map[string]any{"tx": t.ID, "action": a})
			t.Mgr.Journal(t)
			return nil, err
		}
	}
	if a.Facts["_reevaluate"] == true {
		delete(a.Facts, "_reevaluate")
		pol.Evaluate(a)
		if a.Decision == model.Deny {
			if !c.Discard(t, a) {
				t.rollbackLocked("post-execution policy denial")
			}
			return nil, t.deny(a, true)
		}
	}
	c.Settle(t, a)
	if s, ok := res.(*Staged); ok {
		if s.Comp != nil {
			rec, _ := json.Marshal(s.Comp.Record)
			t.Compensations = append(t.Compensations, &CompRecord{Connector: connector, ActionID: a.ID,
				Kind: s.Comp.Kind, Record: rec, SideEffects: s.Comp.SideEffects})
		}
		res = s.Result
	}
	if step != nil {
		step.Status = "done"
	}
	t.learnLineage(a.ID, res)
	if effect == model.Read {
		t.learnReadTokens(res)
	}
	if connector == "fs" || connector == "shell" || (effect == model.Read && c.Egress()) {
		var walk func(any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for _, e := range x {
					walk(e)
				}
			case []any:
				for _, e := range x {
					walk(e)
				}
			case string:
				for _, line := range strings.Split(x, "\n") {
					if line = strings.TrimSpace(line); len(line) >= 20 {
						t.fromWS[line] = true
					}
				}
			}
		}
		walk(normalize(res))
	}
	if connector == "sql" {
		var walk func(any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for _, e := range x {
					walk(e)
				}
			case []any:
				for _, e := range x {
					walk(e)
				}
			case string:
				if len(x) >= t.Mgr.Policy.Settings.LineageMinLen {
					t.fromSQL[x] = true
				}
			}
		}
		walk(normalize(res))
	}
	a.Result = t.redact(res)
	t.Mgr.audit("stage", map[string]any{"tx": t.ID, "action": a})
	if contained {
		t.journalSoon()
	} else {
		t.Mgr.Journal(t)
	}
	return a.Result, nil
}

// journalSoon writes the journal if the last write is a second old; otherwise the next
// write (before any escaping effect, a preview, approval, commit or rollback) carries it.
func (t *Tx) journalSoon() {
	if time.Since(t.journaled) >= time.Second {
		t.Mgr.Journal(t)
		return
	}
	if !t.journalDirty { // the agent may go quiet now: write it out within the second anyway
		time.AfterFunc(time.Second, func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.State == model.Open && t.owner != nil {
				t.flushJournal()
			}
		})
	}
	t.journalDirty = true
}

// flushJournal writes pending journal state (other processes read it: reviewers, show).
func (t *Tx) flushJournal() {
	if t.journalDirty {
		t.Mgr.Journal(t)
	}
}

// normDest folds case and drops whitespace and the punctuation people write around
// names, addresses and account numbers ("US12 3456", "#general", "www.x.com").
func normDest(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '#':
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	for _, p := range []string{"https://", "http://", "www."} {
		out = strings.ReplaceAll(out, p, "")
	}
	return strings.TrimRight(out, "/.")
}

func uniq(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		set[s] = true
	}
	out := []string{}
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (t *Tx) deny(a *model.Action, staged bool) error {
	a.Decision = model.Deny
	a.Error = "denied"
	if staged {
		a.Error = "denied after execution; the change was discarded"
	}
	t.Mgr.audit("deny", map[string]any{"tx": t.ID, "action": a})
	t.Mgr.Journal(t)
	return &model.PolicyViolation{Action: a}
}

func (t *Tx) hold(a *model.Action) any {
	h := sha256.Sum256([]byte(t.ID + ":" + a.ID))
	delay, _ := model.Num(a.Facts["delay"])
	t.Outbox = append(t.Outbox, &OutboxItem{Action: *a, Key: hex.EncodeToString(h[:16]), Status: "held", Delay: delay})
	res := map[string]any{"held": true, "action_id": a.ID,
		"note": "Queued: this takes effect when the task is committed. Carry on with the rest of the task; you do not need to wait for it."}
	if a.Decision == model.RequireApproval {
		res["approval_required"] = a.Reasons
		res["note"] = "Held for a human's approval: it will only happen if they approve it. Do not wait and do not try another way; " +
			"finish the rest of the task, and list this action in your final answer as awaiting approval."
	}
	a.Result = res
	t.Mgr.audit("hold", map[string]any{"tx": t.ID, "action": a})
	t.Mgr.Journal(t)
	return res
}

// Cancel removes held actions from an open transaction before commit: a reviewer declining
// part of what the agent asked for. Cancelled actions never run and no longer need approval.
func (t *Tx) Cancel(actionIDs ...string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.State != model.Open {
		return fmt.Errorf("transaction %s is %s", t.ID, t.State)
	}
	want := map[string]bool{}
	for _, id := range actionIDs {
		want[id] = true
	}
	for _, o := range t.Outbox {
		if want[o.Action.ID] && o.Status == "held" {
			o.Status = "cancelled"
			delete(want, o.Action.ID)
		}
	}
	if len(want) > 0 {
		return fmt.Errorf("not held in %s: %v", t.ID, want)
	}
	t.Mgr.audit("cancel", map[string]any{"tx": t.ID, "actions": actionIDs})
	t.Mgr.Journal(t)
	return nil
}

func (t *Tx) cancelled(actionID string) bool {
	for _, o := range t.Outbox {
		if o.Action.ID == actionID {
			return o.Status == "cancelled"
		}
	}
	return false
}

// ---------------------------------------------------------------- preview

func (t *Tx) changes() map[string]any {
	out := map[string]any{}
	for _, name := range t.touchedNames() {
		c, err := t.Mgr.Connector(name)
		if err != nil {
			continue
		}
		if p := c.Preview(t); len(p) > 0 {
			out[name] = p
		}
	}
	return out
}

func (t *Tx) PreviewHash() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.previewHash(t.changes())
}

// PreviewHashNested is PreviewHash for code already holding the operation lock.
func (t *Tx) PreviewHashNested() string { return t.previewHash(t.changes()) }

func (t *Tx) previewHash(changes map[string]any) string {
	ob, ac := []string{}, []string{}
	for _, o := range t.Outbox {
		ob = append(ob, o.Action.ID+":"+o.Status)
	}
	for _, a := range t.Actions {
		ac = append(ac, a.ID)
	}
	b, _ := json.Marshal(map[string]any{"tx": t.ID, "changes": normalize(changes), "outbox": ob, "actions": ac})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (t *Tx) Totals() map[string]float64 {
	tot := map[string]float64{"external_effects": float64(len(t.Outbox) + len(t.Compensations))}
	for _, name := range t.touchedNames() {
		c, err := t.Mgr.Connector(name)
		if err != nil {
			continue
		}
		for k, v := range c.Totals(t) {
			if strings.HasPrefix(k, "max_") {
				if v > tot[k] {
					tot[k] = v
				}
			} else {
				tot[k] += v
			}
		}
	}
	for _, a := range t.Actions {
		if a.Decision != model.Deny {
			if f, ok := model.Num(a.Facts["amount_cents"]); ok {
				tot["spend_cents"] += f
			}
		}
	}
	return tot
}

func (t *Tx) Preview() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flushJournal() // a reviewer's process computes the same preview from the journal
	return t.preview()
}

func (t *Tx) preview() map[string]any {
	changes := t.changes()
	totals := t.Totals()
	needSet := map[string]bool{}
	for _, a := range t.Actions {
		if a.Decision == model.RequireApproval && !t.cancelled(a.ID) {
			for _, r := range a.Reasons {
				needSet[r] = true
			}
		}
	}
	reasons := []string{}
	for r := range needSet {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	reasons = append(reasons, t.Mgr.Policy.CheckBudget(totals)...)
	held, denied := []any{}, []any{}
	for _, o := range t.Outbox {
		if o.Status == "held" {
			held = append(held, o.Action)
		}
	}
	for _, a := range t.Actions {
		if a.Decision == model.Deny {
			denied = append(denied, a)
		}
	}
	hash := t.previewHash(changes)
	need := len(reasons) > 0 || t.Mgr.Policy.Settings.RequireApprovalForCommit
	pv := map[string]any{"tx": t.ID, "task": t.Task, "state": string(t.State), "changes": changes,
		"held_effects": held, "compensable_effects": len(t.Compensations), "totals": totals,
		"approval_required": need, "approval_reasons": reasons, "denied": denied,
		"secret_scanner": t.Sensitive().Scanner}
	pv["approved"] = need && t.approved(hash)
	out := pv
	if t.Mgr.Policy.Settings.RedactResults {
		r, _ := t.Sensitive().Redact(normalize(pv))
		out = r.(map[string]any)
	}
	out["preview_hash"] = hash
	return out
}

// ---------------------------------------------------------------- approval

// Approve is called by the human's process; it needs no ownership, the owner verifies.
func (t *Tx) Approve(approver, token string) error {
	h := t.PreviewHash()
	if token != t.Mgr.ApprovalToken(t.ID, h) {
		return errors.New("invalid approval token (wrong key, or the transaction changed since preview)")
	}
	if err := t.Mgr.addApproval(t.ID, map[string]any{"approver": approver, "preview_hash": h, "token": token, "ts": model.Now()}); err != nil {
		return err
	}
	t.Mgr.audit("approve", map[string]any{"tx": t.ID, "approver": approver, "preview_hash": h})
	t.Mgr.recordEvidence(t, "commit", h, "approve", approver, t.Preview())
	return nil
}

func (t *Tx) approved(h string) bool {
	if t.Mgr.Review.Enabled() {
		return t.commitOutcome(h, 0).Approved
	}
	good := t.Mgr.ApprovalToken(t.ID, h)
	for _, a := range t.Mgr.approvals(t.ID) {
		if a["preview_hash"] == h && a["token"] == good {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- commit

type CommitResult struct {
	Tx      string         `json:"tx"`
	State   model.TxState  `json:"state"`
	Applied []string       `json:"applied"`
	Outbox  []OutboxReport `json:"outbox"`
}

type OutboxReport struct {
	ActionID  string  `json:"action_id"`
	Status    string  `json:"status"`
	ReleaseAt float64 `json:"release_at,omitempty"`
	Error     string  `json:"error,omitempty"`
}

func (t *Tx) Commit() (*CommitResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.State != model.Open {
		return nil, fmt.Errorf("transaction %s is %s", t.ID, t.State)
	}
	if err := t.requireOwner(); err != nil {
		return nil, err
	}
	t.flushJournal() // what reviewers see is exactly what is about to be judged
	pv := t.preview()
	hash := pv["preview_hash"].(string)
	if pv["approval_required"] == true && !t.approved(hash) {
		var reasons []string
		switch rs := pv["approval_reasons"].(type) {
		case []string:
			reasons = rs
		case []any:
			for _, r := range rs {
				reasons = append(reasons, fmt.Sprint(r))
			}
		}
		d, who := t.awaitCommitDecision(hash, reasons)
		if d == "decline" {
			return nil, &model.ApprovalRequired{Msg: fmt.Sprintf("transaction %s was declined by %s: %v. Roll it back, or change it and ask again",
				t.ID, who, reasons)}
		}
		if d != "approve" {
			return nil, &model.ApprovalRequired{Msg: fmt.Sprintf("transaction %s needs human approval: %v. Run: undolayer approve %s",
				t.ID, reasons, t.ID)}
		}
	}
	order := t.touchedNames()
	for _, name := range order {
		c, _ := t.Mgr.Connector(name)
		if err := c.Prepare(t); err != nil {
			var cc *model.CommitConflict
			if errors.As(err, &cc) {
				t.Mgr.audit("conflict", map[string]any{"tx": t.ID, "error": err.Error()})
				t.rollbackLocked("conflict: " + err.Error())
				return nil, err
			}
			t.rollbackLocked("prepare failed: " + err.Error())
			return nil, err
		}
	}
	t.State = model.Prepared
	t.Mgr.Journal(t)
	t.State = model.Committing
	t.Mgr.Journal(t)
	applied := []string{}
	// intents stored in the vault for connectors that have not applied yet: settled as
	// failed if the commit fails before they are applied
	pendingVault := map[string]string{}
	fail := func(err error) (*CommitResult, error) {
		t.Mgr.audit("commit_failed", map[string]any{"tx": t.ID, "error": err.Error(), "applied": applied})
		for name, batch := range pendingVault {
			t.vaultSettle(name, "failed", batch, nil, nil)
		}
		errs := t.undoApplied()
		for _, n := range order {
			if !contains(applied, n) {
				cc, _ := t.Mgr.Connector(n)
				if e := cc.Rollback(t); e != nil {
					errs = append(errs, e.Error())
				}
			}
		}
		errs = append(errs, t.runCompensations()...)
		for _, o := range t.Outbox {
			if o.Status == "held" {
				o.Status = "cancelled"
			}
		}
		t.State = model.RolledBack
		if len(errs) > 0 {
			t.State = model.Failed
		}
		t.finish()
		msg := "commit failed and was reverted: " + err.Error()
		if len(errs) > 0 {
			msg += "; revert errors: " + strings.Join(errs, "; ")
		}
		return nil, errors.New(msg)
	}
	for _, name := range order {
		c, _ := t.Mgr.Connector(name)
		var intent *UndoRecord
		if ic, ok := c.(Intender); ok { // write-ahead: the way back is durable before anything changes
			rec0, err := ic.Intent(t)
			if err != nil {
				return fail(fmt.Errorf("preparing the undo record for %s: %v", name, err))
			}
			if rec0 != nil {
				raw, _ := json.Marshal(rec0)
				intent = &UndoRecord{Connector: name, Record: raw, InFlight: true}
				t.UndoRecords = append(t.UndoRecords, intent)
			}
		} else {
			t.CommittingConnector = name // a crash now leaves this connector's state unknown
		}
		// the before state goes to the vault first: no quorum, no change
		vaultBatch := ""
		var vaulted json.RawMessage // the intent exactly as the vault holds it
		if intent != nil && t.Mgr.Vault != nil {
			e, err := t.vaultEntry(name, "intent", "", intent.Record)
			if err != nil {
				return fail(fmt.Errorf("%s: %v; nothing was changed", name, err))
			}
			rc, err := t.vaultAppend(e)
			if err != nil {
				return fail(fmt.Errorf("%s: the vault could not store the before state, so the change was not made: %v", name, err))
			}
			vaultBatch, vaulted = rc.Batch, intent.Record
			pendingVault[name] = vaultBatch
		}
		if err := t.Mgr.journal(t); err != nil {
			return fail(fmt.Errorf("%s: the journal could not be written, so the change was not made: %v", name, err))
		}
		rec, err := c.Commit(t)
		t.CommittingConnector = ""
		if err != nil {
			return fail(err)
		}
		delete(pendingVault, name)
		applied = append(applied, name)
		switch {
		case rec != nil && intent != nil: // the precise record replaces the intent
			raw, _ := json.Marshal(rec)
			intent.Record, intent.InFlight = raw, false
		case rec != nil:
			raw, _ := json.Marshal(rec)
			t.UndoRecords = append(t.UndoRecords, &UndoRecord{Connector: name, Record: raw})
		case intent != nil: // nothing to undo after all
			t.UndoRecords = t.UndoRecords[:len(t.UndoRecords)-1]
		}
		switch {
		case vaultBatch != "":
			var final json.RawMessage
			if rec != nil {
				final, _ = json.Marshal(rec)
			}
			t.vaultSettle(name, "committed", vaultBatch, vaulted, final)
		case rec != nil && t.Mgr.Vault != nil:
			// no write-ahead record from this connector: its record exists only now
			raw, _ := json.Marshal(rec)
			if e, err := t.vaultEntry(name, "committed", "", raw); err == nil {
				if _, err := t.vaultAppend(e); err != nil {
					fmt.Fprintf(os.Stderr, "undolayer: vault: %s %s: %v\n", t.ID, name, err)
				}
			}
		}
		t.Mgr.Journal(t)
	}
	t.State = model.Committed
	t.Mgr.Journal(t)
	t.Mgr.audit("commit", map[string]any{"tx": t.ID, "preview_hash": hash, "undo_records": len(t.UndoRecords)})
	t.learnShapes()
	rep := t.flushOutbox(0)
	t.finish()
	return &CommitResult{Tx: t.ID, State: t.State, Applied: applied, Outbox: rep}, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// FlushOutbox releases held effects; delayed ones are scheduled and released once due.
func (t *Tx) FlushOutbox(now float64) []OutboxReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.flushOutbox(now)
}

func (t *Tx) flushOutbox(now float64) []OutboxReport {
	if now == 0 {
		now = model.Now()
	}
	rep := []OutboxReport{}
	maxAttempts := t.Mgr.Policy.Settings.MaxEffectAttempts
	for _, item := range t.Outbox {
		switch item.Status {
		case "sent", "cancelled", "dead":
			continue
		}
		if item.Status == "failed" && item.Attempts >= maxAttempts {
			item.Status = "dead"
			t.Mgr.audit("effect_dead", map[string]any{"tx": t.ID, "action_id": item.Action.ID})
			continue
		}
		if item.Delay > 0 && item.Status == "held" {
			item.Status, item.ReleaseAt = "scheduled", now+item.Delay
		}
		if item.Status == "scheduled" && item.ReleaseAt > now {
			rep = append(rep, OutboxReport{ActionID: item.Action.ID, Status: "scheduled", ReleaseAt: item.ReleaseAt})
			continue
		}
		c, err := t.Mgr.Connector(item.Action.Connector)
		a := item.Action
		a.Facts = model.Facts{}
		for k, v := range item.Action.Facts {
			a.Facts[k] = v
		}
		a.Facts["idempotency_key"] = item.Key
		for i := 0; i < 3 && err == nil; i++ {
			item.Attempts++
			var res any
			res, err = c.RunDeferred(t, &a)
			if err == nil {
				if s, ok := res.(*Staged); ok {
					if s.Comp != nil {
						raw, _ := json.Marshal(s.Comp.Record)
						t.Compensations = append(t.Compensations, &CompRecord{Connector: a.Connector, ActionID: a.ID,
							Kind: s.Comp.Kind, Record: raw, SideEffects: s.Comp.SideEffects})
					}
					res = s.Result
				}
				item.Result, item.Status, item.Error = normalize(res), "sent", ""
				t.Mgr.audit("effect_sent", map[string]any{"tx": t.ID, "action_id": a.ID, "idempotency_key": item.Key})
				break
			}
			item.Status, item.Error = "failed", err.Error()
			t.Mgr.audit("effect_failed", map[string]any{"tx": t.ID, "action_id": a.ID, "error": item.Error, "attempt": item.Attempts})
			if i < 2 {
				time.Sleep(time.Duration(50*(1<<item.Attempts)) * time.Millisecond)
				err = nil
			}
		}
		if err != nil && item.Status != "failed" {
			item.Status, item.Error = "failed", err.Error()
		}
		r := OutboxReport{ActionID: a.ID, Status: item.Status}
		if item.Status != "sent" {
			r.Error = item.Error
		}
		rep = append(rep, r)
		t.Mgr.Journal(t)
	}
	return rep
}

// ---------------------------------------------------------------- rollback

type RollbackResult struct {
	Tx        string        `json:"tx"`
	State     model.TxState `json:"state"`
	Errors    []string      `json:"errors"`
	Cancelled int           `json:"cancelled_effects"`
}

func (t *Tx) Rollback(reason string) (*RollbackResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.State.Terminal() {
		return &RollbackResult{Tx: t.ID, State: t.State}, nil
	}
	if err := t.requireOwner(); err != nil {
		return nil, err
	}
	return t.rollbackLocked(reason), nil
}

func (t *Tx) rollbackLocked(reason string) *RollbackResult {
	t.State = model.RollingBack
	t.Mgr.Journal(t)
	errs := []string{}
	names := t.touchedNames()
	for i := len(names) - 1; i >= 0; i-- {
		c, _ := t.Mgr.Connector(names[i])
		if err := c.Rollback(t); err != nil {
			errs = append(errs, err.Error())
		}
	}
	n := 0
	for _, o := range t.Outbox {
		if o.Status == "held" {
			o.Status = "cancelled"
		}
		if o.Status == "cancelled" {
			n++
		}
	}
	errs = append(errs, t.runCompensations()...)
	t.State = model.RolledBack
	if len(errs) > 0 {
		t.State = model.Failed
	}
	t.Mgr.audit("rollback", map[string]any{"tx": t.ID, "reason": reason, "errors": errs})
	t.finish()
	return &RollbackResult{Tx: t.ID, State: t.State, Errors: errs, Cancelled: n}
}

func (t *Tx) runCompensations() []string {
	errs := []string{}
	for i := len(t.Compensations) - 1; i >= 0; i-- {
		comp := t.Compensations[i]
		if comp.Done {
			continue
		}
		c, err := t.Mgr.Connector(comp.Connector)
		if err == nil {
			err = c.Compensate(comp.Record)
		}
		comp.Done = err == nil
		if err != nil {
			errs = append(errs, err.Error())
		}
		t.Mgr.audit("compensate", map[string]any{"tx": t.ID, "action_id": comp.ActionID, "ok": comp.Done})
	}
	return errs
}

func (t *Tx) undoApplied() []string {
	errs := []string{}
	var remaining []*UndoRecord
	for i := len(t.UndoRecords) - 1; i >= 0; i-- {
		r := t.UndoRecords[i]
		c, err := t.Mgr.Connector(r.Connector)
		if err == nil {
			if ic, ok := c.(Intender); ok && r.InFlight {
				err = ic.UndoInFlight(r.Record)
			} else {
				err = c.Undo(r.Record)
			}
		}
		if err == nil {
			t.AppliedUndo = append(t.AppliedUndo, r)
		}
		if err != nil {
			errs = append(errs, err.Error())
			remaining = append([]*UndoRecord{r}, remaining...)
		}
	}
	t.UndoRecords = remaining
	if t.CommittingConnector != "" {
		errs = append(errs, t.CommittingConnector+" was committing when the process stopped and records no write-ahead "+
			"undo: its state is unknown and must be checked by hand")
	}
	return errs
}

// ---------------------------------------------------------------- undo after commit

type UndoReport struct {
	Tx          string           `json:"tx"`
	State       model.TxState    `json:"state"`
	Undone      []string         `json:"undone"`
	Compensated []string         `json:"compensated"`
	Cancelled   []string         `json:"cancelled"`
	Conflicts   []map[string]any `json:"conflicts"`
	Expired     []map[string]any `json:"expired"`
	FailedParts []map[string]any `json:"failed"`
	NotUndoable []map[string]any `json:"not_undoable"`
	Warnings    []string         `json:"warnings"`
}

func (r *UndoReport) Clean() bool {
	return len(r.Conflicts) == 0 && len(r.Expired) == 0 && len(r.FailedParts) == 0
}

// Undo reverts a committed transaction, or one step and the steps that used its output.
// Every part is attempted; the report says exactly what happened to each.
func (t *Tx) Undo(step string) (*UndoReport, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.State != model.Committed {
		return nil, fmt.Errorf("only committed transactions can be undone (state=%s)", t.State)
	}
	if t.owner == nil && !t.Mgr.TryOwn(t) {
		return nil, &model.NotOwner{Msg: "transaction " + t.ID + " is being handled by another process"}
	}
	var targets map[string]bool
	if step != "" {
		var err error
		if targets, err = t.closure(step); err != nil {
			return nil, err
		}
	}
	in := func(id string) bool { return targets == nil || targets[id] }
	rep := &UndoReport{Tx: t.ID, Undone: []string{}, Compensated: []string{}, Cancelled: []string{},
		Conflicts: []map[string]any{}, Expired: []map[string]any{}, FailedParts: []map[string]any{},
		NotUndoable: []map[string]any{}, Warnings: []string{}}
	for _, o := range t.Outbox {
		if (o.Status == "held" || o.Status == "scheduled" || o.Status == "failed") && in(o.Action.ID) {
			o.Status = "cancelled"
			rep.Cancelled = append(rep.Cancelled, o.Action.ID)
		}
	}
	for i := len(t.Compensations) - 1; i >= 0; i-- {
		comp := t.Compensations[i]
		if comp.Done || !in(comp.ActionID) {
			continue
		}
		c, err := t.Mgr.Connector(comp.Connector)
		if err == nil {
			err = c.Compensate(comp.Record)
		}
		var cc *model.CommitConflict
		var nu *model.NotUndoable
		switch {
		case err == nil:
			comp.Done = true
			if comp.Kind == "reversible" {
				rep.Undone = append(rep.Undone, comp.ActionID)
			} else {
				rep.Compensated = append(rep.Compensated, comp.ActionID)
			}
		case errors.As(err, &cc):
			rep.Conflicts = append(rep.Conflicts, map[string]any{"action_id": comp.ActionID, "reason": err.Error()})
		case errors.As(err, &nu):
			rep.Expired = append(rep.Expired, map[string]any{"action_id": comp.ActionID, "reason": err.Error()})
		default:
			rep.FailedParts = append(rep.FailedParts, map[string]any{"action_id": comp.ActionID, "reason": err.Error()})
		}
		t.Mgr.audit("compensate", map[string]any{"tx": t.ID, "action_id": comp.ActionID, "ok": comp.Done})
	}
	if targets == nil {
		var remaining []*UndoRecord
		for i := len(t.UndoRecords) - 1; i >= 0; i-- {
			r := t.UndoRecords[i]
			c, err := t.Mgr.Connector(r.Connector)
			if err == nil {
				err = c.Undo(r.Record)
			}
			var cc *model.CommitConflict
			switch {
			case err == nil:
				rep.Undone = append(rep.Undone, r.Connector)
				t.AppliedUndo = append(t.AppliedUndo, r)
			case errors.As(err, &cc):
				rep.Conflicts = append(rep.Conflicts, map[string]any{"connector": r.Connector, "reason": err.Error()})
				remaining = append([]*UndoRecord{r}, remaining...)
			default:
				rep.FailedParts = append(rep.FailedParts, map[string]any{"connector": r.Connector, "reason": err.Error()})
				remaining = append([]*UndoRecord{r}, remaining...)
			}
		}
		t.UndoRecords = remaining
	} else if len(t.UndoRecords) > 0 {
		rep.Warnings = append(rep.Warnings, "staged stores (sql/fs/git) are undone only with the whole transaction")
	}
	compensated := map[string]bool{}
	for _, c := range t.Compensations {
		compensated[c.ActionID] = true
		if c.Done && in(c.ActionID) {
			for _, fx := range c.SideEffects {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s.%s: side effect '%s' cannot be taken back",
					c.Connector, t.actionOp(c.ActionID), fx))
			}
		}
	}
	for _, o := range t.Outbox {
		if o.Status == "sent" && in(o.Action.ID) && !compensated[o.Action.ID] {
			rep.NotUndoable = append(rep.NotUndoable, map[string]any{"action_id": o.Action.ID,
				"connector": o.Action.Connector, "operation": o.Action.Operation, "args": o.Action.Args})
		}
	}
	if targets != nil {
		for _, a := range t.Actions {
			if !targets[a.ID] {
				for _, d := range depends(a) {
					if targets[d] {
						rep.Warnings = append(rep.Warnings, fmt.Sprintf("step %s (%s.%s) used output of an undone step", a.ID, a.Connector, a.Operation))
					}
				}
			}
		}
	}
	if targets == nil {
		t.State = model.Undone
		if !rep.Clean() {
			t.State = model.Failed
		}
	}
	rep.State = t.State
	t.Mgr.audit("undo", map[string]any{"tx": t.ID, "step": step, "clean": rep.Clean()})
	t.finish()
	if targets == nil {
		t.Release()
	}
	return rep, nil
}

func (t *Tx) actionOp(id string) string {
	for _, a := range t.Actions {
		if a.ID == id {
			return a.Operation
		}
	}
	return "?"
}

func depends(a *model.Action) []string {
	var out []string
	switch d := a.Facts["depends_on"].(type) {
	case []string:
		out = d
	case []any:
		for _, x := range d {
			out = append(out, fmt.Sprint(x))
		}
	}
	return out
}

func (t *Tx) closure(step string) (map[string]bool, error) {
	found := false
	for _, a := range t.Actions {
		found = found || a.ID == step
	}
	if !found {
		return nil, fmt.Errorf("no step %s in %s", step, t.ID)
	}
	out := map[string]bool{step: true}
	for _, a := range t.Actions {
		for _, d := range depends(a) {
			if out[d] {
				out[a.ID] = true
			}
		}
	}
	return out, nil
}

// reconcileSteps: after a crash, ask the real system whether in-flight steps happened.
func (t *Tx) reconcileSteps() []Step {
	unknown := []Step{}
	for _, s := range t.Steps {
		if s.Status != "about_to_run" {
			continue
		}
		var a *model.Action
		for _, x := range t.Actions {
			if x.ID == s.ActionID {
				a = x
			}
		}
		c, _ := t.Mgr.Connector(s.Connector)
		rc, ok := c.(Reconciler)
		if a == nil || !ok {
			s.Status = "unknown"
			unknown = append(unknown, *s)
			continue
		}
		res, err := rc.Reconcile(t, a, s.Key)
		if err != nil {
			s.Status, s.Reason = "unknown", err.Error()
			unknown = append(unknown, *s)
			continue
		}
		s.Status, s.Reason = res.Status, res.Reason
		if res.Comp != nil {
			raw, _ := json.Marshal(res.Comp.Record)
			t.Compensations = append(t.Compensations, &CompRecord{Connector: s.Connector, ActionID: a.ID,
				Kind: res.Comp.Kind, Record: raw, SideEffects: res.Comp.SideEffects})
		}
		if res.Status == "unknown" {
			unknown = append(unknown, *s)
		}
	}
	t.Mgr.Journal(t)
	return unknown
}

// ---------------------------------------------------------------- journal form

type journalForm struct {
	ID            string                     `json:"id"`
	Task          string                     `json:"task"`
	State         model.TxState              `json:"state"`
	Created       float64                    `json:"created"`
	Actions       []*model.Action            `json:"actions"`
	Outbox        []*OutboxItem              `json:"outbox"`
	Compensations []*CompRecord              `json:"compensations"`
	UndoRecords   []*UndoRecord              `json:"undo_records"`
	AppliedUndo   []*UndoRecord              `json:"applied_undo_records,omitempty"`
	Steps         []*Step                    `json:"steps"`
	State2        map[string]json.RawMessage `json:"connector_state"`
	OwnerPID      int                        `json:"owner_pid,omitempty"`
	Awaiting      *CommitRequest             `json:"awaiting_commit,omitempty"`
	Requester     string                     `json:"requester,omitempty"`
	Node          string                     `json:"node,omitempty"`
	Committing    string                     `json:"committing_connector,omitempty"`
}

func (t *Tx) MarshalJSON() ([]byte, error) {
	t.stMu.Lock()
	defer t.stMu.Unlock()
	st := map[string]json.RawMessage{}
	for k, v := range t.raw {
		st[k] = v
	}
	for k, v := range t.conn {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		st[k] = b
	}
	f := journalForm{ID: t.ID, Task: t.Task, State: t.State, Created: t.Created, Actions: t.Actions, Outbox: t.Outbox,
		Compensations: t.Compensations, UndoRecords: t.UndoRecords, AppliedUndo: t.AppliedUndo, Steps: t.Steps, State2: st, Awaiting: t.AwaitingCommit, Requester: t.Requester,
		Committing: t.CommittingConnector}
	if t.owner != nil {
		f.OwnerPID, f.Node = os.Getpid(), t.Mgr.Node
	}
	if f.Node == "" {
		f.Node = t.Node
	}
	return json.Marshal(f)
}

func fromJournal(m *Manager, b []byte) (*Tx, error) {
	var f journalForm
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	t := newTx(m, f.Task, f.ID)
	t.State, t.Created, t.Actions, t.Outbox = f.State, f.Created, f.Actions, f.Outbox
	t.Compensations, t.UndoRecords, t.AppliedUndo, t.Steps = f.Compensations, f.UndoRecords, f.AppliedUndo, f.Steps
	t.AwaitingCommit, t.Requester, t.Node, t.CommittingConnector = f.Awaiting, f.Requester, f.Node, f.Committing
	if f.State2 != nil {
		t.raw = f.State2
	}
	return t, nil
}

func newTx(m *Manager, task, id string) *Tx {
	if id == "" {
		id = model.NewID("tx")
	}
	return &Tx{Mgr: m, ID: id, Task: task, State: model.Open, Created: model.Now(), Handles: map[string]any{},
		conn: map[string]any{}, raw: map[string]json.RawMessage{}, lineage: map[string]string{},
		fromSQL: map[string]bool{}, fromWS: map[string]bool{}, readTokens: map[string]bool{}}
}
