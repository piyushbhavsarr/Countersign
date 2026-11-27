package cloud

// AWS resources through Cloud Control: one get/list/create/update/delete API across
// hundreds of resource types, each described by its published resource schema. Every
// decision here is read from that schema, never from a list of services:
//
//   - a create is checked against the schema (unknown and read-only properties refused,
//     required ones present) when the agent asks, and runs on commit; undo deletes it;
//   - an update is a JSON Patch; touching a read-only property is refused, and touching a
//     create-only one is refused too (AWS would have to replace the resource: create a
//     new one instead). Undo is a three-way revert of the properties: only what the commit
//     changed is put back, other changes made since are kept;
//   - touching a write-only property (a password, say) cannot be undone, because AWS never
//     returns its old value: that update is irreversible (approval);
//   - a delete is irreversible: whatever the resource held is gone.
//
// A resource type runs in the undoable lane only once `undolayer aws verify` has done a
// real create / update / undo / delete round trip with it, against the current schema;
// until then its creates and updates need approval like any other irreversible action.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"

	"undolayer/internal/model"
	"undolayer/internal/threeway"
	"undolayer/internal/tx"
)

// Schema is the part of a resource schema the runtime uses.
type Schema struct {
	TypeName     string                     `json:"typeName"`
	Properties   map[string]json.RawMessage `json:"properties"`
	Required     []string                   `json:"required"`
	ReadOnly     []string                   `json:"readOnlyProperties"`
	CreateOnly   []string                   `json:"createOnlyProperties"`
	WriteOnly    []string                   `json:"writeOnlyProperties"`
	PrimaryID    []string                   `json:"primaryIdentifier"`
	AdditionalOK *bool                      `json:"additionalProperties"`
	Digest       string                     `json:"-"`
}

func ParseSchema(raw []byte) (*Schema, error) {
	var s Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("resource schema: %v", err)
	}
	if s.TypeName == "" || len(s.Properties) == 0 {
		return nil, errors.New("resource schema has no typeName or properties")
	}
	h := sha256.Sum256(raw)
	s.Digest = hex.EncodeToString(h[:])
	return &s, nil
}

// Resources is the Cloud Control API (the real one runs the AWS CLI; tests may use another).
type Resources interface {
	Schema(typeName string) (*Schema, error)
	Get(typeName, id string) (map[string]any, error) // the resource's properties; nil if it does not exist
	List(typeName string) (any, error)
	// Create returns the identifier. clientToken makes it idempotent: the same token returns
	// the resource of the first request instead of creating another (Cloud Control ClientToken).
	Create(typeName string, desired map[string]any, clientToken string) (string, error)
	Update(typeName, id string, patch []byte) error
	Delete(typeName, id string) error
}

// ---------------------------------------------------------------- schema pointers

// pointer turns a patch path or a property path into schema-pointer segments.
// segments splits a schema pointer: schemas point at a resource's properties as
// /properties/<name>/..., and documents hold them at the top level.
func segments(p string) []string {
	p = strings.TrimPrefix(p, "/properties")
	return strings.Split(strings.Trim(p, "/"), "/")
}

// touches: does a change at path p (a JSON Patch path into the document) affect the schema
// pointer sp (either contains the other)?
func touches(p, sp string) bool {
	a, b := strings.Split(strings.Trim(p, "/"), "/"), segments(sp)
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] && a[i] != "*" && b[i] != "*" && !(isIndex(a[i]) && b[i] == "*") {
			return false
		}
	}
	return true
}

func isIndex(s string) bool {
	if s == "" || s == "-" {
		return s == "-"
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func touchedBy(paths []string, pointers []string) []string {
	var out []string
	for _, p := range paths {
		for _, sp := range pointers {
			if touches(p, sp) {
				out = append(out, strings.TrimPrefix(sp, "/properties/"))
				break
			}
		}
	}
	sort.Strings(out)
	return uniqStrings(out)
}

// readOnlyFree removes read-only properties (AWS sets them; they cannot be written).
func (s *Schema) readOnlyFree(props map[string]any) map[string]any {
	out := deep(props)
	for _, ro := range s.ReadOnly {
		segs := segments(ro)
		if len(segs) == 1 {
			delete(out, segs[0])
		}
	}
	return out
}

// ---------------------------------------------------------------- validation

func (s *Schema) validateCreate(desired map[string]any) error {
	var problems []string
	for k := range desired {
		if _, ok := s.Properties[k]; !ok && (s.AdditionalOK == nil || !*s.AdditionalOK) {
			problems = append(problems, k+" is not a property of "+s.TypeName)
		}
	}
	for _, ro := range s.ReadOnly {
		if segs := segments(ro); len(segs) == 1 {
			if _, ok := desired[segs[0]]; ok {
				problems = append(problems, segs[0]+" is read-only (the cloud sets it)")
			}
		}
	}
	for _, r := range s.Required {
		if _, ok := desired[r]; !ok {
			problems = append(problems, r+" is required")
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%s: %s", s.TypeName, strings.Join(problems, "; "))
	}
	return nil
}

type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	From  string `json:"from,omitempty"`
	Value any    `json:"value,omitempty"`
}

// patchPaths returns every path a JSON Patch writes (move writes both ends).
func patchPaths(patch []byte) ([]string, error) {
	var ops []patchOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		return nil, fmt.Errorf("patch must be a JSON Patch (RFC 6902) array: %v", err)
	}
	var out []string
	for _, o := range ops {
		switch o.Op {
		case "add", "remove", "replace", "copy":
			out = append(out, o.Path)
		case "move":
			out = append(out, o.Path, o.From)
		case "test":
		default:
			return nil, fmt.Errorf("unknown JSON Patch op %q", o.Op)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- verification

type verified map[string]string // type -> schema digest of the round trip that passed

// SharedDocs is where verification results live: the state store, so every node sees them.
type SharedDocs interface {
	Get(name string) ([]byte, error)
	Put(name string, b []byte) error
}

func (c *Connector) verifiedName() string {
	if c.Provider == "" || c.Provider == "aws" {
		return "aws-verified.json"
	}
	return c.Provider + "-verified.json"
}

func (c *Connector) verifiedFile() string { return filepath.Join(c.StateDir, c.verifiedName()) }

func (c *Connector) readVerified() ([]byte, error) {
	if c.Shared != nil {
		return c.Shared.Get(c.verifiedName())
	}
	return os.ReadFile(c.verifiedFile())
}

func (c *Connector) isVerified(s *Schema) bool {
	b, err := c.readVerified()
	if err != nil || b == nil {
		return false
	}
	var v verified
	_ = json.Unmarshal(b, &v)
	return v[s.TypeName] != "" && v[s.TypeName] == s.Digest
}

func (c *Connector) markVerified(s *Schema) error {
	v := verified{}
	if b, err := c.readVerified(); err == nil && b != nil {
		_ = json.Unmarshal(b, &v)
	}
	v[s.TypeName] = s.Digest
	b, _ := json.MarshalIndent(v, "", " ")
	if c.Shared != nil {
		return c.Shared.Put(c.verifiedName(), b)
	}
	return os.WriteFile(c.verifiedFile(), b, 0o600)
}

// ---------------------------------------------------------------- operations

func ccOperations() map[string]tx.OpSchema {
	s := map[string]any{"type": "string"}
	o := map[string]any{"type": "object"}
	return map[string]tx.OpSchema{
		"resource_get": {Description: "Get one AWS resource's properties (Cloud Control), e.g. type=AWS::SQS::Queue.",
			Properties: map[string]any{"type": s, "identifier": s}, Required: []string{"type", "identifier"}},
		"resource_list": {Description: "List AWS resources of a type (Cloud Control).",
			Properties: map[string]any{"type": s}, Required: []string{"type"}},
		"resource_create": {Description: "Create an AWS resource from its properties. Checked against the type's schema now; " +
			"created on commit; undo deletes it.", Properties: map[string]any{"type": s, "desired_state": o},
			Required: []string{"type", "desired_state"}},
		"resource_update": {Description: "Update an AWS resource with a JSON Patch (RFC 6902) over its properties, e.g. " +
			"[{\"op\":\"replace\",\"path\":\"/VisibilityTimeout\",\"value\":60}]. Applied on commit; undo reverts only these fields.",
			Properties: map[string]any{"type": s, "identifier": s, "patch": map[string]any{"type": "array"}},
			Required:   []string{"type", "identifier", "patch"}},
		"resource_delete": {Description: "Delete an AWS resource. Cannot be undone (its contents are gone): needs approval.",
			Properties: map[string]any{"type": s, "identifier": s}, Required: []string{"type", "identifier"}},
	}
}

func isCC(op string) bool { return strings.HasPrefix(op, "resource_") }

func (c *Connector) classifyCC(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	typ := str(args["type"])
	f := model.Facts{"resource_type": typ}
	if op == "resource_get" || op == "resource_list" {
		f["sensitive_read"] = false // decided by IAM when it runs
		return model.Read, f, nil
	}
	if c.CC == nil {
		return "", nil, errors.New("AWS resources need [aws] profiles")
	}
	sch, err := c.CC.Schema(typ)
	if err != nil {
		return "", nil, err
	}
	f["undo_verified"] = c.isVerified(sch)
	if ex := exposure(args["desired_state"], "", nil); len(ex) > 0 {
		f["public_exposure"] = ex
	}
	if ps, ok := args["patch"].([]any); ok {
		var ex []string
		for _, p := range ps {
			if m, ok := p.(map[string]any); ok {
				ex = exposure(m["value"], str(m["path"]), ex)
			}
		}
		if len(ex) > 0 {
			f["public_exposure"] = ex
		}
	}
	switch op {
	case "resource_delete":
		f["destroys_resource"] = true
		return model.Irreversible, f, nil
	case "resource_create":
		desired, _ := args["desired_state"].(map[string]any)
		if err := sch.validateCreate(desired); err != nil {
			return "", nil, err
		}
	case "resource_update":
		patch, err := json.Marshal(args["patch"])
		if err != nil {
			return "", nil, err
		}
		paths, err := patchPaths(patch)
		if err != nil {
			return "", nil, err
		}
		if ro := touchedBy(paths, sch.ReadOnly); len(ro) > 0 {
			return "", nil, fmt.Errorf("%s: %s is read-only (AWS sets it)", typ, strings.Join(ro, ", "))
		}
		if co := touchedBy(paths, sch.CreateOnly); len(co) > 0 {
			return "", nil, fmt.Errorf("%s: %s can only be set when the resource is created; changing it means a new "+
				"resource, so create one instead", typ, strings.Join(co, ", "))
		}
		f["changed_properties"] = paths
		if wo := touchedBy(paths, sch.WriteOnly); len(wo) > 0 {
			f["changes_write_only"] = wo // AWS never returns the old value: no way back
			return model.Irreversible, f, nil
		}
	}
	if f["undo_verified"] != true {
		return model.Irreversible, f, nil
	}
	return model.Reversible, f, nil
}

// ccChange is one staged create or update.
type ccChange struct {
	Op       string          `json:"op"`
	Type     string          `json:"type"`
	ID       string          `json:"id,omitempty"`
	Desired  map[string]any  `json:"desired,omitempty"`
	Patch    json.RawMessage `json:"patch,omitempty"`
	Before   map[string]any  `json:"before,omitempty"`
	Expected map[string]any  `json:"expected,omitempty"` // before with the patch applied
	ActionID string          `json:"action_id"`
}

func (c *Connector) stageCC(t *tx.Tx, a *model.Action) (any, error) {
	typ := str(a.Args["type"])
	switch a.Operation {
	case "resource_get":
		return c.readCC(t, a, "GetResource", map[string]any{"TypeName": typ, "Identifier": str(a.Args["identifier"])})
	case "resource_list":
		return c.readCC(t, a, "ListResources", map[string]any{"TypeName": typ})
	}
	ch := &ccChange{Op: a.Operation, Type: typ, ID: str(a.Args["identifier"]), ActionID: a.ID}
	switch a.Operation {
	case "resource_create":
		ch.Desired, _ = a.Args["desired_state"].(map[string]any)
	case "resource_update":
		before, err := c.CC.Get(typ, ch.ID)
		if err != nil {
			return nil, err
		}
		if before == nil {
			return nil, fmt.Errorf("%s %s does not exist", typ, ch.ID)
		}
		patch, _ := json.Marshal(a.Args["patch"])
		// a property the cloud does not return (a password, a key) has no old value to put
		// back: replacing or removing one cannot be undone
		var ops []patchOp
		_ = json.Unmarshal(patch, &ops)
		var hidden []string
		for _, o := range ops {
			if o.Op == "replace" || o.Op == "remove" {
				if _, ok := threeway.Get(before, pathOf(o.Path)); !ok {
					hidden = append(hidden, o.Path)
				}
			}
		}
		if len(hidden) > 0 && a.Effect != model.Irreversible {
			return nil, &model.Defer{Facts: model.Facts{"changes_write_only": hidden},
				Reason: "the cloud does not return " + strings.Join(hidden, ", ") + ", so its old value cannot be put back"}
		}
		exp, err := applyPatch(before, patch)
		if err != nil {
			return nil, fmt.Errorf("the patch does not apply to %s %s: %v", typ, ch.ID, err)
		}
		ch.Patch, ch.Before, ch.Expected = patch, before, exp
	}
	st := tx.GetState[State](t, c.Name())
	st.CC = append(st.CC, ch)
	return map[string]any{"staged": true, "change": ccSummary(ch)}, nil
}

// readCC reads with the same IAM tiers as the aws operation: what the view-only profile
// may read is metadata; what only the read profile may read is data, and its values are
// treated as secret (a function's environment variables, a connection string, ...).
func (c *Connector) readCC(t *tx.Tx, a *model.Action, action string, params map[string]any) (any, error) {
	if c.Provider != "" && c.Provider != "aws" { // the credential's own permissions decide
		typ, id := str(params["TypeName"]), str(params["Identifier"])
		if action == "ListResources" {
			return c.CC.List(typ)
		}
		props, err := c.CC.Get(typ, id)
		if err != nil {
			return nil, err
		}
		if props == nil {
			return nil, fmt.Errorf("%s %s does not exist", typ, id)
		}
		return map[string]any{"type": typ, "identifier": id, "properties": props}, nil
	}
	if c.ReadProfile == "" {
		return nil, errors.New("AWS resources need [aws] profiles")
	}
	res, err := c.tieredRead(t, a, "cloudcontrol", action, params)
	if err != nil {
		return nil, err
	}
	if action == "GetResource" {
		if props, ok := dig(res, "ResourceDescription", "Properties").(string); ok {
			var m map[string]any
			if json.Unmarshal([]byte(props), &m) == nil {
				return map[string]any{"type": params["TypeName"], "identifier": params["Identifier"], "properties": m}, nil
			}
		}
	}
	return res, nil
}

func ccSummary(ch *ccChange) map[string]any {
	s := map[string]any{"type": ch.Type, "op": ch.Op}
	switch ch.Op {
	case "resource_create":
		s["properties"] = ch.Desired
	case "resource_update":
		s["identifier"] = ch.ID
		var diff []string
		for _, p := range threeway.Changes(ch.Before, ch.Expected) {
			b, _ := threeway.Get(ch.Before, p)
			a, _ := threeway.Get(ch.Expected, p)
			bb, _ := json.Marshal(b)
			ab, _ := json.Marshal(a)
			diff = append(diff, fmt.Sprintf("%s: %s -> %s", p, bb, ab))
		}
		s["diff"] = diff
	}
	return s
}

func applyPatch(doc map[string]any, patch []byte) (map[string]any, error) {
	b, _ := json.Marshal(doc)
	p, err := jsonpatch.DecodePatch(patch)
	if err != nil {
		return nil, err
	}
	out, err := p.Apply(b)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(out, &m)
}

// ---------------------------------------------------------------- prepare, commit, undo

func (c *Connector) prepareCC(t *tx.Tx) error {
	st := tx.PeekState[State](t, c.Name())
	if st == nil {
		return nil
	}
	for _, ch := range st.CC {
		if ch.Op != "resource_update" {
			continue
		}
		now, err := c.CC.Get(ch.Type, ch.ID)
		if err != nil {
			return err
		}
		if now == nil {
			return model.Conflict("%s %s was deleted after it was staged; nothing was applied", ch.Type, ch.ID)
		}
		if cs := threeway.Touched(ch.Before, ch.Expected, now); len(cs) > 0 {
			return model.Conflict("%s %s: properties this task changes were changed after staging (%s); nothing was applied",
				ch.Type, ch.ID, describe(cs))
		}
	}
	return nil
}

// CCEntry is the way back for one applied create or update.
type CCEntry struct {
	Op     string         `json:"op"` // created | updated
	Type   string         `json:"type"`
	ID     string         `json:"id"`
	Before map[string]any `json:"before,omitempty"`
	After  map[string]any `json:"after,omitempty"`
}

func (c *Connector) commitCC(t *tx.Tx) ([]CCEntry, error) {
	st := tx.PeekState[State](t, c.Name())
	if st == nil || len(st.CC) == 0 {
		return nil, nil
	}
	var done []CCEntry
	fail := func(err error) ([]CCEntry, error) {
		if uerr := c.undoCC(done, false); uerr != nil {
			return nil, fmt.Errorf("%v; reverting what was applied also failed: %v", err, uerr)
		}
		return nil, err
	}
	for _, ch := range st.CC {
		switch ch.Op {
		case "resource_create":
			id, err := c.CC.Create(ch.Type, ch.Desired, clientToken(t.ID, ch.ActionID))
			if err != nil {
				return fail(fmt.Errorf("creating %s: %v", ch.Type, err))
			}
			after, err := c.CC.Get(ch.Type, id)
			if err != nil {
				return fail(err)
			}
			done = append(done, CCEntry{Op: "created", Type: ch.Type, ID: id, After: after})
		case "resource_update":
			before, err := c.CC.Get(ch.Type, ch.ID)
			if err != nil {
				return fail(err)
			}
			if err := c.CC.Update(ch.Type, ch.ID, ch.Patch); err != nil {
				return fail(fmt.Errorf("updating %s %s: %v", ch.Type, ch.ID, err))
			}
			after, err := c.CC.Get(ch.Type, ch.ID)
			if err != nil {
				return fail(err)
			}
			done = append(done, CCEntry{Op: "updated", Type: ch.Type, ID: ch.ID, Before: before, After: after})
		}
	}
	st.CC = nil
	return done, nil
}

// undoCC reverts newest first. With check, every revert is planned first and nothing is
// written if any conflicts.
func (c *Connector) undoCC(entries []CCEntry, check bool) error {
	type plan struct {
		patch []byte
	}
	plans := make([]plan, len(entries))
	sim := map[string]map[string]any{}
	cur := func(e CCEntry) (map[string]any, error) {
		k := e.Type + "|" + e.ID
		if v, ok := sim[k]; ok {
			return v, nil
		}
		v, err := c.CC.Get(e.Type, e.ID)
		sim[k] = v
		return v, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		now, err := cur(e)
		if err != nil {
			return err
		}
		sch, err := c.CC.Schema(e.Type)
		if err != nil {
			return err
		}
		switch e.Op {
		case "created":
			if now == nil {
				continue
			}
			if cs := threeway.Changes(sch.readOnlyFree(e.After), sch.readOnlyFree(now)); check && len(cs) > 0 {
				return model.Conflict("%s %s was changed after this task created it (%s); refusing to delete it",
					e.Type, e.ID, pathList(cs))
			}
			sim[e.Type+"|"+e.ID] = nil
		case "updated":
			if now == nil {
				return model.Conflict("%s %s was deleted after commit; nothing to restore into", e.Type, e.ID)
			}
			b, a, n := sch.readOnlyFree(e.Before), sch.readOnlyFree(e.After), sch.readOnlyFree(now)
			res, cs, err := threeway.Revert(b, a, n)
			if err != nil {
				return model.Conflict("%s %s: %v", e.Type, e.ID, err)
			}
			if len(cs) > 0 {
				return model.Conflict("%s %s: properties this commit changed were changed again since (%s)", e.Type, e.ID, describe(cs))
			}
			rm, _ := res.(map[string]any)
			plans[i].patch = patchFrom(n, rm)
			merged := deep(now)
			for k, v := range rm {
				merged[k] = v
			}
			sim[e.Type+"|"+e.ID] = merged
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		switch e.Op {
		case "created":
			if err := c.CC.Delete(e.Type, e.ID); err != nil {
				return fmt.Errorf("undo: deleting %s %s: %v", e.Type, e.ID, err)
			}
		case "updated":
			if len(plans[i].patch) > 2 { // not "[]"
				if err := c.CC.Update(e.Type, e.ID, plans[i].patch); err != nil {
					return fmt.Errorf("undo: restoring %s %s: %v", e.Type, e.ID, err)
				}
			}
		}
	}
	return nil
}

// patchFrom builds the JSON Patch that turns from into to, one op per changed leaf.
func patchFrom(from, to map[string]any) []byte {
	ops := []patchOp{}
	for _, p := range threeway.Changes(from, to) {
		ptr := pointer(p)
		tv, tok := threeway.Get(to, p)
		_, fok := threeway.Get(from, p)
		switch {
		case !tok:
			ops = append(ops, patchOp{Op: "remove", Path: ptr})
		case !fok:
			ops = append(ops, patchOp{Op: "add", Path: ptr, Value: tv})
		default:
			ops = append(ops, patchOp{Op: "replace", Path: ptr, Value: tv})
		}
	}
	b, _ := json.Marshal(ops)
	return b
}

func pointer(p threeway.Path) string {
	var b strings.Builder
	for _, e := range p {
		b.WriteByte('/')
		s := fmt.Sprint(e)
		s = strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
		b.WriteString(s)
	}
	return b.String()
}

// RunDeferredCC runs an approved irreversible resource change.
func (c *Connector) runDeferredCC(a *model.Action) (any, error) {
	typ, id := str(a.Args["type"]), str(a.Args["identifier"])
	switch a.Operation {
	case "resource_delete":
		return map[string]any{"deleted": id, "undoable": false}, c.CC.Delete(typ, id)
	case "resource_create":
		desired, _ := a.Args["desired_state"].(map[string]any)
		nid, err := c.CC.Create(typ, desired, clientToken("deferred", a.ID))
		return map[string]any{"created": nid, "undoable": false}, err
	case "resource_update":
		patch, _ := json.Marshal(a.Args["patch"])
		return map[string]any{"updated": id, "undoable": false}, c.CC.Update(typ, id, patch)
	}
	return nil, fmt.Errorf("unknown resource operation %s", a.Operation)
}

// clientToken: a deterministic Cloud Control ClientToken (allowed characters only).
func clientToken(txID, actionID string) string {
	h := sha256.Sum256([]byte(txID + "/" + actionID))
	return "ul-" + hex.EncodeToString(h[:16])
}

// Intent: the staged creates and updates, each update with its properties read just
// before commit. It is journaled before anything is sent to AWS.
func (c *Connector) intentCC(t *tx.Tx) (*ccIntent, error) {
	st := tx.PeekState[State](t, c.Name())
	if st == nil || len(st.CC) == 0 || c.CC == nil {
		return nil, nil
	}
	in := &ccIntent{Tx: t.ID}
	for _, ch := range st.CC {
		x := *ch
		if ch.Op == "resource_update" {
			before, err := c.CC.Get(ch.Type, ch.ID)
			if err != nil {
				return nil, err
			}
			x.Before = before
		}
		in.Changes = append(in.Changes, &x)
	}
	return in, nil
}

type ccIntent struct {
	Tx      string      `json:"tx"`
	Changes []*ccChange `json:"changes"`
}

// undoInFlightCC reverts whatever part of an interrupted commit reached AWS.
func (c *Connector) undoInFlightCC(in *ccIntent) error {
	for i := len(in.Changes) - 1; i >= 0; i-- {
		ch := in.Changes[i]
		switch ch.Op {
		case "resource_create":
			// the same token returns the resource of the original request, if it was made
			id, err := c.CC.Create(ch.Type, ch.Desired, clientToken(in.Tx, ch.ActionID))
			if err != nil {
				return fmt.Errorf("finding what the interrupted create made: %v", err)
			}
			if err := c.CC.Delete(ch.Type, id); err != nil {
				return fmt.Errorf("undo: deleting %s %s: %v", ch.Type, id, err)
			}
		case "resource_update":
			now, err := c.CC.Get(ch.Type, ch.ID)
			if err != nil {
				return err
			}
			if now == nil {
				return model.Conflict("%s %s no longer exists", ch.Type, ch.ID)
			}
			sch, err := c.CC.Schema(ch.Type)
			if err != nil {
				return err
			}
			// only the properties the patch wrote go back, and only if they moved
			b, n := sch.readOnlyFree(ch.Before), sch.readOnlyFree(now)
			res, cs, err := threeway.Revert(b, sch.readOnlyFree(ch.Expected), n)
			if err != nil {
				return model.Conflict("%s %s: %v", ch.Type, ch.ID, err)
			}
			if len(cs) > 0 {
				return model.Conflict("%s %s: properties of the interrupted update hold neither their old nor their new value (%s)",
					ch.Type, ch.ID, describe(cs))
			}
			rm, _ := res.(map[string]any)
			if p := patchFrom(n, rm); len(p) > 2 {
				if err := c.CC.Update(ch.Type, ch.ID, p); err != nil {
					return fmt.Errorf("undo: restoring %s %s: %v", ch.Type, ch.ID, err)
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- verify

// Verify does a real round trip with a resource type: create, update, undo the update
// (checking the properties are back), delete. On success the type's current schema is
// recorded as verified, and its creates and updates become undoable.
func (c *Connector) Verify(typ string, desired map[string]any, patch []byte) error {
	sch, err := c.CC.Schema(typ)
	if err != nil {
		return err
	}
	if err := sch.validateCreate(desired); err != nil {
		return err
	}
	paths, err := patchPaths(patch)
	if err != nil {
		return err
	}
	if bad := append(touchedBy(paths, sch.CreateOnly), touchedBy(paths, sch.WriteOnly)...); len(bad) > 0 {
		return fmt.Errorf("verify with a patch that changes ordinary properties (not %s)", strings.Join(bad, ", "))
	}
	id, err := c.CC.Create(typ, desired, clientToken("verify", fmt.Sprint(time.Now().UnixNano())))
	if err != nil {
		return fmt.Errorf("create: %v", err)
	}
	cleanup := func() { _ = c.CC.Delete(typ, id) }
	before, err := c.CC.Get(typ, id)
	if err != nil || before == nil {
		cleanup()
		return fmt.Errorf("read after create: %v", err)
	}
	if err := c.CC.Update(typ, id, patch); err != nil {
		cleanup()
		return fmt.Errorf("update: %v", err)
	}
	after, err := c.CC.Get(typ, id)
	if err != nil {
		cleanup()
		return err
	}
	if len(threeway.Changes(sch.readOnlyFree(before), sch.readOnlyFree(after))) == 0 {
		cleanup()
		return errors.New("the update changed nothing AWS reports back; use a patch with a visible effect")
	}
	if err := c.undoCC([]CCEntry{{Op: "updated", Type: typ, ID: id, Before: before, After: after}}, true); err != nil {
		cleanup()
		return fmt.Errorf("undo: %v", err)
	}
	back, err := c.CC.Get(typ, id)
	if err != nil {
		cleanup()
		return err
	}
	if cs := threeway.Changes(sch.readOnlyFree(before), sch.readOnlyFree(back)); len(cs) > 0 {
		cleanup()
		return fmt.Errorf("undo did not restore the properties: %s differ", pathList(cs))
	}
	if err := c.CC.Delete(typ, id); err != nil {
		return fmt.Errorf("delete: %v", err)
	}
	if gone, err := c.CC.Get(typ, id); err == nil && gone != nil {
		return errors.New("the resource still exists after delete")
	}
	return c.markVerified(sch)
}

// ---------------------------------------------------------------- the AWS CLI implementation

// CLIResources runs Cloud Control through the AWS CLI: reads with the read profile,
// writes with the write profile, waiting for each request to finish.
type CLIResources struct {
	c       *Connector
	Timeout time.Duration
	schemas map[string]*Schema
}

func (r *CLIResources) Schema(typ string) (*Schema, error) {
	if s := r.schemas[typ]; s != nil {
		return s, nil
	}
	res, err := r.c.CallAWS(r.c.ReadProfile, "cloudformation", "DescribeType", map[string]any{"Type": "RESOURCE", "TypeName": typ}, false)
	if err != nil {
		return nil, err
	}
	raw, _ := res.(map[string]any)["Schema"].(string)
	s, err := ParseSchema([]byte(raw))
	if err != nil {
		return nil, err
	}
	if r.schemas == nil {
		r.schemas = map[string]*Schema{}
	}
	r.schemas[typ] = s
	return s, nil
}

func (r *CLIResources) Get(typ, id string) (map[string]any, error) {
	res, err := r.c.CallAWS(r.c.ReadProfile, "cloudcontrol", "GetResource", map[string]any{"TypeName": typ, "Identifier": id}, false)
	if err != nil {
		if code(err) == "ResourceNotFoundException" {
			return nil, nil
		}
		return nil, err
	}
	props, _ := dig(res, "ResourceDescription", "Properties").(string)
	var m map[string]any
	return m, json.Unmarshal([]byte(props), &m)
}

func (r *CLIResources) List(typ string) (any, error) {
	return r.c.CallAWS(r.c.ReadProfile, "cloudcontrol", "ListResources", map[string]any{"TypeName": typ}, false)
}

func (r *CLIResources) write(action string, params map[string]any) (string, error) {
	if r.c.WriteProfile == "" {
		return "", errors.New("no write profile configured for AWS")
	}
	res, err := r.c.CallAWS(r.c.WriteProfile, "cloudcontrol", action, params, false)
	if err != nil {
		return "", err
	}
	ev, _ := dig(res, "ProgressEvent").(map[string]any)
	deadline := time.Now().Add(r.Timeout)
	for {
		switch str(ev["OperationStatus"]) {
		case "SUCCESS":
			return str(ev["Identifier"]), nil
		case "FAILED", "CANCEL_COMPLETE":
			return "", fmt.Errorf("%s %s: %s", str(ev["ErrorCode"]), str(ev["OperationStatus"]), str(ev["StatusMessage"]))
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("%s did not finish within %s (request %s)", action, r.Timeout, str(ev["RequestToken"]))
		}
		time.Sleep(2 * time.Second)
		st, err := r.c.CallAWS(r.c.WriteProfile, "cloudcontrol", "GetResourceRequestStatus",
			map[string]any{"RequestToken": ev["RequestToken"]}, false)
		if err != nil {
			return "", err
		}
		ev, _ = dig(st, "ProgressEvent").(map[string]any)
	}
}

func (r *CLIResources) Create(typ string, desired map[string]any, token string) (string, error) {
	b, _ := json.Marshal(desired)
	return r.write("CreateResource", map[string]any{"TypeName": typ, "DesiredState": string(b), "ClientToken": token})
}

func (r *CLIResources) Update(typ, id string, patch []byte) error {
	_, err := r.write("UpdateResource", map[string]any{"TypeName": typ, "Identifier": id, "PatchDocument": string(patch)})
	return err
}

func (r *CLIResources) Delete(typ, id string) error {
	_, err := r.write("DeleteResource", map[string]any{"TypeName": typ, "Identifier": id})
	return err
}

// ---------------------------------------------------------------- helpers

func describe(cs []threeway.Conflict) string {
	var out []string
	for _, c := range cs {
		b, _ := json.Marshal(c.Now)
		out = append(out, fmt.Sprintf("%s is now %s", c.Path, b))
	}
	return strings.Join(out, "; ")
}

func pathList(ps []threeway.Path) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return strings.Join(out, ", ")
}

func deep(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func dig(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func uniqStrings(l []string) []string {
	var out []string
	for i, s := range l {
		if i == 0 || s != l[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// pathOf turns a JSON pointer into a threeway path.
func pathOf(ptr string) threeway.Path {
	var p threeway.Path
	for _, seg := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		if isIndex(seg) && seg != "-" {
			n := 0
			fmt.Sscan(seg, &n)
			p = append(p, n)
		} else {
			p = append(p, seg)
		}
	}
	return p
}

// exposure finds settings that open a resource to the whole internet, on any cloud: an
// address range of everything (0.0.0.0/0, ::/0), a source of * or Internet, or a property
// about public access turned on. It reports where each is.
func exposure(v any, at string, out []string) []string {
	key := strings.ToLower(at[strings.LastIndex(at, "/")+1:])
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			out = exposure(e, at+"/"+k, out)
		}
	case []any:
		for i, e := range x {
			out = exposure(e, fmt.Sprintf("%s/%d", at, i), out)
		}
		if len(x) > 0 {
			return out
		}
	case string:
		l := strings.ToLower(x)
		switch {
		case l == "0.0.0.0/0" || l == "::/0":
			out = append(out, at+" = "+x)
		case (l == "*" || l == "internet") && strings.Contains(key, "source"):
			out = append(out, at+" = "+x)
		case strings.Contains(key, "public") && (l == "enabled" || l == "allow" || l == "true"):
			out = append(out, at+" = "+x)
		}
	case bool:
		if x && strings.Contains(key, "public") && !strings.Contains(key, "block") && !strings.Contains(key, "prevent") {
			out = append(out, at+" = true")
		}
	}
	return out
}
