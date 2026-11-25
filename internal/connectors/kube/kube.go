// Package kube: Kubernetes, where the API server itself decides.
//
// Every change the agent asks for is sent to the real API server as a server-side dry run
// when it is asked for, so schema validation, defaulting and admission webhooks all run, but
// nothing changes until commit. The live object at that moment is the before-image.
//
//   - Before commit, every object is checked again: if anyone changed it since it was
//     staged, the commit is refused (conflict) and nothing is applied.
//   - On commit the changes are applied in order; if one fails, the ones already applied
//     are reverted from their before-images.
//   - Undo restores before-images: an update is replaced back, a creation deleted, a
//     deletion re-created. It refuses if someone changed the object after commit.
//
// What a delete destroys is read from the cluster's own data model, not from a list of
// names: the volume behind a PersistentVolumeClaim (and a StatefulSet's claims) is gone
// when the PersistentVolume's reclaim policy, or the StatefulSet's claim retention policy,
// says Delete; deleting a namespace deletes everything in it. A delete that destroys
// stored data cannot be undone, so it is irreversible: a human approves it.
//
// A cascading delete is undone the way Kubernetes builds objects in the first place: the
// objects that nothing owns (no ownerReferences) are re-created, and their controllers
// re-create what they own (a Deployment its ReplicaSets and Pods).
package kube

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"undolayer/internal/model"
	"undolayer/internal/threeway"
	"undolayer/internal/tx"
)

type Connector struct {
	tx.Base
	Kubectl     string
	Kubeconfig  string
	Context     string
	Namespace   string // default namespace for objects that do not name one
	Environment string // reported as a fact (e.g. "production") for policy rules
}

func New() *Connector {
	return &Connector{Base: tx.Base{ConnName: "kube"}, Kubectl: "kubectl", Namespace: "default"}
}

// Writes carry content into the cluster (a manifest can hold a secret copied from the
// workspace), so they are egress: the secret and destination rules apply to them.
func (*Connector) Egress() bool { return true }

func (c *Connector) Operations() map[string]tx.OpSchema {
	s := map[string]any{"type": "string"}
	return map[string]tx.OpSchema{
		"get": {Description: "Get Kubernetes objects as JSON (read). kind e.g. deployment, pod, configmap; name optional.",
			Properties: map[string]any{"kind": s, "name": s, "namespace": s, "selector": s,
				"all_namespaces": map[string]any{"type": "boolean"}}, Required: []string{"kind"}},
		"logs": {Description: "Read a pod's logs (read).",
			Properties: map[string]any{"name": s, "namespace": s, "container": s, "tail": map[string]any{"type": "integer"}},
			Required:   []string{"name"}},
		"apply": {Description: "Create or update objects from a YAML/JSON manifest (one or more documents). Validated by " +
			"the API server now (dry run), applied on commit, undoable.", Properties: map[string]any{"manifest": s},
			Required: []string{"manifest"}},
		"patch": {Description: "Merge-patch one object (e.g. {\"spec\":{\"template\":...}}). Validated now, applied on commit.",
			Properties: map[string]any{"kind": s, "name": s, "namespace": s, "patch": map[string]any{"type": "object"}},
			Required:   []string{"kind", "name", "patch"}},
		"scale": {Description: "Set the replica count of a workload. Validated now, applied on commit.",
			Properties: map[string]any{"kind": s, "name": s, "namespace": s, "replicas": map[string]any{"type": "integer"}},
			Required:   []string{"kind", "name", "replicas"}},
		"delete": {Description: "Delete one object (and what it owns). Applied on commit; undoable unless it destroys " +
			"stored data, which needs a human.", Properties: map[string]any{"kind": s, "name": s, "namespace": s},
			Required: []string{"kind", "name"}},
	}
}

// ---------------------------------------------------------------- kubectl

type kerr struct{ msg string }

func (e *kerr) Error() string { return e.msg }

func (c *Connector) run(stdin []byte, args ...string) ([]byte, error) {
	base := []string{}
	if c.Kubeconfig != "" {
		base = append(base, "--kubeconfig", c.Kubeconfig)
	}
	if c.Context != "" {
		base = append(base, "--context", c.Context)
	}
	cmd := exec.Command(c.Kubectl, append(base, args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, &kerr{msg: msg}
	}
	return out.Bytes(), nil
}

type obj = map[string]any

func (c *Connector) runJSON(stdin []byte, args ...string) (obj, error) {
	b, err := c.run(stdin, args...)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	var o obj
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, fmt.Errorf("kubectl returned non-JSON output: %s", strings.TrimSpace(string(b)))
	}
	return o, nil
}

// Ref names one object the way the API server does.
type Ref struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

func (r Ref) String() string {
	if r.Namespace != "" {
		return r.Kind + " " + r.Namespace + "/" + r.Name
	}
	return r.Kind + " " + r.Name
}

func refOf(o obj) Ref {
	md, _ := o["metadata"].(obj)
	r := Ref{APIVersion: str(o["apiVersion"]), Kind: str(o["kind"])}
	if md != nil {
		r.Name, r.Namespace = str(md["name"]), str(md["namespace"])
	}
	return r
}

func (r Ref) stub() []byte {
	md := obj{"name": r.Name}
	if r.Namespace != "" {
		md["namespace"] = r.Namespace
	}
	b, _ := json.Marshal(obj{"apiVersion": r.APIVersion, "kind": r.Kind, "metadata": md})
	return b
}

// live returns the object as the API server has it now, or nil if it does not exist.
// (kubectl get -f answers with a List, even for one object.)
func (c *Connector) live(r Ref) (obj, error) {
	o, err := c.runJSON(r.stub(), "get", "-f", "-", "--ignore-not-found", "-o", "json")
	if err != nil || o == nil {
		return o, err
	}
	if items, ok := o["items"].([]any); ok && strings.HasSuffix(str(o["kind"]), "List") {
		if len(items) == 0 {
			return nil, nil
		}
		it, _ := items[0].(obj)
		return it, nil
	}
	return o, nil
}

// ident checks a value from the agent that kubectl takes as a word (a kind, a name): it
// follows the API's naming rules (no leading '-', whitespace, '/' or control characters),
// so it can only ever be a name, never an option or a path.
func ident(what, v string) error {
	if v == "" {
		return fmt.Errorf("%s is required", what)
	}
	if strings.HasPrefix(v, "-") || len(v) > 253 {
		return fmt.Errorf("invalid %s %q", what, v)
	}
	for _, r := range v {
		if r <= ' ' || r == '/' || r == '\\' || r == '%' || r == 0x7f {
			return fmt.Errorf("invalid %s %q", what, v)
		}
	}
	return nil
}

// lookup resolves the agent's (kind, name, namespace) to the live object.
func (c *Connector) lookup(args map[string]any) (obj, error) {
	kind, name := str(args["kind"]), str(args["name"])
	if err := ident("kind", kind); err != nil {
		return nil, err
	}
	if err := ident("name", name); err != nil {
		return nil, err
	}
	ns, err := c.namespace(args)
	if err != nil {
		return nil, err
	}
	o, err := c.runJSON(nil, "get", "--namespace="+ns, "--output=json", "--", kind, name)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (c *Connector) namespace(args map[string]any) (string, error) {
	n := str(args["namespace"])
	if n == "" {
		return c.Namespace, nil
	}
	return n, ident("namespace", n)
}

// ---------------------------------------------------------------- what a change is

// change is one staged operation on one object.
type change struct {
	Op          string `json:"op"` // apply | patch | delete
	Ref         Ref    `json:"ref"`
	Body        []byte `json:"body,omitempty"`   // manifest (apply) or merge patch (patch)
	Before      obj    `json:"before,omitempty"` // live object when staged; nil if it did not exist
	BeforePrint string `json:"before_print"`
	After       obj    `json:"after,omitempty"` // what the API server said it would become (dry run)
	ActionID    string `json:"action_id"`
}

type State struct {
	Changes []*change `json:"changes"`
}

// fingerprint identifies an object's desired state. Objects with a generation have their
// spec changes counted by the API server itself (status updates by controllers do not
// bump it); for the others, everything but status and server bookkeeping is hashed.
func fingerprint(o obj) string {
	if o == nil {
		return "absent"
	}
	md, _ := o["metadata"].(obj)
	if g, ok := model.Num(md["generation"]); ok && g > 0 {
		return fmt.Sprintf("uid:%v gen:%v", md["uid"], g)
	}
	c := desired(o)
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return fmt.Sprintf("uid:%v sha:%s", md["uid"], hex.EncodeToString(h[:8]))
}

// desired strips what the server and controllers own: status and bookkeeping metadata.
func desired(o obj) obj {
	out := obj{}
	for k, v := range o {
		if k != "status" {
			out[k] = v
		}
	}
	if md, ok := o["metadata"].(obj); ok {
		m := obj{}
		for k, v := range md {
			switch k {
			case "resourceVersion", "managedFields", "generation", "creationTimestamp", "uid", "selfLink":
			default:
				m[k] = v
			}
		}
		out["metadata"] = m
	}
	return out
}

// forCreate is a before-image ready to be created again.
func forCreate(o obj) obj {
	d := desired(o)
	if md, ok := d["metadata"].(obj); ok {
		delete(md, "deletionTimestamp")
		delete(md, "deletionGracePeriodSeconds")
		delete(md, "finalizers") // finalizers belong to the controllers that add them again
	}
	return d
}

// ---------------------------------------------------------------- classify

func (c *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	f := model.Facts{"cluster": c.Context}
	if c.Environment != "" {
		f["env"] = c.Environment
	}
	switch op {
	case "get", "logs":
		return model.Read, f, nil
	case "apply":
		docs, err := documents(str(args["manifest"]))
		if err != nil {
			return "", nil, err
		}
		groups := []string{}
		for _, d := range docs {
			groups = append(groups, group(str(d["apiVersion"])))
			f["kinds"] = append(strs(f["kinds"]), str(d["kind"]))
		}
		f["objects"] = len(docs)
		f["grants_permissions"] = containsStr(groups, "rbac.authorization.k8s.io")
		return model.Reversible, f, nil
	case "patch", "scale":
		live, err := c.lookup(args)
		if err != nil {
			return "", nil, err
		}
		r := refOf(live)
		f["kind"], f["namespace"] = r.Kind, r.Namespace
		f["grants_permissions"] = group(r.APIVersion) == "rbac.authorization.k8s.io"
		if op == "scale" {
			n, _ := model.Num(args["replicas"])
			cur, _ := model.Num(dig(live, "spec", "replicas"))
			f["replicas_before"], f["replicas_after"] = cur, n
			f["scales_to_zero"] = n == 0 && cur > 0
		}
		return model.Reversible, f, nil
	case "delete":
		live, err := c.lookup(args)
		if err != nil {
			return "", nil, err
		}
		r := refOf(live)
		f["kind"], f["namespace"] = r.Kind, r.Namespace
		f["grants_permissions"] = group(r.APIVersion) == "rbac.authorization.k8s.io"
		lost, cascade, err := c.consequences(live)
		if err != nil {
			return "", nil, err
		}
		f["cascade_count"] = cascade
		if len(lost) > 0 {
			f["destroys_data"], f["data_destroyed"] = true, lost
			return model.Irreversible, f, nil
		}
		f["destroys_data"] = false
		return model.Reversible, f, nil
	}
	return "", nil, fmt.Errorf("unknown kube operation %s", op)
}

// consequences reports the stored data a delete would destroy and how many objects it takes.
func (c *Connector) consequences(o obj) ([]string, int, error) {
	r := refOf(o)
	switch {
	case r.Kind == "Namespace" && group(r.APIVersion) == "":
		items, err := c.namespaceObjects(r.Name)
		if err != nil {
			return nil, 0, err
		}
		var lost []string
		for _, it := range items {
			if l, err := c.claimLoss(it); err != nil {
				return nil, 0, err
			} else if l != "" {
				lost = append(lost, l)
			}
		}
		return lost, len(items), nil
	default:
		l, err := c.claimLoss(o)
		if err != nil || l != "" {
			return []string{l}, 1, err
		}
		if r.Kind == "PersistentVolume" && str(dig(o, "spec", "persistentVolumeReclaimPolicy")) == "Delete" {
			return []string{"volume " + r.Name + " (reclaim policy Delete)"}, 1, nil
		}
		// a StatefulSet's claims follow its retention policy
		if str(dig(o, "spec", "persistentVolumeClaimRetentionPolicy", "whenDeleted")) == "Delete" {
			return []string{r.String() + " deletes its volume claims (retention policy Delete)"}, 1, nil
		}
		return nil, 1, nil
	}
}

// claimLoss: a bound claim whose volume's reclaim policy is Delete loses its data.
func (c *Connector) claimLoss(o obj) (string, error) {
	r := refOf(o)
	if r.Kind != "PersistentVolumeClaim" || group(r.APIVersion) != "" {
		return "", nil
	}
	pvName := str(dig(o, "spec", "volumeName"))
	if pvName == "" {
		return "", nil // not bound to a volume: no data yet
	}
	pv, err := c.live(Ref{APIVersion: "v1", Kind: "PersistentVolume", Name: pvName})
	if err != nil {
		return "", err
	}
	if pv != nil && str(dig(pv, "spec", "persistentVolumeReclaimPolicy")) == "Delete" {
		return fmt.Sprintf("claim %s/%s: volume %s is deleted with it (reclaim policy Delete)", r.Namespace, r.Name, pvName), nil
	}
	return "", nil
}

// namespaceObjects lists every listable namespaced object in a namespace, using the API
// server's own discovery of resource types.
func (c *Connector) namespaceObjects(ns string) ([]obj, error) {
	b, err := c.run(nil, "api-resources", "--namespaced=true", "--verbs=list,create", "-o", "name")
	if err != nil {
		return nil, err
	}
	kinds := strings.Fields(string(b))
	if len(kinds) == 0 {
		return nil, nil
	}
	l, err := c.runJSON(nil, "get", strings.Join(kinds, ","), "-n", ns, "-o", "json")
	if err != nil {
		return nil, err
	}
	items, _ := l["items"].([]any)
	out := make([]obj, 0, len(items))
	for _, it := range items {
		if o, ok := it.(obj); ok {
			out = append(out, o)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- stage (validated now, applied at commit)

func (c *Connector) Stage(t *tx.Tx, a *model.Action) (any, error) {
	switch a.Operation {
	case "get":
		return c.get(t, a.Args)
	case "logs":
		name := str(a.Args["name"])
		if err := ident("name", name); err != nil {
			return nil, err
		}
		ns, err := c.namespace(a.Args)
		if err != nil {
			return nil, err
		}
		args := []string{"logs", "--namespace=" + ns}
		if ct := str(a.Args["container"]); ct != "" {
			if err := ident("container", ct); err != nil {
				return nil, err
			}
			args = append(args, "--container="+ct)
		}
		if n, ok := model.Num(a.Args["tail"]); ok && n > 0 {
			args = append(args, fmt.Sprintf("--tail=%d", int(n)))
		}
		b, err := c.run(nil, append(args, "--", name)...)
		if err != nil {
			return nil, err
		}
		return map[string]any{"logs": string(b)}, nil
	}
	var staged []*change
	switch a.Operation {
	case "apply":
		docs, err := documents(str(a.Args["manifest"]))
		if err != nil {
			return nil, err
		}
		for _, d := range docs {
			body, _ := json.Marshal(d)
			after, err := c.applyObj(body, true)
			if err != nil {
				return nil, fmt.Errorf("the API server rejected %s %s: %v", str(d["kind"]), name(d), err)
			}
			staged = append(staged, &change{Op: "apply", Ref: refOf(after), Body: body, After: after})
		}
	case "patch", "scale":
		live, err := c.lookup(a.Args)
		if err != nil {
			return nil, err
		}
		p := a.Args["patch"]
		if a.Operation == "scale" {
			n, _ := model.Num(a.Args["replicas"])
			p = obj{"spec": obj{"replicas": int(n)}}
		}
		body, _ := json.Marshal(p)
		r := refOf(live)
		after, err := c.patchObj(r, body, true)
		if err != nil {
			return nil, fmt.Errorf("the API server rejected the change to %s: %v", r, err)
		}
		staged = append(staged, &change{Op: "patch", Ref: r, Body: body, After: after})
	case "delete":
		live, err := c.lookup(a.Args)
		if err != nil {
			return nil, err
		}
		r := refOf(live)
		if _, err := c.run(r.stub(), "delete", "-f", "-", "--dry-run=server", "--wait=false"); err != nil {
			return nil, fmt.Errorf("the API server rejected deleting %s: %v", r, err)
		}
		staged = append(staged, &change{Op: "delete", Ref: r})
	}
	st := tx.GetState[State](t, c.Name())
	out := []any{}
	for _, ch := range staged {
		before, err := c.live(ch.Ref)
		if err != nil {
			return nil, err
		}
		ch.Before, ch.BeforePrint, ch.ActionID = before, fingerprint(before), a.ID
		c.noteSecrets(t, before)
		c.noteSecrets(t, ch.After)
		st.Changes = append(st.Changes, ch)
		out = append(out, summary(ch))
	}
	return map[string]any{"staged": true, "validated_by": "API server (dry run)", "changes": out}, nil
}

func (c *Connector) get(t *tx.Tx, args map[string]any) (any, error) {
	kind := str(args["kind"])
	if err := ident("kind", kind); err != nil {
		return nil, err
	}
	a := []string{"get", "--output=json"}
	if args["all_namespaces"] == true {
		a = append(a, "--all-namespaces")
	} else {
		ns, err := c.namespace(args)
		if err != nil {
			return nil, err
		}
		a = append(a, "--namespace="+ns)
	}
	if s := str(args["selector"]); s != "" {
		a = append(a, "--selector="+s) // one token: kubectl parses it as a selector, nothing else
	}
	a = append(a, "--", kind)
	if n := str(args["name"]); n != "" {
		if err := ident("name", n); err != nil {
			return nil, err
		}
		a = append(a, n)
	}
	o, err := c.runJSON(nil, a...)
	if err != nil {
		return nil, err
	}
	c.noteSecrets(t, o)
	return o, nil
}

// noteSecrets registers Secret values (encoded and decoded) as sensitive, so they are
// redacted from everything the agent sees and blocked from leaving.
func (c *Connector) noteSecrets(t *tx.Tx, o obj) {
	if o == nil {
		return
	}
	if items, ok := o["items"].([]any); ok {
		for _, it := range items {
			if io, ok := it.(obj); ok {
				c.noteSecrets(t, io)
			}
		}
		return
	}
	if str(o["kind"]) != "Secret" || group(str(o["apiVersion"])) != "" {
		return
	}
	idx := t.Sensitive()
	r := refOf(o)
	for _, field := range []string{"data", "stringData"} {
		m, _ := o[field].(obj)
		for k, v := range m {
			s := str(v)
			label := "kube:secret:" + r.Namespace + "/" + r.Name + ":" + k
			if len(s) >= idx.MinLen {
				idx.AddValue(s, label)
			}
			if field == "data" {
				if dec, err := base64.StdEncoding.DecodeString(s); err == nil && len(dec) >= idx.MinLen {
					idx.AddValue(string(dec), label)
				}
			}
		}
	}
	if md, ok := o["metadata"].(obj); ok { // kubectl stores the applied manifest, values included
		if ann, ok := md["annotations"].(obj); ok {
			if s := str(ann["kubectl.kubernetes.io/last-applied-configuration"]); len(s) >= idx.MinLen {
				idx.AddValue(s, "kube:secret:"+r.Namespace+"/"+r.Name+":last-applied")
			}
		}
	}
}

func (c *Connector) applyObj(body []byte, dry bool) (obj, error) {
	args := []string{"apply", "--server-side", "--field-manager=undolayer", "--force-conflicts", "-f", "-", "-o", "json"}
	var d obj
	_ = json.Unmarshal(body, &d)
	if c.Namespace != "" && str(dig(d, "metadata", "namespace")) == "" {
		args = append(args, "-n", c.Namespace) // ignored by the server for cluster-scoped kinds
	}
	if dry {
		args = append(args, "--dry-run=server")
	}
	return c.runJSON(body, args...)
}

func (c *Connector) patchObj(r Ref, body []byte, dry bool) (obj, error) {
	args := []string{"patch", "-f", "-", "--type", "merge", "-p", string(body), "-o", "json"}
	if dry {
		args = append(args, "--dry-run=server")
	}
	return c.runJSON(r.stub(), args...)
}

func summary(ch *change) map[string]any {
	s := map[string]any{"object": ch.Ref.String(), "op": ch.Op}
	switch {
	case ch.Op == "delete":
		s["result"] = "deleted"
	case ch.Before == nil:
		s["result"] = "created"
	default:
		s["result"] = "updated"
		s["diff"] = diff(desired(ch.Before), desired(ch.After), "")
	}
	return s
}

// diff lists the fields that differ between two objects, as path: before -> after.
func diff(a, b any, path string) []string {
	am, aok := a.(obj)
	bm, bok := b.(obj)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		ks := make([]string, 0, len(keys))
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		var out []string
		for _, k := range ks {
			if k == "annotations" && strings.HasSuffix(path, "metadata") {
				continue // kubectl and controllers keep bookkeeping there
			}
			out = append(out, diff(am[k], bm[k], strings.TrimPrefix(path+"."+k, "."))...)
		}
		return out
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) == string(bb) {
		return nil
	}
	return []string{fmt.Sprintf("%s: %s -> %s", path, short(ab), short(bb))}
}

func short(b []byte) string {
	if len(b) > 160 {
		return string(b[:160]) + "…"
	}
	return string(b)
}

// ---------------------------------------------------------------- preview, totals

func (c *Connector) Preview(t *tx.Tx) map[string]any {
	st := tx.PeekState[State](t, c.Name())
	if st == nil || len(st.Changes) == 0 {
		return nil
	}
	out := []any{}
	for _, ch := range st.Changes {
		out = append(out, summary(ch))
	}
	return map[string]any{"cluster": c.Context, "changes": out}
}

func (c *Connector) Totals(t *tx.Tx) map[string]float64 {
	st := tx.PeekState[State](t, c.Name())
	if st == nil {
		return nil
	}
	tot := map[string]float64{}
	for _, ch := range st.Changes {
		tot["kube_objects_changed"]++
		if ch.Op == "delete" {
			tot["kube_objects_deleted"]++
		}
	}
	return tot
}

// ---------------------------------------------------------------- prepare, commit, rollback

func (c *Connector) Prepare(t *tx.Tx) error {
	st := tx.PeekState[State](t, c.Name())
	if st == nil {
		return nil
	}
	// per object: the state it was staged against, and what the staged changes make of it
	type span struct {
		ref           Ref
		before, after obj
	}
	var order []string
	spans := map[string]*span{}
	for _, ch := range st.Changes {
		k := ch.Ref.String()
		if spans[k] == nil {
			spans[k] = &span{ref: ch.Ref, before: ch.Before}
			order = append(order, k)
		}
		spans[k].after = ch.After
	}
	for _, k := range order {
		sp := spans[k]
		now, err := c.live(sp.ref)
		if err != nil {
			return err
		}
		switch {
		case sp.before == nil && now != nil:
			return model.Conflict("%s was created by someone else after it was staged; nothing was applied", sp.ref)
		case sp.before == nil:
			continue
		case now == nil:
			return model.Conflict("%s was deleted after it was staged; nothing was applied", sp.ref)
		case str(dig(now, "metadata", "uid")) != str(dig(sp.before, "metadata", "uid")):
			return model.Conflict("%s was replaced by a new object after it was staged; nothing was applied", sp.ref)
		}
		if sp.after == nil { // a delete: any change since staging means the agent saw something else
			if c := threeway.Touched(desired(sp.before), obj{}, desired(now)); len(c) > 0 {
				return model.Conflict("%s changed after its delete was staged (%s); nothing was applied", sp.ref, conflictList(c))
			}
			continue
		}
		if c := threeway.Touched(desired(sp.before), desired(sp.after), desired(now)); len(c) > 0 {
			return model.Conflict("%s: fields this task changes were changed by someone else after staging (%s); nothing was applied",
				sp.ref, conflictList(c))
		}
	}
	return nil
}

func conflictList(cs []threeway.Conflict) string {
	var out []string
	for _, c := range cs {
		b, _ := json.Marshal(c.Now)
		out = append(out, fmt.Sprintf("%s is now %s", c.Path, short(b)))
	}
	return strings.Join(out, "; ")
}

// UndoEntry is the way back for one applied change.
type UndoEntry struct {
	Ref        Ref    `json:"ref"`
	Kind       string `json:"kind"` // created | updated | deleted
	Before     obj    `json:"before,omitempty"`
	Roots      []obj  `json:"roots,omitempty"` // a deleted namespace's unowned objects
	After      obj    `json:"after,omitempty"` // the object right after the change (updated, created)
	AfterUID   string `json:"after_uid,omitempty"`
	AfterPrint string `json:"after_print"`
}

type UndoRecord struct {
	InFlight   bool        `json:"in_flight,omitempty"`
	Kubectl    string      `json:"kubectl"`
	Kubeconfig string      `json:"kubeconfig,omitempty"`
	Context    string      `json:"context,omitempty"`
	Entries    []UndoEntry `json:"entries"`
}

func (c *Connector) Commit(t *tx.Tx) (any, error) {
	st := tx.PeekState[State](t, c.Name())
	if st == nil || len(st.Changes) == 0 {
		return nil, nil
	}
	rec := &UndoRecord{Kubectl: c.Kubectl, Kubeconfig: c.Kubeconfig, Context: c.Context}
	fail := func(err error) (any, error) {
		if uerr := c.undoEntries(rec.Entries, false); uerr != nil {
			return nil, fmt.Errorf("%v; reverting the applied changes also failed: %v", err, uerr)
		}
		return nil, err
	}
	for _, ch := range st.Changes {
		before, err := c.live(ch.Ref)
		if err != nil {
			return fail(err)
		}
		e := UndoEntry{Ref: ch.Ref, Before: before}
		switch ch.Op {
		case "apply":
			if _, err := c.applyObj(ch.Body, false); err != nil {
				return fail(fmt.Errorf("applying %s: %v", ch.Ref, err))
			}
		case "patch":
			if _, err := c.patchObj(ch.Ref, ch.Body, false); err != nil {
				return fail(fmt.Errorf("patching %s: %v", ch.Ref, err))
			}
		case "delete":
			if ch.Ref.Kind == "Namespace" {
				items, err := c.namespaceObjects(ch.Ref.Name)
				if err != nil {
					return fail(err)
				}
				for _, it := range items {
					if md, _ := it["metadata"].(obj); md != nil && md["ownerReferences"] == nil && !isEvent(it) {
						e.Roots = append(e.Roots, it)
					}
				}
			}
			if _, err := c.run(ch.Ref.stub(), "delete", "-f", "-", "--wait=false"); err != nil {
				return fail(fmt.Errorf("deleting %s: %v", ch.Ref, err))
			}
		}
		after, err := c.live(ch.Ref)
		if err != nil {
			return fail(err)
		}
		switch {
		case ch.Op == "delete":
			e.Kind = "deleted"
		case before == nil:
			e.Kind = "created"
		default:
			e.Kind = "updated"
		}
		e.AfterPrint = fingerprint(after)
		e.After = after
		if md, _ := after["metadata"].(obj); md != nil {
			e.AfterUID = str(md["uid"])
		}
		rec.Entries = append(rec.Entries, e)
	}
	st.Changes = nil
	return rec, nil
}

func (c *Connector) Rollback(t *tx.Tx) error {
	if st := tx.PeekState[State](t, c.Name()); st != nil {
		st.Changes = nil // nothing reached the cluster: staged changes were dry runs
	}
	return nil
}

func (c *Connector) Recover(t *tx.Tx) error { return c.Rollback(t) }

// RunDeferred runs an approved delete that cannot be undone (it destroys stored data).
func (c *Connector) RunDeferred(t *tx.Tx, a *model.Action) (any, error) {
	if a.Operation != "delete" {
		return nil, fmt.Errorf("kube %s does not run deferred", a.Operation)
	}
	live, err := c.lookup(a.Args)
	if err != nil {
		return nil, err
	}
	r := refOf(live)
	if _, err := c.run(r.stub(), "delete", "-f", "-", "--wait=false"); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": r.String(), "undoable": false}, nil
}

// ---------------------------------------------------------------- undo

func (c *Connector) Undo(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	k := &Connector{Base: c.Base, Kubectl: rec.Kubectl, Kubeconfig: rec.Kubeconfig, Context: rec.Context}
	return k.undoEntries(rec.Entries, true)
}

// Intent: every staged change with the object as it was staged and as the API server said
// it would become (the dry run); a namespace's contents are listed before it is deleted.
func (c *Connector) Intent(t *tx.Tx) (any, error) {
	st := tx.PeekState[State](t, c.Name())
	if st == nil || len(st.Changes) == 0 {
		return nil, nil
	}
	rec := &UndoRecord{Kubectl: c.Kubectl, Kubeconfig: c.Kubeconfig, Context: c.Context, InFlight: true}
	for _, ch := range st.Changes {
		e := UndoEntry{Ref: ch.Ref, Before: ch.Before, After: ch.After}
		switch {
		case ch.Op == "delete":
			e.Kind = "deleted"
			if ch.Ref.Kind == "Namespace" {
				items, err := c.namespaceObjects(ch.Ref.Name)
				if err != nil {
					return nil, err
				}
				for _, it := range items {
					if md, _ := it["metadata"].(obj); md != nil && md["ownerReferences"] == nil && !isEvent(it) {
						e.Roots = append(e.Roots, it)
					}
				}
			}
		case ch.Before == nil:
			e.Kind = "created"
		default:
			e.Kind = "updated"
		}
		rec.Entries = append(rec.Entries, e)
	}
	return rec, nil
}

// UndoInFlight reverts whatever part of an interrupted commit reached the cluster.
func (c *Connector) UndoInFlight(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	k := &Connector{Base: c.Base, Kubectl: rec.Kubectl, Kubeconfig: rec.Kubeconfig, Context: rec.Context}
	return k.undoEntries(rec.Entries, true, true)
}

// undoEntries reverts entries newest first, field by field: only what the commit changed
// is put back, and changes made since by anyone else are kept. With check, every revert is
// first planned against the live objects, and nothing is written if any of them conflicts.
func (c *Connector) undoEntries(entries []UndoEntry, check bool, inFlight ...bool) error {
	partial := len(inFlight) > 0 && inFlight[0] // some entries may never have been applied
	skip := map[int]bool{}
	if check {
		sim := map[string]obj{}
		live := func(r Ref) (obj, error) {
			if o, ok := sim[r.String()]; ok {
				return o, nil
			}
			o, err := c.live(r)
			if err != nil {
				return nil, err
			}
			var d obj
			if o != nil && str(dig(o, "metadata", "deletionTimestamp")) == "" {
				d = desired(o)
			}
			sim[r.String()] = d
			return d, nil
		}
		for i := len(entries) - 1; i >= 0; i-- {
			e := entries[i]
			now, err := live(e.Ref)
			if err != nil {
				return err
			}
			switch e.Kind {
			case "deleted":
				if now != nil {
					if partial && e.Before != nil && len(specChanges(desired(e.Before), now)) == 0 {
						skip[i] = true // the object is as it was staged: the delete never ran
						continue
					}
					return model.Conflict("%s was re-created after commit; refusing to overwrite it", e.Ref)
				}
				sim[e.Ref.String()] = desired(e.Before)
			case "created":
				if now == nil {
					continue // already gone
				}
				if cs := specChanges(desired(e.After), now); len(cs) > 0 {
					return model.Conflict("%s was changed after this task created it (%s); refusing to delete it", e.Ref, conflictList(cs))
				}
				sim[e.Ref.String()] = nil
			case "updated":
				if now == nil {
					return model.Conflict("%s was deleted after commit; nothing to restore into", e.Ref)
				}
				res, cs, err := threeway.Revert(desired(e.Before), desired(e.After), now)
				if err != nil {
					return model.Conflict("%s: %v", e.Ref, err)
				}
				if len(cs) > 0 {
					return model.Conflict("%s: fields this commit changed were changed again since (%s); refusing to overwrite them",
						e.Ref, conflictList(cs))
				}
				sim[e.Ref.String()], _ = res.(obj)
			}
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if skip[i] {
			continue
		}
		switch e.Kind {
		case "created":
			if _, err := c.run(e.Ref.stub(), "delete", "-f", "-", "--ignore-not-found", "--wait=false"); err != nil {
				return fmt.Errorf("undo: deleting %s: %v", e.Ref, err)
			}
		case "updated":
			if err := c.revertUpdate(e); err != nil {
				return err
			}
		case "deleted":
			if err := c.waitGone(e.Ref); err != nil {
				return err
			}
			if err := c.create(forCreate(e.Before)); err != nil {
				return fmt.Errorf("undo: re-creating %s: %v", e.Ref, err)
			}
			for _, r := range e.Roots {
				if err := c.create(forCreate(r)); err != nil && !strings.Contains(err.Error(), "AlreadyExists") {
					return fmt.Errorf("undo: re-creating %s: %v", refOf(r), err)
				}
			}
		}
	}
	return nil
}

// revertUpdate writes the three-way revert of one update with optimistic concurrency: the
// replace carries the resourceVersion it was computed from, and is recomputed if the
// object changes in between.
func (c *Connector) revertUpdate(e UndoEntry) error {
	for attempt := 0; attempt < 5; attempt++ {
		now, err := c.live(e.Ref)
		if err != nil {
			return err
		}
		if now == nil {
			return model.Conflict("%s was deleted during undo", e.Ref)
		}
		res, cs, err := threeway.Revert(desired(e.Before), desired(e.After), desired(now))
		if err != nil {
			return model.Conflict("%s: %v", e.Ref, err)
		}
		if len(cs) > 0 {
			return model.Conflict("%s: fields this commit changed were changed again since (%s)", e.Ref, conflictList(cs))
		}
		img, _ := res.(obj)
		if len(threeway.Changes(desired(now), img)) == 0 {
			return nil // nothing of this change is in the cluster
		}
		md, _ := img["metadata"].(obj)
		nmd, _ := now["metadata"].(obj)
		if md == nil || nmd == nil {
			return fmt.Errorf("undo: %s has no metadata", e.Ref)
		}
		md["resourceVersion"], md["uid"] = nmd["resourceVersion"], nmd["uid"]
		body, _ := json.Marshal(img)
		_, err = c.run(body, "replace", "-f", "-", "-o", "json")
		if err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "the object has been modified") && !strings.Contains(err.Error(), "Conflict") {
			return fmt.Errorf("undo: restoring %s: %v", e.Ref, err)
		}
	}
	return model.Conflict("%s kept changing during undo; try again", e.Ref)
}

// specChanges: changes to anything but metadata (where controllers keep bookkeeping) and status.
func specChanges(after, now obj) []threeway.Conflict {
	strip := func(o obj) obj {
		out := obj{}
		for k, v := range o {
			if k != "metadata" && k != "status" {
				out[k] = v
			}
		}
		return out
	}
	a, n := strip(after), strip(now)
	var out []threeway.Conflict
	for _, p := range threeway.Changes(a, n) {
		av, _ := threeway.Get(a, p)
		nv, _ := threeway.Get(n, p)
		out = append(out, threeway.Conflict{Path: p.String(), After: av, Now: nv})
	}
	return out
}

func (c *Connector) create(o obj) error {
	body, _ := json.Marshal(o)
	_, err := c.run(body, "create", "-f", "-", "-o", "json")
	if err != nil && strings.Contains(err.Error(), "AlreadyExists") {
		return &kerr{msg: "AlreadyExists: " + err.Error()}
	}
	return err
}

// waitGone waits for a deleted object to finish terminating (finalizers, namespace cleanup).
func (c *Connector) waitGone(r Ref) error {
	_, err := c.run(r.stub(), "wait", "-f", "-", "--for=delete", "--timeout=180s")
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return fmt.Errorf("undo: %s is still terminating: %v", r, err)
	}
	return nil
}

// ---------------------------------------------------------------- helpers

func documents(manifest string) ([]obj, error) {
	dec := yaml.NewDecoder(strings.NewReader(manifest))
	var out []obj
	for {
		var d map[string]any
		err := dec.Decode(&d)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("manifest is not valid YAML/JSON: %v", err)
		}
		if d == nil {
			continue
		}
		b, _ := json.Marshal(d) // normalise YAML types to JSON types
		var o obj
		if err := json.Unmarshal(b, &o); err != nil {
			return nil, err
		}
		if items, ok := o["items"].([]any); ok && strings.HasSuffix(str(o["kind"]), "List") {
			for _, it := range items {
				if io, ok := it.(obj); ok {
					out = append(out, io)
				}
			}
			continue
		}
		if str(o["apiVersion"]) == "" || str(o["kind"]) == "" || name(o) == "" {
			return nil, errors.New("every manifest document needs apiVersion, kind and metadata.name")
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		return nil, errors.New("manifest has no objects")
	}
	return out, nil
}

// isEvent: Events are the cluster's record of what happened, not desired state; they
// expire on their own, and re-creating them on undo would forge history.
func isEvent(o obj) bool {
	g := group(str(o["apiVersion"]))
	return str(o["kind"]) == "Event" && (g == "" || g == "events.k8s.io")
}

func name(o obj) string { return str(dig(o, "metadata", "name")) }

func group(apiVersion string) string {
	if i := strings.IndexByte(apiVersion, '/'); i >= 0 {
		return apiVersion[:i]
	}
	return ""
}

func dig(o obj, path ...string) any {
	var cur any = o
	for _, p := range path {
		m, ok := cur.(obj)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
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

func strs(v any) []string {
	l, _ := v.([]string)
	return l
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Contained: staging runs inside a transaction this process holds (or a server-side dry
// run); nothing reaches anyone else before commit.
func (c *Connector) Contained(string) bool { return true }
