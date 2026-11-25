package kube

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

// These tests run against a real cluster: UNDOLAYER_TEST_KUBE_CONTEXT=kind-undolayer-test
// (kind create cluster --name undolayer-test). Each test works in its own namespace.

func cluster(t *testing.T) string {
	ctx := os.Getenv("UNDOLAYER_TEST_KUBE_CONTEXT")
	if ctx == "" {
		t.Skip("set UNDOLAYER_TEST_KUBE_CONTEXT to run Kubernetes tests")
	}
	return ctx
}

type env struct {
	t   *testing.T
	ctx string
	ns  string
	m   *tx.Manager
}

func setup(t *testing.T) *env {
	ctx := cluster(t)
	ns := fmt.Sprintf("ul-%d", time.Now().UnixNano()%1e9)
	e := &env{t: t, ctx: ctx, ns: ns}
	e.kubectl("create", "namespace", ns)
	t.Cleanup(func() { _, _ = e.try("delete", "namespace", ns, "--wait=false", "--ignore-not-found") })
	m, err := tx.NewManager(filepath.Join(t.TempDir(), "state"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	c := New()
	c.Context, c.Namespace = ctx, ns
	m.Register(c)
	e.m = m
	return e
}

func (e *env) try(args ...string) (string, error) {
	b, err := exec.Command("kubectl", append([]string{"--context", e.ctx}, args...)...).CombinedOutput()
	return string(b), err
}

func (e *env) kubectl(args ...string) string {
	e.t.Helper()
	out, err := e.try(args...)
	if err != nil {
		e.t.Fatalf("kubectl %v: %v: %s", args, err, out)
	}
	return out
}

func (e *env) apply(manifest string) {
	e.t.Helper()
	cmd := exec.Command("kubectl", "--context", e.ctx, "-n", e.ns, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		e.t.Fatalf("apply: %v: %s", err, out)
	}
}

func (e *env) jsonpath(kind, name, path string) string {
	out, err := e.try("get", kind, name, "-n", e.ns, "-o", "jsonpath="+path, "--ignore-not-found")
	if err != nil {
		return "ERR " + out
	}
	return out
}

func (e *env) exists(kind, name string) bool {
	out, _ := e.try("get", kind, name, "-n", e.ns, "--ignore-not-found", "-o", "name")
	return strings.TrimSpace(out) != ""
}

func call(t *testing.T, x *tx.Tx, op string, args map[string]any) map[string]any {
	t.Helper()
	r, err := x.Call("kube", op, args)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	m, _ := r.(map[string]any)
	return m
}

func undo(t *testing.T, x *tx.Tx) error {
	t.Helper()
	r, err := x.Undo("")
	if err != nil {
		return err
	}
	b, _ := json.Marshal(r)
	var rep struct {
		Conflicts []any `json:"conflicts"`
		Failed    []any `json:"failed"`
	}
	_ = json.Unmarshal(b, &rep)
	if len(rep.Conflicts) > 0 {
		return &model.CommitConflict{Msg: fmt.Sprint(rep.Conflicts)}
	}
	if len(rep.Failed) > 0 {
		return fmt.Errorf("undo failed: %v", rep.Failed)
	}
	return nil
}

const image = "registry.k8s.io/pause:3.10"

func deployment(name string, replicas int) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
spec:
  replicas: %d
  selector: {matchLabels: {app: %s}}
  template:
    metadata: {labels: {app: %s}}
    spec:
      containers: [{name: main, image: %s}]
`, name, replicas, name, name, image)
}

func TestApplyIsStagedCommittedAndUndone(t *testing.T) {
	e := setup(t)
	x := e.m.Begin("deploy web")
	r := call(t, x, "apply", map[string]any{"manifest": deployment("web", 2) + "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: web-config}\ndata: {mode: blue}\n"})
	if r["staged"] != true {
		t.Fatalf("not staged: %v", r)
	}
	if e.exists("deployment", "web") || e.exists("configmap", "web-config") {
		t.Fatal("a staged apply reached the cluster before commit")
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if !e.exists("deployment", "web") || e.jsonpath("configmap", "web-config", "{.data.mode}") != "blue" {
		t.Fatal("commit did not apply")
	}
	if err := undo(t, x); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if e.exists("configmap", "web-config") {
		t.Fatal("undo did not delete what the commit created")
	}
}

func TestTheAPIServerRejectsInvalidChangesAtCallTime(t *testing.T) {
	e := setup(t)
	x := e.m.Begin("deploy")
	_, err := x.Call("kube", "apply", map[string]any{"manifest": strings.Replace(deployment("bad", 1), "replicas: 1", "replicas: -3", 1)})
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("an invalid object was staged: %v", err)
	}
	_, _ = x.Rollback("test")
}

func TestUpdatesUndoExactlyAndRefuseToOverwriteLaterChanges(t *testing.T) {
	e := setup(t)
	e.apply(deployment("api", 1) + "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: flags}\ndata: {beta: \"off\", limit: \"10\"}\n")
	x := e.m.Begin("turn the beta on and scale api to 3")
	call(t, x, "patch", map[string]any{"kind": "configmap", "name": "flags", "patch": map[string]any{"data": map[string]any{"beta": "on"}}})
	r := call(t, x, "scale", map[string]any{"kind": "deployment", "name": "api", "replicas": 3})
	if !strings.Contains(fmt.Sprint(r), "spec.replicas: 1 -> 3") {
		t.Fatalf("preview does not show the change: %v", r)
	}
	if e.jsonpath("deployment", "api", "{.spec.replicas}") != "1" {
		t.Fatal("scale reached the cluster before commit")
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if e.jsonpath("deployment", "api", "{.spec.replicas}") != "3" || e.jsonpath("configmap", "flags", "{.data.beta}") != "on" {
		t.Fatal("commit did not apply")
	}
	time.Sleep(2 * time.Second) // let the controllers update status: that must not count as a change
	if err := undo(t, x); err != nil {
		t.Fatal(err)
	}
	if e.jsonpath("deployment", "api", "{.spec.replicas}") != "1" || e.jsonpath("configmap", "flags", "{.data.beta}") != "off" ||
		e.jsonpath("configmap", "flags", "{.data.limit}") != "10" {
		t.Fatal("undo did not restore the before-images")
	}

	// someone else changes another field after commit: undo puts back ours and keeps theirs
	y := e.m.Begin("turn the beta on")
	call(t, y, "patch", map[string]any{"kind": "configmap", "name": "flags", "patch": map[string]any{"data": map[string]any{"beta": "on"}}})
	if _, err := y.Commit(); err != nil {
		t.Fatal(err)
	}
	e.kubectl("-n", e.ns, "patch", "configmap", "flags", "--type", "merge", "-p", `{"data":{"limit":"99"}}`)
	if err := undo(t, y); err != nil {
		t.Fatalf("undo refused although nobody touched what it changed: %v", err)
	}
	if e.jsonpath("configmap", "flags", "{.data.beta}") != "off" || e.jsonpath("configmap", "flags", "{.data.limit}") != "99" {
		t.Fatal("undo did not revert only its own field")
	}

	// someone changes the same field again: undo must refuse and keep their value
	z := e.m.Begin("turn the beta on")
	call(t, z, "patch", map[string]any{"kind": "configmap", "name": "flags", "patch": map[string]any{"data": map[string]any{"beta": "on"}}})
	if _, err := z.Commit(); err != nil {
		t.Fatal(err)
	}
	e.kubectl("-n", e.ns, "patch", "configmap", "flags", "--type", "merge", "-p", `{"data":{"beta":"partial"}}`)
	var cc *model.CommitConflict
	if err := undo(t, z); !errors.As(err, &cc) {
		t.Fatalf("undo overwrote a later change to the same field: %v", err)
	}
	if e.jsonpath("configmap", "flags", "{.data.beta}") != "partial" {
		t.Fatal("the other person's change was lost")
	}
}

func TestUndoKeepsTheAutoscalersReplicas(t *testing.T) {
	e := setup(t)
	e.apply(deployment("web", 2))
	x := e.m.Begin("set LOG_LEVEL=debug on web")
	call(t, x, "patch", map[string]any{"kind": "deployment", "name": "web", "patch": map[string]any{"spec": map[string]any{
		"template": map[string]any{"metadata": map[string]any{"annotations": map[string]any{"log-level": "debug"}}}}}})
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	e.kubectl("-n", e.ns, "scale", "deployment", "web", "--replicas=7") // an autoscaler reacts meanwhile
	if err := undo(t, x); err != nil {
		t.Fatalf("undo refused: %v", err)
	}
	if e.jsonpath("deployment", "web", "{.spec.template.metadata.annotations.log-level}") != "" {
		t.Fatal("the change was not undone")
	}
	if e.jsonpath("deployment", "web", "{.spec.replicas}") != "7" {
		t.Fatal("undo threw away the autoscaler's replica count")
	}
}

func TestSeveralChangesToOneObjectUndoNewestFirst(t *testing.T) {
	e := setup(t)
	e.apply(deployment("api", 1))
	x := e.m.Begin("scale api to 2, then 3")
	call(t, x, "scale", map[string]any{"kind": "deployment", "name": "api", "replicas": 2})
	call(t, x, "scale", map[string]any{"kind": "deployment", "name": "api", "replicas": 3})
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if e.jsonpath("deployment", "api", "{.spec.replicas}") != "3" {
		t.Fatal("not committed")
	}
	if err := undo(t, x); err != nil {
		t.Fatal(err)
	}
	if e.jsonpath("deployment", "api", "{.spec.replicas}") != "1" {
		t.Fatalf("undo left replicas at %s", e.jsonpath("deployment", "api", "{.spec.replicas}"))
	}
}

func TestAChangeToOtherFieldsDoesNotStopTheCommit(t *testing.T) {
	e := setup(t)
	e.apply("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cfg}\ndata: {v: \"1\", w: \"1\"}\n")
	x := e.m.Begin("set v to 2")
	call(t, x, "patch", map[string]any{"kind": "configmap", "name": "cfg", "patch": map[string]any{"data": map[string]any{"v": "2"}}})
	e.kubectl("-n", e.ns, "patch", "configmap", "cfg", "--type", "merge", "-p", `{"data":{"w":"9"}}`)
	if _, err := x.Commit(); err != nil {
		t.Fatalf("a change to another field stopped the commit: %v", err)
	}
	if e.jsonpath("configmap", "cfg", "{.data.v}") != "2" || e.jsonpath("configmap", "cfg", "{.data.w}") != "9" {
		t.Fatal("commit lost a change")
	}
}

func TestAChangeMadeAfterStagingStopsTheCommit(t *testing.T) {
	e := setup(t)
	e.apply("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cfg}\ndata: {v: \"1\"}\n")
	x := e.m.Begin("set v to 2")
	call(t, x, "patch", map[string]any{"kind": "configmap", "name": "cfg", "patch": map[string]any{"data": map[string]any{"v": "2"}}})
	e.kubectl("-n", e.ns, "patch", "configmap", "cfg", "--type", "merge", "-p", `{"data":{"v":"9"}}`)
	var cc *model.CommitConflict
	if _, err := x.Commit(); !errors.As(err, &cc) {
		t.Fatalf("committed over a concurrent change: %v", err)
	}
	if e.jsonpath("configmap", "cfg", "{.data.v}") != "9" {
		t.Fatal("the concurrent change was overwritten")
	}
}

func TestDeleteIsUndoneByRecreatingTheObject(t *testing.T) {
	e := setup(t)
	e.apply(deployment("worker", 2))
	x := e.m.Begin("remove the worker")
	call(t, x, "delete", map[string]any{"kind": "deployment", "name": "worker"})
	if !e.exists("deployment", "worker") {
		t.Fatal("delete reached the cluster before commit")
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	e.kubectl("-n", e.ns, "wait", "--for=delete", "deployment/worker", "--timeout=60s")
	if err := undo(t, x); err != nil {
		t.Fatal(err)
	}
	if e.jsonpath("deployment", "worker", "{.spec.replicas}") != "2" ||
		e.jsonpath("deployment", "worker", "{.spec.template.spec.containers[0].image}") != image {
		t.Fatal("undo did not re-create the deployment as it was")
	}
	// its controller rebuilds what it owned
	e.kubectl("-n", e.ns, "wait", "--for=condition=available", "deployment/worker", "--timeout=120s")
}

func TestDeletingStoredDataNeedsApproval(t *testing.T) {
	e := setup(t)
	pv := "ul-pv-" + e.ns
	e.apply(fmt.Sprintf(`apiVersion: v1
kind: PersistentVolume
metadata: {name: %s}
spec:
  capacity: {storage: 1Mi}
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Delete
  storageClassName: ""
  hostPath: {path: /tmp/%s}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: data}
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: ""
  volumeName: %s
  resources: {requests: {storage: 1Mi}}
`, pv, pv, pv))
	t.Cleanup(func() { _, _ = e.try("delete", "pv", pv, "--wait=false", "--ignore-not-found") })
	e.kubectl("-n", e.ns, "wait", "--for=jsonpath={.status.phase}=Bound", "pvc/data", "--timeout=60s")
	x := e.m.Begin("clean up the namespace")
	r := call(t, x, "delete", map[string]any{"kind": "pvc", "name": "data"})
	if r["held"] != true {
		t.Fatalf("a data-destroying delete was not held: %v", r)
	}
	if pv := x.Preview(); pv["approval_required"] != true {
		t.Fatalf("no approval required: %v", pv["approval_reasons"])
	}
	var ar *model.ApprovalRequired
	if _, err := x.Commit(); !errors.As(err, &ar) {
		t.Fatalf("committed without approval: %v", err)
	}
	if !e.exists("pvc", "data") {
		t.Fatal("the claim was deleted without approval")
	}

	// the same delete of a claim whose volume is retained is undoable
	e.kubectl("patch", "pv", pv, "-p", `{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}`)
	y := e.m.Begin("clean up the namespace")
	if r := call(t, y, "delete", map[string]any{"kind": "pvc", "name": "data"}); r["held"] == true {
		t.Fatalf("a retained claim was treated as data loss: %v", r)
	}
	_, _ = y.Rollback("test")
}

func TestScalingToZeroNeedsApproval(t *testing.T) {
	e := setup(t)
	e.apply(deployment("shop", 2))
	x := e.m.Begin("save money overnight")
	call(t, x, "scale", map[string]any{"kind": "deployment", "name": "shop", "replicas": 0})
	var ar *model.ApprovalRequired
	if _, err := x.Commit(); !errors.As(err, &ar) {
		t.Fatalf("scaled to zero without approval: %v", err)
	}
	if e.jsonpath("deployment", "shop", "{.spec.replicas}") != "2" {
		t.Fatal("the workload went offline")
	}
}

func TestNamespaceDeleteIsUndoneWithEverythingInIt(t *testing.T) {
	e := setup(t)
	e.apply(deployment("svc", 1) + "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: settings}\ndata: {region: eu}\n")
	x := e.m.Begin("tear down " + e.ns)
	call(t, x, "delete", map[string]any{"kind": "namespace", "name": e.ns})
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	e.kubectl("wait", "--for=delete", "namespace/"+e.ns, "--timeout=180s")
	if err := undo(t, x); err != nil {
		t.Fatal(err)
	}
	if e.jsonpath("configmap", "settings", "{.data.region}") != "eu" || !e.exists("deployment", "svc") {
		t.Fatal("undo did not bring back what was in the namespace")
	}
	// owned objects (its ReplicaSet and Pods) are rebuilt by the controller, not copied back
	e.kubectl("-n", e.ns, "wait", "--for=condition=available", "deployment/svc", "--timeout=120s")
}

func TestSecretValuesAreRedacted(t *testing.T) {
	e := setup(t)
	e.kubectl("-n", e.ns, "create", "secret", "generic", "db", "--from-literal=password=hunter2-prod-kube")
	x := e.m.Begin("check the db secret exists")
	r, err := x.Call("kube", "get", map[string]any{"kind": "secret", "name": "db"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "hunter2-prod-kube") || strings.Contains(string(b), "aHVudGVyMi1wcm9kLWt1YmU=") {
		t.Fatalf("secret value reached the agent: %s", b)
	}
	_, _ = x.Rollback("test")
}
