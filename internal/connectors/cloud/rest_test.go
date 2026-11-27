package cloud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

// fakeARM stands in for Azure Resource Manager: documents by id, etags, conditional PUTs,
// long-running operations, and a property it accepts but never returns (a password).
type fakeARM struct {
	mu    sync.Mutex
	docs  map[string]map[string]any
	etag  int
	ops   map[string]int
	puts  int
	srv   *httptest.Server
	block bool // answer PUTs with 412 (someone else wrote)
}

func newFakeARM(t *testing.T) *fakeARM {
	f := &fakeARM{docs: map[string]map[string]any{}, ops: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeARM) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer arm-token" {
		w.WriteHeader(401)
		return
	}
	reply := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/subscriptions/sub1/providers/Microsoft.Storage") && !strings.Contains(r.URL.Path, "/resourceGroups/"):
		reply(200, map[string]any{"resourceTypes": []any{map[string]any{"resourceType": "storageAccounts",
			"apiVersions": []any{"2024-01-01-preview", "2023-05-01", "2022-09-01"}}}})
		return
	case strings.HasPrefix(r.URL.Path, "/ops/"):
		f.ops[r.URL.Path]++
		if f.ops[r.URL.Path] < 2 {
			reply(200, map[string]any{"status": "InProgress"})
		} else {
			reply(200, map[string]any{"status": "Succeeded"})
		}
		return
	}
	if r.URL.Query().Get("api-version") != "2023-05-01" {
		reply(400, map[string]any{"error": map[string]any{"code": "InvalidApiVersion", "message": r.URL.Query().Get("api-version")}})
		return
	}
	id := r.URL.Path
	doc := f.docs[id]
	switch r.Method {
	case "GET":
		if doc == nil {
			reply(404, map[string]any{"error": map[string]any{"code": "ResourceNotFound"}})
			return
		}
		out := deep(doc)
		if p, ok := out["properties"].(map[string]any); ok {
			delete(p, "adminPassword") // write-only: never returned
		}
		reply(200, out)
	case "PATCH":
		if doc == nil {
			reply(404, map[string]any{"error": map[string]any{"code": "ResourceNotFound"}})
			return
		}
		if m := r.Header.Get("If-Match"); m != "" && doc["etag"] != m {
			reply(412, map[string]any{"error": map[string]any{"code": "PreconditionFailed"}})
			return
		}
		var patch map[string]any
		_ = json.NewDecoder(r.Body).Decode(&patch)
		var merge func(dst, p map[string]any)
		merge = func(dst, p map[string]any) {
			for k, v := range p {
				if v == nil {
					delete(dst, k)
				} else if pm, ok := v.(map[string]any); ok {
					dm, _ := dst[k].(map[string]any)
					if dm == nil {
						dm = map[string]any{}
					}
					merge(dm, pm)
					dst[k] = dm
				} else {
					dst[k] = v
				}
			}
		}
		merge(doc, patch)
		f.etag++
		doc["etag"] = fmt.Sprintf(`W/"%d"`, f.etag)
		reply(200, doc)
	case "PUT":
		f.puts++
		if f.block {
			reply(412, map[string]any{"error": map[string]any{"code": "PreconditionFailed"}})
			return
		}
		if r.Header.Get("If-None-Match") == "*" && doc != nil {
			reply(412, map[string]any{"error": map[string]any{"code": "PreconditionFailed"}})
			return
		}
		if m := r.Header.Get("If-Match"); m != "" && (doc == nil || doc["etag"] != m) {
			reply(412, map[string]any{"error": map[string]any{"code": "PreconditionFailed"}})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, ro := range []string{"id", "name", "type", "etag", "systemData"} {
			if _, ok := body[ro]; ok {
				reply(400, map[string]any{"error": map[string]any{"code": "ReadOnly", "message": ro}})
				return
			}
		}
		if doc != nil && doc["location"] != body["location"] {
			reply(400, map[string]any{"error": map[string]any{"code": "LocationImmutable"}})
			return
		}
		f.etag++
		body["id"], body["name"], body["type"] = id, id[strings.LastIndex(id, "/")+1:], "Microsoft.Storage/storageAccounts"
		body["etag"] = fmt.Sprintf(`W/"%d"`, f.etag)
		if p, ok := body["properties"].(map[string]any); ok {
			p["provisioningState"] = "Succeeded"

		}
		created := doc == nil
		f.docs[id] = body
		if created {
			op := fmt.Sprintf("/ops/%d", f.etag)
			w.Header().Set("Azure-AsyncOperation", f.srv.URL+op)
			reply(201, body)
			return
		}
		reply(200, body)
	case "DELETE":
		if doc == nil {
			w.WriteHeader(204)
			return
		}
		delete(f.docs, id)
		w.WriteHeader(200)
	}
}

func armManager(t *testing.T) (*tx.Manager, *Connector, *fakeARM) {
	f := newFakeARM(t)
	arm := NewARM(f.srv.URL, "sub1", []string{"echo", "arm-token"}, time.Minute)
	old := pollEvery
	pollEvery = time.Millisecond
	t.Cleanup(func() { pollEvery = old })
	d := t.TempDir()
	c := NewResources("azure", d, arm)
	m, err := tx.NewManager(filepath.Join(d, "state"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	m.Register(c)
	return m, c, f
}

const sa = "Microsoft.Storage/storageAccounts"
const saID = "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct1"

func TestAzureVerifyUpdateUndoAndConflicts(t *testing.T) {
	m, c, f := armManager(t)
	desired := map[string]any{"id": saID + "-verify", "location": "westeurope", "sku": map[string]any{"name": "Standard_LRS"},
		"tags": map[string]any{"env": "test"}, "properties": map[string]any{"minimumTlsVersion": "TLS1_2"}}
	if err := c.Verify(sa, desired, []byte(`[{"op":"replace","path":"/tags/env","value":"verify"}]`)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// a real account exists
	f.mu.Lock()
	f.docs[saID] = map[string]any{"id": saID, "location": "westeurope", "etag": `W/"100"`, "tags": map[string]any{"env": "prod", "team": "a"},
		"properties": map[string]any{"minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": false, "adminPassword": "s3cret"}}
	f.mu.Unlock()
	x := m.Begin("open the account to the public")
	if _, err := x.Call("azure", "resource_update", map[string]any{"type": sa, "identifier": saID,
		"patch": []any{map[string]any{"op": "replace", "path": "/properties/allowBlobPublicAccess", "value": true}}}); err != nil {
		t.Fatal(err)
	}
	if x.Actions[0].Effect != model.Reversible {
		t.Fatalf("a verified type should be reversible: %s", x.Actions[0].Effect)
	}
	if _, err := x.Commit(); err == nil || !strings.Contains(err.Error(), "whole internet") {
		t.Fatalf("opening public access must wait for a person: %v", err)
	}
	approveTx(t, m, x)
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if dig(f.docs[saID], "properties", "allowBlobPublicAccess") != true {
		t.Fatal("not applied")
	}
	// someone else changes a tag since; undo reverts only what the task changed
	f.mu.Lock()
	f.docs[saID]["tags"].(map[string]any)["team"] = "b"
	f.mu.Unlock()
	if rep, err := x.Undo(""); err != nil || !rep.Clean() {
		t.Fatalf("undo: %v %+v", err, rep)
	}
	if dig(f.docs[saID], "properties", "allowBlobPublicAccess") != false || dig(f.docs[saID], "tags", "team") != "b" {
		t.Fatalf("undo: %v", f.docs[saID])
	}
	if f.docs[saID]["properties"].(map[string]any)["adminPassword"] != "s3cret" {
		t.Fatal("a secret the cloud never returns was lost: updates must send only what changed")
	}
	// a property the cloud never returns cannot be undone: it waits for a person
	y := m.Begin("rotate the password")
	r, err := y.Call("azure", "resource_update", map[string]any{"type": sa, "identifier": saID,
		"patch": []any{map[string]any{"op": "replace", "path": "/properties/adminPassword", "value": "new"}}})
	if err != nil || !strings.Contains(fmt.Sprint(r), "held") {
		t.Fatalf("write-only change: %v %v", r, err)
	}
	_, _ = y.Rollback("done")
	// a change made by someone else between staging and commit stops the commit
	z := m.Begin("tls 1.3")
	if _, err := z.Call("azure", "resource_update", map[string]any{"type": sa, "identifier": saID,
		"patch": []any{map[string]any{"op": "replace", "path": "/properties/minimumTlsVersion", "value": "TLS1_3"}}}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.docs[saID]["properties"].(map[string]any)["minimumTlsVersion"] = "TLS1_0"
	f.mu.Unlock()
	if _, err := z.Commit(); err == nil {
		t.Fatal("commit over someone else's change")
	}
	if dig(f.docs[saID], "properties", "minimumTlsVersion") != "TLS1_0" {
		t.Fatal("overwrote someone else's change")
	}
}

func TestAzureCreateIsIdempotentAndUndoDeletes(t *testing.T) {
	m, c, f := armManager(t)
	if err := c.Verify(sa, map[string]any{"id": saID + "-v", "location": "westeurope"},
		[]byte(`[{"op":"add","path":"/tags","value":{"a":"b"}}]`)); err != nil {
		t.Fatal(err)
	}
	x := m.Begin("new account")
	if _, err := x.Call("azure", "resource_create", map[string]any{"type": sa,
		"desired_state": map[string]any{"id": saID + "-new", "location": "westeurope"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if f.docs[saID+"-new"] == nil {
		t.Fatal("not created")
	}
	arm := c.CC.(*ARMResources)
	tok := f.docs[saID+"-new"]["tags"].(map[string]any)[tokenTag].(string)
	if id, err := arm.Create(sa, map[string]any{"id": saID + "-new", "location": "westeurope"}, tok); err != nil || id != saID+"-new" {
		t.Fatalf("retried create with the same token: %v %v", id, err)
	}
	if _, err := arm.Create(sa, map[string]any{"id": saID + "-new", "location": "westeurope"}, "other"); err == nil {
		t.Fatal("a create with another token took over an existing resource")
	}
	if _, err := x.Undo(""); err != nil {
		t.Fatal(err)
	}
	if f.docs[saID+"-new"] != nil {
		t.Fatal("undo did not delete what the task created")
	}
}

// fakeGCP: a Compute-style API (operations with selfLink) behind PATCH with updateMask.
type fakeGCP struct {
	mu   sync.Mutex
	docs map[string]map[string]any
	n    int
	srv  *httptest.Server
	ops  map[string]string // op url -> target
}

func newFakeGCP(t *testing.T) *fakeGCP {
	f := &fakeGCP{docs: map[string]map[string]any{}, ops: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGCP) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(code int, v any) { w.WriteHeader(code); _ = json.NewEncoder(w).Encode(v) }
	if r.Header.Get("Authorization") != "Bearer gcp-token" {
		w.WriteHeader(401)
		return
	}
	u := f.srv.URL + r.URL.Path
	op := func(target string) map[string]any {
		f.n++
		ou := fmt.Sprintf("%s/compute/v1/operations/op%d", f.srv.URL, f.n)
		f.ops[ou] = target
		return map[string]any{"kind": "compute#operation", "status": "RUNNING", "selfLink": ou, "targetLink": target}
	}
	switch {
	case strings.Contains(r.URL.Path, "/operations/"):
		reply(200, map[string]any{"kind": "compute#operation", "status": "DONE", "selfLink": u, "targetLink": f.ops[u]})
	case r.URL.Path == "/compute/v1/projects/p/global/firewalls" && r.Method == "POST":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := f.srv.URL + "/compute/v1/projects/p/global/firewalls/" + fmt.Sprint(body["name"])
		body["selfLink"], body["id"], body["creationTimestamp"] = id, "123", "now"
		f.docs[id] = body
		reply(200, op(id))
	case r.URL.Path == "/compute/v1/projects/p/global/firewalls" && r.Method == "GET":
		var items []any
		for _, d := range f.docs {
			items = append(items, d)
		}
		reply(200, map[string]any{"items": items})
	default:
		doc := f.docs[u]
		switch r.Method {
		case "GET":
			if doc == nil {
				reply(404, map[string]any{"error": map[string]any{"code": 404, "message": "not found"}})
				return
			}
			reply(200, doc)
		case "PATCH":
			var body map[string]any
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			for _, k := range strings.Split(r.URL.Query().Get("updateMask"), ",") {
				if k == "" {
					continue
				}
				top := strings.Split(k, ".")[0]
				if v, ok := body[top]; ok && v != nil {
					doc[top] = v
				} else {
					delete(doc, top)
				}
			}
			reply(200, op(u))
		case "DELETE":
			delete(f.docs, u)
			reply(200, op(u))
		}
	}
}

func TestGoogleCloudVerifyUpdateUndoCreateDelete(t *testing.T) {
	f := newFakeGCP(t)
	old := pollEvery
	pollEvery = time.Millisecond
	defer func() { pollEvery = old }()
	coll := f.srv.URL + "/compute/v1/projects/p/global/firewalls"
	g := NewGCP(map[string]GCPType{"compute.googleapis.com/Firewall": {Collection: coll, Update: "mask"}},
		[]string{"echo", "gcp-token"}, time.Minute)
	d := t.TempDir()
	c := NewResources("gcp", d, g)
	m, _ := tx.NewManager(filepath.Join(d, "state"), policy.Default())
	m.Register(c)
	const fw = "compute.googleapis.com/Firewall"
	if err := c.Verify(fw, map[string]any{"name": "verify-fw", "sourceRanges": []any{"10.0.0.0/8"}},
		[]byte(`[{"op":"replace","path":"/sourceRanges","value":["10.1.0.0/16"]}]`)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	x := m.Begin("open ssh to the world")
	if _, err := x.Call("gcp", "resource_create", map[string]any{"type": fw,
		"desired_state": map[string]any{"name": "ssh", "sourceRanges": []any{"10.0.0.0/8"}, "allowed": []any{map[string]any{"IPProtocol": "tcp", "ports": []any{"22"}}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	id := coll + "/ssh"
	if f.docs[id] == nil {
		t.Fatal("not created")
	}
	y := m.Begin("widen it")
	if _, err := y.Call("gcp", "resource_update", map[string]any{"type": fw, "identifier": id,
		"patch": []any{map[string]any{"op": "replace", "path": "/sourceRanges", "value": []any{"0.0.0.0/0"}}}}); err != nil {
		t.Fatal(err)
	}
	approveTx(t, m, y)
	if _, err := y.Commit(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.docs[id]["sourceRanges"]) != "[0.0.0.0/0]" {
		t.Fatalf("update: %v", f.docs[id])
	}
	if _, err := y.Undo(""); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.docs[id]["sourceRanges"]) != "[10.0.0.0/8]" {
		t.Fatalf("undo: %v", f.docs[id])
	}
	if _, err := x.Undo(""); err != nil {
		t.Fatal(err)
	}
	if f.docs[id] != nil {
		t.Fatal("undo of the create did not delete it")
	}
	// an unconfigured type is refused with what to configure
	z := m.Begin("bucket")
	if _, err := z.Call("gcp", "resource_create", map[string]any{"type": "storage.googleapis.com/Bucket",
		"desired_state": map[string]any{"name": "b"}}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unconfigured type: %v", err)
	}
}

func TestPublicExposureIsFoundOnEveryCloud(t *testing.T) {
	cases := []struct {
		v    any
		want bool
	}{
		{map[string]any{"sourceRanges": []any{"0.0.0.0/0"}}, true},                                         // GCP firewall
		{map[string]any{"SecurityGroupIngress": []any{map[string]any{"CidrIpv6": "::/0"}}}, true},          // AWS
		{map[string]any{"properties": map[string]any{"sourceAddressPrefix": "Internet"}}, true},            // Azure NSG
		{map[string]any{"properties": map[string]any{"allowBlobPublicAccess": true}}, true},                // Azure storage
		{map[string]any{"properties": map[string]any{"publicNetworkAccess": "Enabled"}}, true},             // Azure
		{map[string]any{"PublicAccessBlockConfiguration": map[string]any{"BlockPublicAcls": true}}, false}, // AWS S3: a block
		{map[string]any{"sourceRanges": []any{"10.0.0.0/8"}}, false},
	}
	for _, c := range cases {
		if got := len(exposure(c.v, "", nil)) > 0; got != c.want {
			t.Errorf("%v: %v", c.v, got)
		}
	}
}

func approveTx(t *testing.T, m *tx.Manager, x *tx.Tx) {
	t.Helper()
	if err := x.Approve("op", m.ApprovalToken(x.ID, x.PreviewHash())); err != nil {
		t.Fatal(err)
	}
}
