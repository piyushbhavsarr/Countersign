package cloud

// Azure and Google Cloud resources, behind the same interface as AWS Cloud Control, so they
// get the same treatment: creates checked and run on commit (undo deletes them), updates as
// a JSON Patch over the resource's document (undo is a three-way revert of only what the
// commit changed, refused if those properties changed again since), deletes irreversible,
// a check before commit that nobody changed what is about to be overwritten, and a type
// undoable only after `undolayer azure|gcp verify` did a real round trip with it.
//
// Azure: Resource Manager is one uniform API. A resource is addressed by its full id
// (/subscriptions/.../providers/Microsoft.Storage/storageAccounts/name). Creates are PUTs
// (If-None-Match: *); updates are a merge PATCH of only what changed, guarded by the etag,
// so properties Azure never returns (secrets) are not touched; long-running operations
// are followed to the end. The API version of each type is configured or discovered.
//
// Google Cloud: there is no one API, but resources are REST documents addressed by their
// URL (selfLink). Each type to manage is configured: the collection to create in, how
// updates are sent (PATCH with an update mask, a merge PATCH, or PUT), and which fields
// the cloud sets (read-only) or keeps secret (write-only). Operations are followed to the end.
//
// Idempotent create: the client token is written as a tag (Azure) or label (GCP), so a
// create retried after a crash finds the resource it made instead of making another, and
// never mistakes someone else's resource for it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

const tokenTag = "countersign-client-token"

// Bearer gets an access token by running a command (az, gcloud), cached for a while.
type Bearer struct {
	Command []string
	TTL     time.Duration
	mu      sync.Mutex
	tok     string
	at      time.Time
}

func (b *Bearer) token(refresh bool) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ttl := b.TTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if !refresh && b.tok != "" && time.Since(b.at) < ttl {
		return b.tok, nil
	}
	if len(b.Command) == 0 {
		return "", errors.New("no token command configured")
	}
	out, err := exec.Command(b.Command[0], b.Command[1:]...).Output()
	if err != nil {
		return "", fmt.Errorf("token command %s: %v", b.Command[0], err)
	}
	b.tok, b.at = strings.TrimSpace(string(out)), time.Now()
	if b.tok == "" {
		return "", fmt.Errorf("token command %s printed nothing", b.Command[0])
	}
	return b.tok, nil
}

type restClient struct {
	auth    *Bearer
	http    *http.Client
	timeout time.Duration
}

type restResp struct {
	status int
	header http.Header
	body   map[string]any
	raw    []byte
}

// do sends one request with the bearer token (refreshed once on 401).
func (c *restClient) do(method, u string, body any, headers map[string]string) (*restResp, error) {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.auth.token(attempt > 0)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(method, u, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 401 && attempt == 0 {
			continue
		}
		r := &restResp{status: resp.StatusCode, header: resp.Header, raw: raw}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &r.body)
		}
		return r, nil
	}
	return nil, errors.New("unauthorized")
}

func (r *restResp) err(what string) error {
	msg := strings.TrimSpace(string(r.raw))
	if e, ok := r.body["error"].(map[string]any); ok {
		msg = fmt.Sprintf("%v: %v", firstOf(e, "code", "status"), e["message"])
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return fmt.Errorf("%s: HTTP %d: %s", what, r.status, msg)
}

func firstOf(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return ""
}

func digest(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

func rawProps(names ...string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, n := range names {
		out[n] = json.RawMessage(`{}`)
	}
	return out
}

func strip(doc map[string]any, readOnly []string) map[string]any {
	out := deep(doc)
	for _, p := range readOnly {
		segs := segments(p)
		cur := out
		for i, s := range segs {
			if i == len(segs)-1 {
				delete(cur, s)
				break
			}
			next, ok := cur[s].(map[string]any)
			if !ok {
				break
			}
			cur = next
		}
	}
	return out
}

// ======================================================================== Azure

// ARMResources is Azure Resource Manager.
type ARMResources struct {
	BaseURL      string            // default https://management.azure.com
	Subscription string            // for discovering API versions
	APIVersions  map[string]string // type -> api-version (overrides discovery)
	WriteOnly    map[string][]string
	// PutTypes: types whose provider does not accept PATCH; they are updated by PUT of the
	// whole document (which some providers treat as clearing fields they never return).
	PutTypes map[string]bool
	Timeout  time.Duration
	c        *restClient
	mu       sync.Mutex
	versions map[string]string
}

// NewARM: tokens from `az account get-access-token` unless tokenCmd says otherwise.
func NewARM(base, subscription string, tokenCmd []string, timeout time.Duration) *ARMResources {
	if base == "" {
		base = "https://management.azure.com"
	}
	if len(tokenCmd) == 0 {
		tokenCmd = []string{"az", "account", "get-access-token", "--resource", "https://management.azure.com/", "--query", "accessToken", "-o", "tsv"}
	}
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	return &ARMResources{BaseURL: strings.TrimSuffix(base, "/"), Subscription: subscription, Timeout: timeout,
		APIVersions: map[string]string{}, WriteOnly: map[string][]string{}, PutTypes: map[string]bool{}, versions: map[string]string{},
		c: &restClient{auth: &Bearer{Command: tokenCmd}, http: &http.Client{Timeout: 2 * time.Minute}}}
}

var armReadOnly = []string{"/properties/id", "/properties/name", "/properties/type", "/properties/etag",
	"/properties/systemData", "/properties/properties/provisioningState"}

func (a *ARMResources) apiVersion(typ string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v := a.APIVersions[typ]; v != "" {
		return v, nil
	}
	if v := a.versions[typ]; v != "" {
		return v, nil
	}
	ns, rest, ok := strings.Cut(typ, "/")
	if !ok || a.Subscription == "" {
		return "", fmt.Errorf("%s: set [azure] api_versions for it, or [azure] subscription to discover it", typ)
	}
	r, err := a.c.do("GET", fmt.Sprintf("%s/subscriptions/%s/providers/%s?api-version=2021-04-01", a.BaseURL, a.Subscription, ns), nil, nil)
	if err != nil {
		return "", err
	}
	if r.status != 200 {
		return "", r.err("discovering the API version of " + typ)
	}
	rts, _ := r.body["resourceTypes"].([]any)
	for _, x := range rts {
		rt, _ := x.(map[string]any)
		if !strings.EqualFold(str(rt["resourceType"]), rest) {
			continue
		}
		vs, _ := rt["apiVersions"].([]any)
		var stable []string
		for _, v := range vs {
			if s := str(v); !strings.Contains(s, "preview") {
				stable = append(stable, s)
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(stable)))
		if len(stable) > 0 {
			a.versions[typ] = stable[0]
			return stable[0], nil
		}
	}
	return "", fmt.Errorf("%s: the provider lists no stable API version", typ)
}

func (a *ARMResources) Schema(typ string) (*Schema, error) {
	v, err := a.apiVersion(typ)
	if err != nil {
		return nil, err
	}
	yes := true
	return &Schema{TypeName: typ, Properties: rawProps("id", "name", "type", "location", "tags", "properties", "sku", "kind",
		"identity", "zones", "plan", "extendedLocation", "managedBy", "etag"),
		// the id is given on create (it is where the resource goes) and never changes after
		Required: []string{"id"}, ReadOnly: armReadOnly[1:], CreateOnly: []string{"/properties/id", "/properties/location"},
		WriteOnly: a.WriteOnly[typ], PrimaryID: []string{"/properties/id"}, AdditionalOK: &yes,
		Digest: digest("azure", typ, v, strings.Join(a.WriteOnly[typ], ","))}, nil
}

func (a *ARMResources) url(typ, id string) (string, error) {
	if !strings.HasPrefix(id, "/subscriptions/") {
		return "", fmt.Errorf("%s: the identifier must be the full resource id (/subscriptions/...)", typ)
	}
	v, err := a.apiVersion(typ)
	if err != nil {
		return "", err
	}
	return a.BaseURL + id + "?api-version=" + url.QueryEscape(v), nil
}

func (a *ARMResources) Get(typ, id string) (map[string]any, error) {
	u, err := a.url(typ, id)
	if err != nil {
		return nil, err
	}
	r, err := a.c.do("GET", u, nil, nil)
	if err != nil {
		return nil, err
	}
	switch {
	case r.status == 404:
		return nil, nil
	case r.status != 200:
		return nil, r.err("reading " + id)
	}
	return r.body, nil
}

func (a *ARMResources) List(typ string) (any, error) {
	if a.Subscription == "" {
		return nil, errors.New("[azure] subscription is needed to list resources")
	}
	v, err := a.apiVersion(typ)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/subscriptions/%s/resources?api-version=2021-04-01&$filter=%s", a.BaseURL, a.Subscription,
		url.QueryEscape("resourceType eq '"+typ+"'"))
	_ = v
	r, err := a.c.do("GET", u, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.err("listing " + typ)
	}
	return r.body, nil
}

// wait follows an Azure long-running operation to its end.
func (a *ARMResources) wait(r *restResp, typ, id, what string) error {
	deadline := time.Now().Add(a.Timeout)
	poll := r.header.Get("Azure-AsyncOperation")
	loc := r.header.Get("Location")
	for {
		switch {
		case poll != "":
			s, err := a.c.do("GET", poll, nil, nil)
			if err != nil {
				return err
			}
			switch strings.ToLower(str(s.body["status"])) {
			case "succeeded":
				return nil
			case "failed", "canceled", "cancelled":
				return s.err(what)
			}
		case loc != "" && (r.status == 202 || r.status == 201):
			s, err := a.c.do("GET", loc, nil, nil)
			if err != nil {
				return err
			}
			if s.status == 200 || s.status == 204 {
				return nil
			}
			if s.status != 202 {
				return s.err(what)
			}
		default: // a resource that reports provisioningState
			if what == "deleting "+id {
				doc, err := a.Get(typ, id)
				if err != nil || doc == nil {
					return err
				}
			} else {
				doc, err := a.Get(typ, id)
				if err != nil {
					return err
				}
				state := strings.ToLower(str(dig(doc, "properties", "provisioningState")))
				switch state {
				case "", "succeeded":
					return nil
				case "failed", "canceled":
					return fmt.Errorf("%s: provisioningState %s", what, state)
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not finish within %s", what, a.Timeout)
		}
		time.Sleep(pollEvery)
	}
}

// pollEvery: how often long-running operations are polled (a var for tests).
var pollEvery = 2 * time.Second

func (a *ARMResources) Create(typ string, desired map[string]any, token string) (string, error) {
	id := str(desired["id"])
	if id == "" {
		return "", fmt.Errorf("%s: desired_state needs the id of the resource to create", typ)
	}
	cur, err := a.Get(typ, id)
	if err != nil {
		return "", err
	}
	if cur != nil {
		if tags, _ := cur["tags"].(map[string]any); str(tags[tokenTag]) == token {
			return id, nil // made by the request this token belongs to
		}
		return "", fmt.Errorf("%s already exists; update it instead", id)
	}
	body := deep(desired)
	delete(body, "id")
	tags, _ := body["tags"].(map[string]any)
	if tags == nil {
		tags = map[string]any{}
	}
	tags[tokenTag] = token
	body["tags"] = tags
	u, err := a.url(typ, id)
	if err != nil {
		return "", err
	}
	r, err := a.c.do("PUT", u, body, map[string]string{"If-None-Match": "*"})
	if err != nil {
		return "", err
	}
	if r.status != 200 && r.status != 201 && r.status != 202 {
		return "", r.err("creating " + id)
	}
	return id, a.wait(r, typ, id, "creating "+id)
}

func (a *ARMResources) Update(typ, id string, patch []byte) error {
	cur, err := a.Get(typ, id)
	if err != nil {
		return err
	}
	if cur == nil {
		return fmt.Errorf("%s does not exist", id)
	}
	next, err := applyPatch(cur, patch)
	if err != nil {
		return err
	}
	h := map[string]string{}
	if e := str(cur["etag"]); e != "" {
		h["If-Match"] = e // nobody changed it between our read and this write
	}
	u, err := a.url(typ, id)
	if err != nil {
		return err
	}
	method, body := "PATCH", mergePatch(strip(cur, armReadOnly), strip(next, armReadOnly))
	if a.PutTypes[typ] {
		method, body = "PUT", strip(next, armReadOnly)
	}
	if len(body) == 0 && method == "PATCH" {
		return nil
	}
	r, err := a.c.do(method, u, body, h)
	if err != nil {
		return err
	}
	if r.status == 412 {
		return fmt.Errorf("%s changed while it was being updated; nothing was written", id)
	}
	if r.status != 200 && r.status != 201 && r.status != 202 {
		return r.err("updating " + id)
	}
	return a.wait(r, typ, id, "updating "+id)
}

func (a *ARMResources) Delete(typ, id string) error {
	u, err := a.url(typ, id)
	if err != nil {
		return err
	}
	r, err := a.c.do("DELETE", u, nil, nil)
	if err != nil {
		return err
	}
	switch r.status {
	case 200, 204, 404:
		return nil
	case 202:
		return a.wait(r, typ, id, "deleting "+id)
	}
	return r.err("deleting " + id)
}

// ======================================================================== Google Cloud

// GCPType configures one Google Cloud resource type.
type GCPType struct {
	// Collection: where creates are POSTed, e.g.
	// https://storage.googleapis.com/storage/v1/b?project=my-project
	Collection string `toml:"collection"`
	// Update: "mask" (PATCH with updateMask, AIP-134), "merge" (PATCH with the changed
	// fields) or "put" (the whole document).
	Update    string   `toml:"update"`
	ReadOnly  []string `toml:"read_only"`  // fields the cloud sets (top-level or a/b paths)
	WriteOnly []string `toml:"write_only"` // fields the cloud never returns
	// CreateOnly: fields that cannot change after create.
	CreateOnly []string `toml:"create_only"`
}

// GCPResources is Google Cloud REST, resource by resource.
type GCPResources struct {
	Types   map[string]GCPType
	Timeout time.Duration
	c       *restClient
}

// NewGCP: tokens from `gcloud auth print-access-token` unless tokenCmd says otherwise.
func NewGCP(types map[string]GCPType, tokenCmd []string, timeout time.Duration) *GCPResources {
	if len(tokenCmd) == 0 {
		tokenCmd = []string{"gcloud", "auth", "print-access-token"}
	}
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	return &GCPResources{Types: types, Timeout: timeout,
		c: &restClient{auth: &Bearer{Command: tokenCmd}, http: &http.Client{Timeout: 2 * time.Minute}}}
}

var gcpReadOnly = []string{"id", "selfLink", "kind", "creationTimestamp", "timeCreated", "updated", "etag", "fingerprint",
	"metageneration", "generation", "createTime", "updateTime"}

func (g *GCPResources) typ(name string) (GCPType, error) {
	t, ok := g.Types[name]
	if !ok {
		return t, fmt.Errorf("%s is not configured: add [gcp.types.%q] with its collection and update mode", name, name)
	}
	return t, nil
}

func ptrs(fields []string) []string {
	out := []string{}
	for _, f := range fields {
		out = append(out, "/properties/"+strings.Trim(f, "/"))
	}
	return out
}

func (g *GCPResources) Schema(name string) (*Schema, error) {
	t, err := g.typ(name)
	if err != nil {
		return nil, err
	}
	yes := true
	ro := ptrs(append(append([]string{}, gcpReadOnly...), t.ReadOnly...))
	return &Schema{TypeName: name, Properties: rawProps("name"), ReadOnly: ro, CreateOnly: ptrs(append([]string{"name"}, t.CreateOnly...)),
		WriteOnly: ptrs(t.WriteOnly), AdditionalOK: &yes,
		Digest: digest("gcp", name, t.Collection, t.Update, strings.Join(t.ReadOnly, ","), strings.Join(t.WriteOnly, ","),
			strings.Join(t.CreateOnly, ","))}, nil
}

func (g *GCPResources) Get(name, id string) (map[string]any, error) {
	if !strings.HasPrefix(id, "https://") && !strings.HasPrefix(id, "http://") {
		return nil, fmt.Errorf("%s: the identifier must be the resource's URL (selfLink)", name)
	}
	r, err := g.c.do("GET", id, nil, nil)
	if err != nil {
		return nil, err
	}
	switch {
	case r.status == 404:
		return nil, nil
	case r.status != 200:
		return nil, r.err("reading " + id)
	}
	return r.body, nil
}

func (g *GCPResources) List(name string) (any, error) {
	t, err := g.typ(name)
	if err != nil {
		return nil, err
	}
	r, err := g.c.do("GET", t.Collection, nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.err("listing " + name)
	}
	return r.body, nil
}

// wait follows a Google Cloud operation (Compute's or google.longrunning's) to its end and
// returns the resource it acted on, if it says.
func (g *GCPResources) wait(r *restResp, what string) (string, error) {
	op := r.body
	isOp := strings.HasSuffix(str(op["kind"]), "#operation") || (op["name"] != nil && op["done"] != nil)
	if !isOp {
		return str(op["selfLink"]), nil
	}
	deadline := time.Now().Add(g.Timeout)
	for {
		if e, ok := op["error"].(map[string]any); ok {
			b, _ := json.Marshal(e)
			return "", fmt.Errorf("%s: %s", what, b)
		}
		if op["done"] == true || strings.EqualFold(str(op["status"]), "DONE") {
			target := str(op["targetLink"])
			if resp, ok := op["response"].(map[string]any); ok && target == "" {
				target = str(resp["selfLink"])
			}
			return target, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("%s did not finish within %s", what, g.Timeout)
		}
		time.Sleep(pollEvery)
		next := str(op["selfLink"])
		if next == "" { // google.longrunning: GET {scheme://host/version}/{name}
			u, err := url.Parse(r.header.Get("X-Request-URL"))
			if err != nil || u.Host == "" {
				return "", fmt.Errorf("%s: cannot follow operation %v", what, op["name"])
			}
			ver := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)[0]
			next = u.Scheme + "://" + u.Host + "/" + ver + "/" + str(op["name"])
		}
		s, err := g.c.do("GET", next, nil, nil)
		if err != nil {
			return "", err
		}
		if s.status != 200 {
			return "", s.err(what)
		}
		s.header.Set("X-Request-URL", next)
		r, op = s, s.body
	}
}

func (g *GCPResources) doTracked(method, u string, body any) (*restResp, error) {
	r, err := g.c.do(method, u, body, nil)
	if err == nil {
		r.header.Set("X-Request-URL", u)
	}
	return r, err
}

func (g *GCPResources) Create(name string, desired map[string]any, token string) (string, error) {
	t, err := g.typ(name)
	if err != nil {
		return "", err
	}
	// a label holds the token (labels: lowercase letters, digits, dashes)
	label := strings.ToLower(strings.ReplaceAll(token, "_", "-"))
	if len(label) > 63 {
		label = label[:63]
	}
	if found, err := g.findByLabel(t, label); err != nil || found != "" {
		return found, err
	}
	body := deep(desired)
	labels, _ := body["labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
	}
	labels[tokenTag] = label
	body["labels"] = labels
	r, err := g.doTracked("POST", t.Collection, body)
	if err != nil {
		return "", err
	}
	if r.status != 200 && r.status != 201 && r.status != 202 {
		return "", r.err("creating " + name)
	}
	id, err := g.wait(r, "creating "+name)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("creating %s: the cloud did not say where the resource is", name)
	}
	return id, nil
}

// findByLabel: the resource a create with this token made, if any.
func (g *GCPResources) findByLabel(t GCPType, label string) (string, error) {
	r, err := g.c.do("GET", t.Collection, nil, nil)
	if err != nil {
		return "", err
	}
	if r.status != 200 {
		return "", nil // listing is not possible: the create goes ahead
	}
	for _, v := range r.body {
		items, ok := v.([]any)
		if !ok {
			continue
		}
		for _, it := range items {
			m, _ := it.(map[string]any)
			if l, _ := m["labels"].(map[string]any); str(l[tokenTag]) == label {
				return str(m["selfLink"]), nil
			}
		}
	}
	return "", nil
}

func (g *GCPResources) Update(name, id string, patch []byte) error {
	t, err := g.typ(name)
	if err != nil {
		return err
	}
	cur, err := g.Get(name, id)
	if err != nil {
		return err
	}
	if cur == nil {
		return fmt.Errorf("%s does not exist", id)
	}
	next, err := applyPatch(cur, patch)
	if err != nil {
		return err
	}
	ro := append(append([]string{}, gcpReadOnly...), t.ReadOnly...)
	var r *restResp
	switch t.Update {
	case "put":
		body := strip(next, ptrs(ro))
		if e := cur["etag"]; e != nil {
			body["etag"] = e // optimistic concurrency where the API supports it
		}
		if f := cur["fingerprint"]; f != nil {
			body["fingerprint"] = f
		}
		r, err = g.doTracked("PUT", id, body)
	case "merge", "mask":
		changed := mergePatch(strip(cur, ptrs(ro)), strip(next, ptrs(ro)))
		if len(changed) == 0 {
			return nil
		}
		if f := cur["fingerprint"]; f != nil {
			changed["fingerprint"] = f
		}
		u := id
		if t.Update == "mask" {
			mask := maskPaths(changed, "")
			var keep []string
			for _, p := range mask {
				if p != "fingerprint" {
					keep = append(keep, p)
				}
			}
			sep := "?"
			if strings.Contains(u, "?") {
				sep = "&"
			}
			u += sep + "updateMask=" + url.QueryEscape(strings.Join(keep, ","))
		}
		r, err = g.doTracked("PATCH", u, changed)
	default:
		return fmt.Errorf("%s: update must be mask, merge or put", name)
	}
	if err != nil {
		return err
	}
	if r.status == 412 {
		return fmt.Errorf("%s changed while it was being updated; nothing was written", id)
	}
	if r.status != 200 && r.status != 201 && r.status != 202 {
		return r.err("updating " + id)
	}
	_, err = g.wait(r, "updating "+id)
	return err
}

func (g *GCPResources) Delete(name, id string) error {
	r, err := g.doTracked("DELETE", id, nil)
	if err != nil {
		return err
	}
	switch r.status {
	case 404:
		return nil
	case 200, 202, 204:
		if len(r.raw) == 0 {
			return nil
		}
		_, err = g.wait(r, "deleting "+id)
		return err
	}
	return r.err("deleting " + id)
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// mergePatch is the JSON merge patch (RFC 7396) that turns from into to: only what changed,
// nested objects descended into, removals as null. Fields the cloud never returns (secrets)
// are absent from both, so they are not in the patch and stay as they are.
func mergePatch(from, to map[string]any) map[string]any {
	out := map[string]any{}
	for k, tv := range to {
		fv, ok := from[k]
		if !ok {
			out[k] = tv
			continue
		}
		fm, fok := fv.(map[string]any)
		tm, tok := tv.(map[string]any)
		if fok && tok {
			if sub := mergePatch(fm, tm); len(sub) > 0 {
				out[k] = sub
			}
			continue
		}
		if !jsonEqual(fv, tv) {
			out[k] = tv
		}
	}
	for k := range from {
		if _, ok := to[k]; !ok {
			out[k] = nil
		}
	}
	return out
}

// maskPaths lists the leaf field paths a merge patch writes (a.b.c).
func maskPaths(p map[string]any, prefix string) []string {
	var out []string
	for k, v := range p {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if m, ok := v.(map[string]any); ok && len(m) > 0 {
			out = append(out, maskPaths(m, path)...)
		} else {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}
