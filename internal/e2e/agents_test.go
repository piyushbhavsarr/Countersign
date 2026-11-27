package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An agent's HTTP request may not reach cloud metadata, private networks, other schemes,
// or carry credentials or line breaks of its own.
func TestHTTPGuardsAgainstSSRFAndSmuggling(t *testing.T) {
	w := world(t)
	x := w.Mgr.Begin("look something up")
	for _, c := range []struct{ url, why string }{
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "metadata"},
		{"http://metadata.google.internal/computeMetadata/v1/", "metadata"},
		{"http://10.0.0.5/admin", "private network"},
		{"http://127.0.0.1:2375/containers/json", "private network"},
		{"file:///etc/passwd", "Only http and https"},
		{"https://user:pass@api.example.com/", "Credentials written into a URL"},
		{"https://api.example.com/x\r\nX-Admin: 1", "line break"},
	} {
		_, err := x.Call("http", "request", map[string]any{"method": "GET", "url": c.url})
		if !isViolation(err) || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%q: want a denial mentioning %q, got %v", c.url, c.why, err)
		}
	}
	_, _ = x.Rollback("done")
}

// API calls that act at once are in the vault before they are sent: the request, then
// the response and the recipe that compensates them; changes lists them.
func TestAPICallsAreKeptInTheVault(t *testing.T) {
	w, c, _, _ := crmWorld(t)
	x := w.Mgr.Begin("charge 900")
	call(t, x, "crm", "update_deal", map[string]any{"id": 88, "stage": "Lost"})
	call(t, x, "crm", "charge", map[string]any{"amount": 900})
	commit(t, w.Mgr, x)
	_ = c
	// a fresh process with only the vault
	if err := os.Remove(filepath.Join(w.State, "tx", x.ID+".json")); err != nil {
		t.Fatal(err)
	}
	_ = w.Mgr.Flush() // another process reads what this one wrote
	m2 := w.MakeManager()
	m2.Vault = w.Mgr.Vault
	crs, err := m2.ChangedRows(x.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, cr := range crs {
		for _, r := range cr.Rows {
			if r.Op == "call" {
				got[r.Table] = true
				if r.Before["request"] == nil || r.After == nil || len(cr.Record) == 0 {
					t.Errorf("%s: request %v, response %v, recipe %d bytes", r.Table, r.Before, r.After, len(cr.Record))
				}
			}
		}
	}
	if !got["crm.charge"] || !got["crm.update_deal"] {
		t.Fatalf("calls in the vault: %v (%+v)", got, crs)
	}
}

// No vault quorum: an API call is not sent at all.
func TestNoVaultQuorumMeansTheCallIsNotSent(t *testing.T) {
	w, c, _, _ := crmWorld(t)
	for _, r := range w.Mgr.Vault.Replicas()[1:] {
		_ = os.RemoveAll(r)
		_ = os.WriteFile(r, []byte("broken"), 0o600)
	}
	c.mu.Lock()
	n0 := len(c.charges) // the verification round trip made (and refunded) one
	c.mu.Unlock()
	x := w.Mgr.Begin("charge 500")
	if _, err := x.Call("crm", "charge", map[string]any{"amount": 500}); err == nil ||
		!strings.Contains(err.Error(), "not sent") {
		t.Fatalf("want refusal, got %v", err)
	}
	c.mu.Lock()
	n := len(c.charges)
	c.mu.Unlock()
	if n != n0 {
		t.Fatalf("%d charges were made without a stored request", n-n0)
	}
	_, _ = x.Rollback("done")
}

// A frozen requester can do nothing anywhere until unfrozen, and cannot commit a task it
// had already staged.
func TestFreezeStopsARequesterEverywhere(t *testing.T) {
	w := world(t)
	x := w.Mgr.Begin("before the freeze")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders WHERE id = 3"})
	if err := w.Mgr.Freeze(x.Requester, "alice", "suspicious deletes"); err != nil {
		t.Fatal(err)
	}
	other := w.MakeManager() // another gateway on the same store
	y := other.Begin("after")
	for _, c := range [][2]string{{"sql", "query"}, {"fs", "read"}, {"http", "request"}} {
		args := map[string]any{"sql": "SELECT 1", "path": "README.md", "method": "GET", "url": "https://api.example.com/"}
		if _, err := y.Call(c[0], c[1], args); !isViolation(err) || !strings.Contains(err.Error(), "suspicious deletes") {
			t.Errorf("%s.%s while frozen: %v", c[0], c[1], err)
		}
	}
	approve(t, w.Mgr, x)
	if _, err := x.Commit(); !isViolation(err) {
		t.Fatalf("commit while frozen: %v", err)
	}
	if n := w.Count("orders", "id = 3"); n != 1 {
		t.Fatal("a frozen task's change was applied")
	}
	if err := w.Mgr.Unfreeze(x.Requester, "alice"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // other gateways see a change to the list within 250ms for reads
	if _, err := y.Call("sql", "query", map[string]any{"sql": "SELECT 1"}); err != nil {
		t.Fatalf("after unfreeze: %v", err)
	}
	l, _ := w.Mgr.FrozenRequesters()
	if len(l) != 0 {
		t.Fatal(fmt.Sprint(l))
	}
	_, _ = x.Rollback("done")
	_, _ = y.Rollback("done")
}
