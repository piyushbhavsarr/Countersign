package netguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestKinds(t *testing.T) {
	cases := map[string]string{
		"169.254.169.254": Metadata, "fd00:ec2::254": Metadata, "100.100.100.200": Metadata, "metadata.google.internal": Metadata,
		"127.0.0.1": Loopback, "::1": Loopback, "localhost": Loopback, "app.localhost": Loopback, "::ffff:127.0.0.1": Loopback,
		"169.254.10.1": LinkLocal, "fe80::1": LinkLocal,
		"10.1.2.3": Private, "192.168.0.1": Private, "172.16.5.5": Private, "fd12::1": Private, "100.64.1.1": Private, "0.0.0.0": Private,
		"8.8.8.8": Public, "2606:4700::1111": Public,
	}
	for h, want := range cases {
		if got := HostKind(h); got != want {
			t.Errorf("%s: %s, want %s", h, got, want)
		}
	}
}

func fakeDNS(t *testing.T, m map[string][]string) {
	old := Resolver
	t.Cleanup(func() { Resolver = old })
	Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, a := range m[host] {
			out = append(out, netip.MustParseAddr(a))
		}
		if len(out) == 0 {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
}

func TestANameIsAsBadAsItsWorstAddress(t *testing.T) {
	fakeDNS(t, map[string][]string{"mixed.example": {"8.8.8.8", "10.0.0.1"}, "ok.example": {"1.1.1.1"}})
	if HostKind("mixed.example") != Private || HostKind("ok.example") != Public || HostKind("nope.example") != Unresolved {
		t.Fatal("kinds")
	}
}

func TestInspect(t *testing.T) {
	fakeDNS(t, map[string][]string{"api.example": {"1.1.1.1"}})
	a := Inspect("GET", "https://api.example/v1/users/12345/orders?limit=5", nil, nil)
	b := Inspect("get", "https://API.example/v1/users/99/orders?limit=50", nil, nil)
	c := Inspect("GET", "https://api.example/v1/users/99/orders?limit=5&admin=1", nil, nil)
	if a.Shape != b.Shape || a.Shape == c.Shape {
		t.Fatalf("shapes %s %s %s", a.Shape, b.Shape, c.Shape)
	}
	if !Inspect("GET", "https://u:p@api.example/", nil, nil).UserInfo {
		t.Fatal("userinfo")
	}
	if !Inspect("GET", "https://api.example/", map[string]string{"accept": "x\r\nX-Admin: 1"}, nil).HeaderInjection {
		t.Fatal("header injection")
	}
	if f := Inspect("GET", "file:///etc/passwd", nil, nil); f.Scheme != "file" {
		t.Fatal(f.Scheme)
	}
	if f := Inspect("GET", "http://10.0.0.7/x", nil, []string{"10.0.0.*"}); f.Network != Private || !f.PrivateAllowed {
		t.Fatalf("%+v", f)
	}
}

// The check is made again on the address actually dialled: rebinding, redirects and
// private addresses are refused unless allowed; metadata always.
func TestClientRefusesWhereItDials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	fakeDNS(t, map[string][]string{"rebind.example": {"127.0.0.1"}, "svc.internal": {"127.0.0.1"}})
	get := func(c *http.Client, u string) error {
		resp, err := c.Get(u)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	strict := Client(5*time.Second, nil)
	if err := get(strict, srv.URL); !errors.Is(err, ErrRefused) {
		t.Fatalf("loopback: %v", err)
	}
	if err := get(strict, "http://rebind.example:"+port); !errors.Is(err, ErrRefused) {
		t.Fatalf("a name resolving to loopback: %v", err)
	}
	allowed := Client(5*time.Second, []string{"127.0.0.1", "svc.internal"})
	if err := get(allowed, srv.URL); err != nil {
		t.Fatalf("allowed host: %v", err)
	}
	if err := get(allowed, "http://svc.internal:"+port); err != nil {
		t.Fatalf("allowed name: %v", err)
	}
	if err := get(allowed, srv.URL+"/redirect"); !errors.Is(err, ErrRefused) {
		t.Fatalf("redirect to metadata: %v", err)
	}
	if err := get(Client(5*time.Second, []string{"*"}), "http://169.254.169.254/"); !errors.Is(err, ErrRefused) {
		t.Fatalf("metadata even when everything is allowed: %v", err)
	}
}
