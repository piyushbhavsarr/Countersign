package egress

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func client(proxyAddr string) *http.Client {
	u, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}

func TestProxyAllowsOnlyListedHosts(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "hello") }))
	defer up.Close()
	var log []Decision
	p := &Proxy{Allow: []string{"127.0.0.1"}, OnDecision: func(d Decision) { log = append(log, d) }}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go p.Serve(l)
	defer p.Close()
	c := client(l.Addr().String())

	resp, err := c.Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "hello" {
		t.Fatalf("allowed host: %d %q", resp.StatusCode, b)
	}
	resp, err = c.Get("http://example.com/")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("forbidden host got %d", resp.StatusCode)
		}
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "secure") }))
	defer tls.Close()
	tc := tls.Client()
	tc.Transport.(*http.Transport).Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: l.Addr().String()})
	resp, err = tc.Get(tls.URL) // CONNECT tunnel to an allowed host
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "secure" {
		t.Fatalf("tunnel: %q", b)
	}
	p.Allow = nil
	// a brand-new transport (no pooled tunnel), so a new CONNECT is attempted
	tc2 := &http.Client{Transport: &http.Transport{TLSClientConfig: tc.Transport.(*http.Transport).TLSClientConfig.Clone(),
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: l.Addr().String()})}}
	if _, err := tc2.Get(tls.URL); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("tunnel to a no-longer-allowed host: %v", err)
	}
	if len(log) != 4 || !log[0].Allowed || log[1].Allowed || !log[2].Allowed || log[3].Allowed {
		t.Fatalf("decisions not recorded correctly: %+v", log)
	}
}

func TestBridgeForwardsToUnixSocket(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "via-bridge") }))
	defer up.Close()
	p := &Proxy{Allow: []string{"127.0.0.1"}}
	sock := t.TempDir() + "/p.sock"
	ul, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(ul)
	defer p.Close()
	bl, err := Bridge("127.0.0.1:0", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	resp, err := client(bl.Addr().String()).Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "via-bridge" {
		t.Fatalf("%q", b)
	}
}

func TestSafeOnlyPassesReadsAndRefusesWritesOverHTTPAndHTTPS(t *testing.T) {
	var got []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method)
		_, _ = io.WriteString(w, "ok")
	})
	plain := httptest.NewServer(h)
	defer plain.Close()
	secure := httptest.NewTLSServer(h)
	defer secure.Close()
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	up := x509.NewCertPool()
	up.AddCert(secure.Certificate())
	p := &Proxy{Allow: []string{"127.0.0.1"}, SafeOnly: true, CA: ca, UpstreamTLS: &tls.Config{RootCAs: up}}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go p.Serve(l)
	defer p.Close()
	trust := x509.NewCertPool()
	trust.AppendCertsFromPEM(ca.PEM)
	pu, _ := url.Parse("http://" + l.Addr().String())
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: trust}}}
	for _, base := range []string{plain.URL, secure.URL} {
		for _, m := range []string{"GET", "POST", "DELETE", "PUT"} {
			req, _ := http.NewRequest(m, base+"/x", strings.NewReader("data"))
			resp, err := c.Do(req)
			code := 0
			if err == nil {
				code = resp.StatusCode
				resp.Body.Close()
			}
			if want := map[string]int{"GET": 200}[m]; (want == 200) != (code == 200) {
				t.Errorf("%s %s: status %d err %v", m, base, code, err)
			}
		}
	}
	for _, m := range got {
		if m != "GET" {
			t.Fatalf("a %s reached the server", m)
		}
	}
	if len(got) != 2 {
		t.Fatalf("reads did not get through: %v", got)
	}
}
