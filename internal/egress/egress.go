// Package egress is the only way out of the agent's sandbox besides the gateway.
//
// The agent runs in an OS sandbox whose network is cut except for (a) the gateway's
// Unix socket and (b) this proxy. The proxy forwards CONNECT tunnels and plain HTTP
// requests only to allow-listed hosts (typically the model API) and refuses everything
// else, recording each decision. On Linux the agent's network namespace has no route at
// all, so a bridge inside it listens on loopback and forwards to the proxy's Unix socket.
package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

type Decision struct {
	Host    string
	Allowed bool
	Method  string
}

type Proxy struct {
	Allow      []string // host globs, e.g. "api.anthropic.com", "*.anthropic.com"
	OnDecision func(Decision)
	// SafeOnly: only methods HTTP defines as safe (GET, HEAD, OPTIONS; RFC 9110 9.2.1) may
	// pass. HTTPS is opened with CA (which only the sandbox trusts) so methods are visible.
	SafeOnly bool
	CA       *CA
	// Resolve, if set, maps a requested host:port to the address actually dialled (tests).
	Resolve func(hostport string) string
	// UpstreamTLS is used to verify upstream servers when terminating TLS (nil = system roots).
	UpstreamTLS *tls.Config

	mu  sync.Mutex
	lns []net.Listener
}

func (p *Proxy) allowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, g := range p.Allow {
		if ok, _ := path.Match(strings.ToLower(g), host); ok {
			return true
		}
	}
	return false
}

var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

func (p *Proxy) dial(hostport string) (net.Conn, error) {
	addr := hostport
	if p.Resolve != nil {
		addr = p.Resolve(hostport)
	}
	return net.DialTimeout("tcp", addr, 10*time.Second)
}

func (p *Proxy) record(d Decision) {
	if p.OnDecision != nil {
		p.OnDecision(d)
	}
}

// Serve accepts proxy connections on l until it is closed.
func (p *Proxy) Serve(l net.Listener) {
	p.mu.Lock()
	p.lns = append(p.lns, l)
	p.mu.Unlock()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, l := range p.lns {
		_ = l.Close()
	}
}

func (p *Proxy) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		target := req.Host
		ok := p.allowed(target)
		if !ok {
			p.record(Decision{Host: target, Allowed: false, Method: "CONNECT"})
			fmt.Fprintf(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Undolayer: egress denied\r\n\r\n")
			return
		}
		if p.SafeOnly {
			p.inspectTLS(c, br, target)
			return
		}
		p.record(Decision{Host: target, Allowed: true, Method: "CONNECT"})
		up, err := p.dial(target)
		if err != nil {
			fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		defer up.Close()
		_ = c.SetDeadline(time.Time{})
		fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		pipe(c, br, up)
		return
	}
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	ok := req.URL.IsAbs() && p.allowed(host) && (!p.SafeOnly || safeMethods[req.Method])
	p.record(Decision{Host: host, Allowed: ok, Method: req.Method})
	if !ok {
		fmt.Fprintf(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Undolayer: egress denied\r\n\r\n")
		return
	}
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return p.dial(a) }}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	_ = resp.Write(c)
}

func pipe(a net.Conn, ar io.Reader, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, ar); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
}

// Bridge listens on a loopback TCP address and forwards each connection to a Unix socket.
func Bridge(listenAddr, unixPath string) (net.Listener, error) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				u, err := net.Dial("unix", unixPath)
				if err != nil {
					return
				}
				defer u.Close()
				pipe(c, c, u)
			}()
		}
	}()
	return l, nil
}

// ListenUnix creates a Unix-socket listener (removing a stale socket file).
func ListenUnix(p string) (net.Listener, error) {
	_ = os.Remove(p)
	l, err := net.Listen("unix", p)
	if err == nil {
		_ = os.Chmod(p, 0o600)
	}
	return l, err
}
