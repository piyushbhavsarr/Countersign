// Package netguard says what kind of network a destination is on, and refuses connections
// an agent must not make: to cloud metadata services (where instance credentials live), and
// to loopback, private and link-local addresses unless the operator allowed that host.
//
// It is checked twice: when a request is classified (as facts for policy), and again when
// the connection is made, on the address actually dialled, so a name that resolves to a
// public address when checked and to 169.254.169.254 when connecting (DNS rebinding) is
// still refused, and so is a redirect to one.
package netguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Kinds of network, most dangerous first.
const (
	Metadata    = "metadata"   // a cloud instance metadata service
	Loopback    = "loopback"   // this machine
	LinkLocal   = "link_local" // the local link (169.254/16, fe80::/10)
	Private     = "private"    // RFC 1918, unique local, carrier-grade NAT, unspecified
	Public      = "public"     // anything else
	Unresolved  = "unresolved" // the name did not resolve (the request will fail)
	rankUnknown = 99
)

var rank = map[string]int{Metadata: 0, Loopback: 1, LinkLocal: 2, Private: 3, Public: 4, Unresolved: 5}

// metadata endpoints of AWS (IMDS, ECS task metadata), Azure IMDS, GCP, Alibaba, Oracle
var metadataAddrs = map[netip.Addr]bool{
	netip.MustParseAddr("169.254.169.254"): true,
	netip.MustParseAddr("169.254.170.2"):   true,
	netip.MustParseAddr("fd00:ec2::254"):   true,
	netip.MustParseAddr("100.100.100.200"): true,
	netip.MustParseAddr("192.0.0.192"):     true,
}

var metadataNames = map[string]bool{"metadata.google.internal": true, "metadata.goog": true, "metadata": true,
	"instance-data": true, "instance-data.ec2.internal": true}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// KindOf classifies one address.
func KindOf(a netip.Addr) string {
	a = a.Unmap()
	switch {
	case metadataAddrs[a]:
		return Metadata
	case a.IsLoopback():
		return Loopback
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
		return LinkLocal
	case a.IsPrivate() || a.IsUnspecified() || cgnat.Contains(a) || a.IsMulticast() || a.IsInterfaceLocalMulticast():
		return Private
	}
	return Public
}

// Worst returns the more dangerous of two kinds.
func Worst(a, b string) string {
	ra, ok := rank[a]
	if !ok {
		ra = rankUnknown
	}
	rb, ok := rank[b]
	if !ok {
		rb = rankUnknown
	}
	if rb < ra {
		return b
	}
	return a
}

// Resolver looks names up (swappable in tests).
var Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// HostKind classifies a host name or address: the most dangerous of what it resolves to.
func HostKind(host string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if metadataNames[h] {
		return Metadata
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return KindOf(a)
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return Loopback
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := Resolver(ctx, h)
	if err != nil || len(addrs) == 0 {
		return Unresolved
	}
	k := Public
	for _, a := range addrs {
		k = Worst(k, KindOf(a))
	}
	return k
}

// Allowed reports whether host matches one of the operator's glob patterns.
func Allowed(host string, patterns []string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	for _, p := range patterns {
		if ok, _ := path.Match(strings.ToLower(p), h); ok {
			return true
		}
	}
	return false
}

// Facts about a URL an agent asked for.
type URLFacts struct {
	Scheme          string
	Host            string
	Network         string
	PrivateAllowed  bool
	UserInfo        bool // credentials written into the URL
	HeaderInjection bool // CR or LF in the URL or a header value: request smuggling
	Shape           string
}

var idSeg = regexp.MustCompile(`^([0-9]+|[0-9a-fA-F-]{16,}|[A-Za-z0-9_-]{24,})$`)

// Inspect reads a request's URL and headers.
func Inspect(method, rawURL string, headers map[string]string, allowPrivate []string) URLFacts {
	f := URLFacts{}
	if strings.ContainsAny(rawURL, "\r\n") {
		f.HeaderInjection = true
	}
	for k, v := range headers {
		if strings.ContainsAny(k+v, "\r\n") {
			f.HeaderInjection = true
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		f.Scheme, f.Network = "invalid", Unresolved
		return f
	}
	f.Scheme, f.Host, f.UserInfo = strings.ToLower(u.Scheme), u.Hostname(), u.User != nil
	f.Network = HostKind(f.Host)
	f.PrivateAllowed = Allowed(f.Host, allowPrivate)
	// shape: method, host and path with identifiers taken out; query parameter names only
	segs := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	for i, s := range segs {
		if idSeg.MatchString(s) {
			segs[i] = "{id}"
		}
	}
	var qk []string
	for k := range u.Query() {
		qk = append(qk, k)
	}
	sortStrings(qk)
	shape := strings.ToUpper(method) + " " + f.Scheme + "://" + strings.ToLower(f.Host) + "/" + strings.Join(segs, "/") + "?" + strings.Join(qk, "&")
	h := sha256.Sum256([]byte(shape))
	f.Shape = hex.EncodeToString(h[:8])
	return f
}

func sortStrings(l []string) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && l[j] < l[j-1]; j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

// ErrRefused: the connection was refused by the guard.
var ErrRefused = errors.New("netguard: refused")

// Client is an HTTP client whose connections are checked on the address actually dialled.
// allowPrivate lists hosts (globs) that may be on loopback, private or link-local networks;
// metadata services are never allowed. Redirects are followed only to http(s) and are
// checked the same way.
func Client(timeout time.Duration, allowPrivate []string) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // a proxy would dial for us, out of the guard's sight
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		h := strings.ToLower(host)
		if metadataNames[strings.TrimSuffix(h, ".")] {
			return nil, fmt.Errorf("%w: %s is a cloud metadata service", ErrRefused, host)
		}
		var addrs []netip.Addr
		if a, err := netip.ParseAddr(h); err == nil {
			addrs = []netip.Addr{a}
		} else if addrs, err = Resolver(ctx, h); err != nil {
			return nil, err
		}
		var last error
		for _, a := range addrs {
			switch k := KindOf(a); {
			case k == Metadata:
				last = fmt.Errorf("%w: %s (%s) is a cloud metadata service", ErrRefused, host, a)
				continue
			case k != Public && !Allowed(host, allowPrivate):
				last = fmt.Errorf("%w: %s resolves to %s (%s); allow it in [http] allow_private_hosts", ErrRefused, host, a, k)
				continue
			}
			c, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if err == nil {
				return c, nil
			}
			last = err
		}
		if last == nil {
			last = fmt.Errorf("%s: no address", host)
		}
		return nil, last
	}
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if s := req.URL.Scheme; s != "http" && s != "https" {
			return fmt.Errorf("%w: redirect to %s", ErrRefused, req.URL.Scheme)
		}
		return nil
	}}
}
