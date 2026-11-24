package egress

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// CA is a private certificate authority, created per runtime state directory. Only
// confined processes are told to trust it (SSL_CERT_FILE and friends); with it the proxy
// can see the method of each HTTPS request and refuse those that change something.
// Clients that pin their own CA (e.g. kubectl with a cluster CA) fail closed instead.
type CA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	PEM    []byte
	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func LoadOrCreateCA(dir string) (*CA, error) {
	certPath, keyPath := dir+"/egress-ca.pem", dir+"/egress-ca.key"
	if cb, err := os.ReadFile(certPath); err == nil {
		kb, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		cblk, _ := pem.Decode(cb)
		kblk, _ := pem.Decode(kb)
		if cblk == nil || kblk == nil {
			return nil, fmt.Errorf("corrupt egress CA in %s", dir)
		}
		cert, err := x509.ParseCertificate(cblk.Bytes)
		if err != nil {
			return nil, err
		}
		key, err := x509.ParseECPrivateKey(kblk.Bytes)
		if err != nil {
			return nil, err
		}
		return &CA{cert: cert, key: key, PEM: cb, leaves: map[string]*tls.Certificate{}}, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "undolayer egress CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	kder, _ := x509.MarshalECPrivateKey(key)
	cpem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, cpem, 0o644); err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, PEM: cpem, leaves: map[string]*tls.Certificate{}}, nil
}

func (ca *CA) leaf(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leaves[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
	ca.leaves[host] = c
	return c, nil
}

// Bundle writes the system roots plus the CA into one PEM file for confined processes.
func (ca *CA) Bundle(path string) error {
	var sys []byte
	for _, f := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"} {
		if b, err := os.ReadFile(f); err == nil {
			sys = b
			break
		}
	}
	return os.WriteFile(path, append(append(sys, '\n'), ca.PEM...), 0o644)
}

// CAEnv points common clients at the bundle.
func CAEnv(bundle string) []string {
	return []string{"SSL_CERT_FILE=" + bundle, "CURL_CA_BUNDLE=" + bundle, "REQUESTS_CA_BUNDLE=" + bundle,
		"NODE_EXTRA_CA_CERTS=" + bundle, "GIT_SSL_CAINFO=" + bundle, "AWS_CA_BUNDLE=" + bundle}
}

// inspectTLS terminates TLS for an allowed host, then forwards each request only if its
// method is safe.
func (p *Proxy) inspectTLS(c net.Conn, br *bufio.Reader, target string) {
	if p.CA == nil {
		p.record(Decision{Host: target, Allowed: false, Method: "CONNECT"})
		fmt.Fprintf(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Undolayer: no inspection CA\r\n\r\n")
		return
	}
	host, _, _ := net.SplitHostPort(target)
	cert, err := p.CA.leaf(host)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	tc := tls.Server(&bufConn{Conn: c, r: br}, &tls.Config{Certificates: []tls.Certificate{*cert}})
	defer tc.Close()
	upCfg := &tls.Config{ServerName: host}
	if p.UpstreamTLS != nil {
		upCfg = p.UpstreamTLS.Clone()
		upCfg.ServerName = host
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: upCfg,
		DialContext: func(_ context.Context, n, a string) (net.Conn, error) { return p.dial(a) }}
	tbr := bufio.NewReader(tc)
	for {
		req, err := http.ReadRequest(tbr)
		if err != nil {
			return
		}
		ok := safeMethods[req.Method]
		p.record(Decision{Host: target, Allowed: ok, Method: req.Method})
		if !ok {
			fmt.Fprintf(tc, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Undolayer: method %s refused (only reads leave this sandbox)\r\n\r\n", req.Method)
			return
		}
		req.URL.Scheme, req.URL.Host, req.RequestURI = "https", target, ""
		resp, err := tr.RoundTrip(req)
		if err != nil {
			fmt.Fprintf(tc, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		err = resp.Write(tc)
		resp.Body.Close()
		if err != nil {
			return
		}
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
