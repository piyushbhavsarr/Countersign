package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// S3 is a minimal client for S3-compatible object storage (AWS S3, MinIO, R2, GCS's S3
// interface): signed with AWS Signature Version 4, path-style addressing, no SDK.
type S3 struct {
	Endpoint  string // https://s3.eu-west-1.amazonaws.com, http://127.0.0.1:9000, ...
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	http      *http.Client
}

func (c *S3) client() *http.Client {
	if c.http == nil {
		c.http = &http.Client{Timeout: 5 * time.Minute}
	}
	return c.http
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// uriEncode encodes as SigV4 requires (RFC 3986 unreserved characters kept).
func uriEncode(s string, slash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.' || ch == '~' || (ch == '/' && !slash) {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

// do sends a signed request for key (empty for the bucket itself).
func (c *S3) do(method, key string, query url.Values, body []byte, headers map[string]string) (int, http.Header, []byte, error) {
	u, err := url.Parse(strings.TrimSuffix(c.Endpoint, "/"))
	if err != nil {
		return 0, nil, nil, err
	}
	path := "/" + c.Bucket
	if key != "" {
		path += "/" + key
	}
	canonURI := uriEncode(path, false)
	var qk []string
	for k := range query {
		qk = append(qk, k)
	}
	sort.Strings(qk)
	var qs []string
	for _, k := range qk {
		for _, v := range query[k] {
			qs = append(qs, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	canonQuery := strings.Join(qs, "&")
	now := time.Now().UTC()
	amzDate, day := now.Format("20060102T150405Z"), now.Format("20060102")
	payload := sha256hex(body)
	h := map[string]string{"host": u.Host, "x-amz-date": amzDate, "x-amz-content-sha256": payload}
	for k, v := range headers {
		h[strings.ToLower(k)] = v
	}
	var hk []string
	for k := range h {
		hk = append(hk, k)
	}
	sort.Strings(hk)
	var ch strings.Builder
	for _, k := range hk {
		ch.WriteString(k + ":" + strings.TrimSpace(h[k]) + "\n")
	}
	signed := strings.Join(hk, ";")
	creq := strings.Join([]string{method, canonURI, canonQuery, ch.String(), signed, payload}, "\n")
	scope := day + "/" + c.Region + "/s3/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256hex([]byte(creq))
	k := hmacSHA([]byte("AWS4"+c.SecretKey), []byte(day))
	k = hmacSHA(k, []byte(c.Region))
	k = hmacSHA(k, []byte("s3"))
	k = hmacSHA(k, []byte("aws4_request"))
	sig := hex.EncodeToString(hmacSHA(k, []byte(sts)))
	full := u.Scheme + "://" + u.Host + canonURI
	if canonQuery != "" {
		full += "?" + canonQuery
	}
	req, err := http.NewRequest(method, full, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for _, k := range hk {
		if k != "host" {
			req.Header.Set(k, h[k])
		}
	}
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKey, scope, signed, sig))
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<30))
	return resp.StatusCode, resp.Header, rb, err
}

func hmacSHA(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func s3err(what string, code int, body []byte) error {
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	_ = xml.Unmarshal(body, &e)
	if e.Code != "" {
		return fmt.Errorf("%s: HTTP %d %s: %s", what, code, e.Code, e.Message)
	}
	return fmt.Errorf("%s: HTTP %d", what, code)
}

// Put stores an object. With lockUntil it is written under Object Lock in compliance mode:
// nobody, the account's root included, can delete or overwrite that version before then.
func (c *S3) Put(key string, body []byte, lockUntil time.Time) error {
	sum := sha256.Sum256(body)
	m := md5.Sum(body)
	h := map[string]string{"content-type": "application/octet-stream",
		"x-amz-checksum-sha256": base64.StdEncoding.EncodeToString(sum[:]), // the store checks what it received
		"content-md5":           base64.StdEncoding.EncodeToString(m[:])}
	if !lockUntil.IsZero() {
		h["x-amz-object-lock-mode"] = "COMPLIANCE"
		h["x-amz-object-lock-retain-until-date"] = lockUntil.UTC().Format(time.RFC3339)
	}
	code, _, rb, err := c.do("PUT", key, nil, body, h)
	if err != nil {
		return err
	}
	if code != 200 {
		return s3err("put "+key, code, rb)
	}
	return nil
}

// Get reads an object.
func (c *S3) Get(key string) ([]byte, error) {
	code, _, rb, err := c.do("GET", key, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, s3err("get "+key, code, rb)
	}
	return rb, nil
}

// Head reports an object's headers, or nil if it does not exist.
func (c *S3) Head(key string) (http.Header, error) {
	code, h, rb, err := c.do("HEAD", key, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	switch code {
	case 200:
		return h, nil
	case 404:
		return nil, nil
	}
	return nil, s3err("head "+key, code, rb)
}

// List returns the keys under prefix, in order.
func (c *S3) List(prefix string) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		code, _, rb, err := c.do("GET", "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		if code != 200 {
			return nil, s3err("list", code, rb)
		}
		var r struct {
			Contents []struct {
				Key string `xml:"Key"`
			} `xml:"Contents"`
			IsTruncated bool   `xml:"IsTruncated"`
			Next        string `xml:"NextContinuationToken"`
		}
		if err := xml.Unmarshal(rb, &r); err != nil {
			return nil, err
		}
		for _, o := range r.Contents {
			keys = append(keys, o.Key)
		}
		if !r.IsTruncated || r.Next == "" {
			break
		}
		token = r.Next
	}
	sort.Strings(keys)
	return keys, nil
}

// CreateBucket makes the bucket with Object Lock enabled (it can only be enabled at creation).
func (c *S3) CreateBucket() error {
	h := map[string]string{"x-amz-bucket-object-lock-enabled": "true"}
	var body []byte
	if c.Region != "" && c.Region != "us-east-1" {
		body = []byte(`<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>` +
			c.Region + `</LocationConstraint></CreateBucketConfiguration>`)
	}
	code, _, rb, err := c.do("PUT", "", nil, body, h)
	if err != nil {
		return err
	}
	if code != 200 && !bytes.Contains(rb, []byte("BucketAlreadyOwnedByYou")) {
		return s3err("create bucket", code, rb)
	}
	return nil
}
