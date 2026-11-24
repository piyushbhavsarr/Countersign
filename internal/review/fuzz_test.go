package review

import (
	"strings"
	"testing"
)

// No input may crash the parser, and nothing but a real signature by the reviewer's key verifies.
func FuzzSignatureParsing(f *testing.F) {
	f.Add("-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ==\n-----END SSH SIGNATURE-----")
	f.Add("")
	f.Add("-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----")
	cfg := &Config{Reviewers: map[string]*Reviewer{"alice": {Name: "alice"}}}
	f.Fuzz(func(t *testing.T, armored string) {
		_, _, _, _, _ = parseSSHSIG(armored)
		if cfg.Verify(Statement{V: 1, Tx: "t", Subject: "s", Decision: "approve", Reviewer: "alice"}, armored) == nil {
			t.Fatalf("a signature verified for a reviewer with no keys: %q", armored)
		}
	})
}

func FuzzSignatureBlob(f *testing.F) {
	f.Add([]byte("SSHSIG\x00\x00\x00\x01"))
	f.Fuzz(func(t *testing.T, blob []byte) {
		armored := "-----BEGIN SSH SIGNATURE-----\n" + b64(blob) + "\n-----END SSH SIGNATURE-----"
		_, _, _, _, _ = parseSSHSIG(armored) // must not panic on any bytes
	})
}

func b64(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var s strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		k := 0
		for j := 0; j < 3; j++ {
			n <<= 8
			if i+j < len(b) {
				n |= uint32(b[i+j])
				k++
			}
		}
		for j := 0; j < 4; j++ {
			if j <= k {
				s.WriteByte(enc[(n>>(18-6*j))&63])
			} else {
				s.WriteByte('=')
			}
		}
	}
	return s.String()
}
