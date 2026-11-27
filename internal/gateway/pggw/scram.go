package pggw

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// SCRAM-SHA-256 (RFC 5802, RFC 7677), the server side, as PostgreSQL does it: clients log
// in to the gateway with their own password; the gateway reaches the database with its own
// credentials, which clients never hold.

type scramVerifier struct {
	salt      []byte
	iter      int
	storedKey []byte
	serverKey []byte
}

func hmacSHA(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func newVerifier(password string) (*scramVerifier, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	const iter = 4096
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return nil, err
	}
	ck := hmacSHA(salted, []byte("Client Key"))
	sk := sha256.Sum256(ck)
	return &scramVerifier{salt: salt, iter: iter, storedKey: sk[:], serverKey: hmacSHA(salted, []byte("Server Key"))}, nil
}

type scramServer struct {
	v               *scramVerifier
	clientFirstBare string
	serverFirst     string
	nonce           string
}

// first takes the client-first-message and returns the server-first-message.
func (s *scramServer) first(msg string) (string, error) {
	// gs2 header: "n,," (no channel binding) or "y,,"
	parts := strings.SplitN(msg, ",", 3)
	if len(parts) != 3 || (parts[0] != "n" && parts[0] != "y") {
		return "", errors.New("SCRAM: channel binding is not supported")
	}
	s.clientFirstBare = parts[2]
	var cnonce string
	for _, a := range strings.Split(s.clientFirstBare, ",") {
		if strings.HasPrefix(a, "r=") {
			cnonce = a[2:]
		}
	}
	if cnonce == "" {
		return "", errors.New("SCRAM: no client nonce")
	}
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s.nonce = cnonce + base64.RawStdEncoding.EncodeToString(b)
	s.serverFirst = fmt.Sprintf("r=%s,s=%s,i=%d", s.nonce, base64.StdEncoding.EncodeToString(s.v.salt), s.v.iter)
	return s.serverFirst, nil
}

// final checks the client-final-message and returns the server-final-message.
func (s *scramServer) final(msg string) (string, error) {
	i := strings.LastIndex(msg, ",p=")
	if i < 0 {
		return "", errors.New("SCRAM: no proof")
	}
	withoutProof, proofB64 := msg[:i], msg[i+3:]
	var nonce string
	for _, a := range strings.Split(withoutProof, ",") {
		if strings.HasPrefix(a, "r=") {
			nonce = a[2:]
		}
	}
	if nonce != s.nonce {
		return "", errors.New("SCRAM: nonce mismatch")
	}
	proof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil || len(proof) != 32 {
		return "", errors.New("SCRAM: bad proof")
	}
	authMsg := s.clientFirstBare + "," + s.serverFirst + "," + withoutProof
	sig := hmacSHA(s.v.storedKey, []byte(authMsg))
	ck := make([]byte, 32)
	for k := range ck {
		ck[k] = proof[k] ^ sig[k]
	}
	got := sha256.Sum256(ck)
	if !hmac.Equal(got[:], s.v.storedKey) {
		return "", errors.New("password authentication failed")
	}
	return "v=" + base64.StdEncoding.EncodeToString(hmacSHA(s.v.serverKey, []byte(authMsg))), nil
}
