// Package audit is a tamper-evident log: JSON lines, each carrying the SHA-256 of the
// previous line and an HMAC over its own canonical bytes. Several processes (agent
// session, human CLI, worker) append to one chain under an exclusive file lock, each
// linking to the record actually last on disk.
package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"undolayer/internal/model"
)

const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Backend stores the chain's lines; AppendAudit must serialise appenders.
type Backend interface {
	AppendAudit(next func(prev []byte) ([]byte, error)) error
	AuditLines(fn func(line []byte) error) error
}

type Log struct {
	Path string // the file, when the backend is a directory (for tools and tests)
	b    Backend
	key  []byte
	mu   sync.Mutex
}

func New(b Backend, key []byte, path string) *Log { return &Log{b: b, key: key, Path: path} }

func canonical(v map[string]any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // map keys are sorted by encoding/json
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func hashOf(line []byte) string {
	if len(bytes.TrimSpace(line)) == 0 {
		return Genesis
	}
	h := sha256.Sum256(line)
	return hex.EncodeToString(h[:])
}

// Record appends one event, linked to the record actually last in the chain.
func (l *Log) Record(event string, data map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.AppendAudit(func(prev []byte) ([]byte, error) {
		body := map[string]any{"ts": model.Now(), "event": event, "prev": hashOf(prev)}
		for k, v := range data {
			body[k] = v
		}
		mac := hmac.New(sha256.New, l.key)
		mac.Write(canonical(body))
		body["mac"] = hex.EncodeToString(mac.Sum(nil))
		return canonical(body), nil
	})
}

// Verify checks the whole chain.
func (l *Log) Verify() (bool, string) {
	prev := Genesis
	n := 0
	bad := ""
	err := l.b.AuditLines(func(raw []byte) error {
		n++
		var rec map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&rec); err != nil {
			bad = fmt.Sprintf("line %d: not JSON", n)
			return errStop
		}
		if rec["prev"] != prev {
			bad = fmt.Sprintf("line %d: chain broken (record removed or reordered)", n)
			return errStop
		}
		got, _ := rec["mac"].(string)
		delete(rec, "mac")
		mac := hmac.New(sha256.New, l.key)
		mac.Write(canonical(rec))
		if !hmac.Equal([]byte(got), []byte(hex.EncodeToString(mac.Sum(nil)))) {
			bad = fmt.Sprintf("line %d: MAC mismatch (record edited)", n)
			return errStop
		}
		prev = hashOf(raw)
		return nil
	})
	if bad != "" {
		return false, bad
	}
	if err != nil {
		return false, err.Error()
	}
	if n == 0 {
		return true, "empty log"
	}
	return true, "ok"
}

var errStop = errors.New("stop")
