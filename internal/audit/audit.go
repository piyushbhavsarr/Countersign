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

// Backend stores the chain's lines. AppendAudit must serialise appenders (across
// processes too) and make the lines it is given durable together.
type Backend interface {
	AppendAudit(next func(prev []byte) ([][]byte, error)) error
	AuditLines(fn func(line []byte) error) error
}

// Log is written by group commit: events recorded at the same time, from any goroutine,
// are linked into the chain in the order they arrived and made durable with one write and
// one sync. Record returns once its event is durable. Note returns at once: its event goes
// into the next batch (which starts as soon as the current one is on disk), so it can be
// lost only if the process dies in those milliseconds; it is used for reads, which change
// nothing. Every durable event also makes every event noted before it durable.
type Log struct {
	Path string // the file, when the backend is a directory (for tools and tests)
	b    Backend
	key  []byte

	mu      sync.Mutex
	pending []*entry
	writing bool
	idle    *sync.Cond
}

type entry struct {
	event string
	data  map[string]any
	ts    float64
	done  chan error // nil for noted events
}

func New(b Backend, key []byte, path string) *Log {
	l := &Log{b: b, key: key, Path: path}
	l.idle = sync.NewCond(&l.mu)
	return l
}

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

// Record appends one event and returns once it is durable.
func (l *Log) Record(event string, data map[string]any) error {
	e := &entry{event: event, data: data, ts: model.Now(), done: make(chan error, 1)}
	l.enqueue(e)
	return <-e.done
}

// Note appends one event without waiting for it to be durable (see Log).
func (l *Log) Note(event string, data map[string]any) {
	l.enqueue(&entry{event: event, data: data, ts: model.Now()})
}

// Flush returns once every event recorded or noted so far is durable.
func (l *Log) Flush() error {
	return l.Record("", nil)
}

func (l *Log) enqueue(e *entry) {
	l.mu.Lock()
	l.pending = append(l.pending, e)
	if l.writing {
		l.mu.Unlock()
		return
	}
	l.writing = true
	l.mu.Unlock()
	go l.writer()
}

// writer drains the queue a batch at a time until it is empty.
func (l *Log) writer() {
	for {
		l.mu.Lock()
		batch := l.pending
		l.pending = nil
		if len(batch) == 0 {
			l.writing = false
			l.idle.Broadcast()
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
		err := l.b.AppendAudit(func(prev []byte) ([][]byte, error) {
			var lines [][]byte
			for _, e := range batch {
				if e.event == "" { // a flush marker
					continue
				}
				body := map[string]any{"ts": e.ts, "event": e.event, "prev": hashOf(prev)}
				for k, v := range e.data {
					body[k] = v
				}
				mac := hmac.New(sha256.New, l.key)
				mac.Write(canonical(body))
				body["mac"] = hex.EncodeToString(mac.Sum(nil))
				line := canonical(body)
				lines = append(lines, line)
				prev = line
			}
			return lines, nil
		})
		for _, e := range batch {
			if e.done != nil {
				e.done <- err
			}
		}
	}
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
