package tx

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"undolayer/internal/model"
)

// Query shapes each requester has used. A shape is learned only when a task that used it
// commits, so a query that was refused or rolled back (an injected one, say) is never
// learned as normal. Connectors report a statement's shape as the fact query_shape; the
// runtime adds shape_new (this requester never committed a query of this shape) for policy.

type shapeBook struct {
	mu    sync.Mutex
	path  string
	size  int64
	known map[string]bool
}

func (m *Manager) shapeBook() *shapeBook {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shapes == nil {
		m.shapes = &shapeBook{path: filepath.Join(m.StateDir, "shapes.jsonl"), size: -1, known: map[string]bool{}}
	}
	return m.shapes
}

type shapeLine struct {
	Requester string `json:"r"`
	Connector string `json:"c"`
	Shape     string `json:"s"`
}

func shapeKey(l shapeLine) string { return l.Requester + "\x00" + l.Connector + "\x00" + l.Shape }

// load rereads the file when another process has added to it.
func (b *shapeBook) load() {
	fi, err := os.Stat(b.path)
	if err != nil || fi.Size() == b.size {
		return
	}
	f, err := os.Open(b.path)
	if err != nil {
		return
	}
	defer f.Close()
	known := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var l shapeLine
		if json.Unmarshal(sc.Bytes(), &l) == nil && l.Shape != "" {
			known[shapeKey(l)] = true
		}
	}
	b.known, b.size = known, fi.Size()
}

func (b *shapeBook) Known(requester, connector, shape string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.load()
	return b.known[shapeKey(shapeLine{requester, connector, shape})]
}

func (b *shapeBook) Learn(ls []shapeLine) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.load()
	var buf []byte
	for _, l := range ls {
		if b.known[shapeKey(l)] {
			continue
		}
		b.known[shapeKey(l)] = true
		j, _ := json.Marshal(l)
		buf = append(buf, append(j, '\n')...)
	}
	if len(buf) == 0 {
		return nil
	}
	f, err := os.OpenFile(b.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck
	if _, err := f.Write(buf); err != nil {
		return err
	}
	return f.Sync()
}

// learnShapes records the shapes a committed task used.
func (t *Tx) learnShapes() {
	var ls []shapeLine
	for _, a := range t.Actions {
		s, _ := a.Facts["query_shape"].(string)
		if s == "" || a.Decision == model.Deny || a.Error != "" || t.cancelled(a.ID) {
			continue
		}
		ls = append(ls, shapeLine{t.Requester, a.Connector, s})
	}
	if len(ls) > 0 {
		_ = t.Mgr.shapeBook().Learn(ls)
	}
}
