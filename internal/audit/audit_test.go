package audit

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"undolayer/internal/store"
)

func count(t *testing.T, s *store.Files) int {
	n := 0
	_ = s.AuditLines(func([]byte) error { n++; return nil })
	return n
}

// Many goroutines and two processes' logs at once: one chain, every event in it.
func TestGroupCommitKeepsOneChain(t *testing.T) {
	s, err := store.OpenFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	a, b := New(s, key, ""), New(s, key, "") // two processes on one store
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			l := a
			if g%2 == 1 {
				l = b
			}
			for i := 0; i < 50; i++ {
				if i%3 == 0 {
					l.Note("read", map[string]any{"g": g, "i": i})
				} else if err := l.Record("write", map[string]any{"g": g, "i": i}); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s); n != 16*50 {
		t.Fatalf("%d events, want %d", n, 16*50)
	}
	if ok, why := a.Verify(); !ok {
		t.Fatal(why)
	}
}

// A noted event is durable once any later event is recorded.
func TestANoteIsDurableBeforeTheNextRecord(t *testing.T) {
	s, _ := store.OpenFiles(t.TempDir())
	l := New(s, bytes.Repeat([]byte{1}, 32), "")
	for i := 0; i < 20; i++ {
		l.Note("read", map[string]any{"i": i})
	}
	if err := l.Record("commit", nil); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s); n != 21 {
		t.Fatalf("%d events", n)
	}
	var last []byte
	_ = s.AuditLines(func(b []byte) error { last = append([]byte{}, b...); return nil })
	if !bytes.Contains(last, []byte(`"event":"commit"`)) {
		t.Fatalf("order: %s", last)
	}
	if ok, why := l.Verify(); !ok {
		t.Fatal(why)
	}
	_ = fmt.Sprint
}
