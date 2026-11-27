package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Every backend must pass the same tests. Two instances opened on the same place stand in
// for two gateway nodes. PostgreSQL runs when UNDOLAYER_TEST_STATE_PG is a server DSN
// (a fresh database is created per test).

type opener func(t *testing.T) (a, b Store)

func backends(t *testing.T) map[string]opener {
	out := map[string]opener{
		"files": func(t *testing.T) (Store, Store) {
			dir := t.TempDir()
			a, err := OpenFiles(dir)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := OpenFiles(dir)
			return a, b
		},
	}
	if dsn := os.Getenv("UNDOLAYER_TEST_STATE_PG"); dsn != "" {
		out["postgres"] = func(t *testing.T) (Store, Store) {
			db := freshDB(t, dsn)
			a, err := OpenPostgres(db)
			if err != nil {
				t.Fatal(err)
			}
			b, err := OpenPostgres(db)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { a.Close(); b.Close() })
			return a, b
		}
	}
	return out
}

func freshDB(t *testing.T, dsn string) string {
	c, cancel := ctx()
	defer cancel()
	conn, err := pgx.Connect(c, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(c)
	name := fmt.Sprintf("ul_store_%d", time.Now().UnixNano())
	if _, err := conn.Exec(c, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgx.ParseConfig(dsn)
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s", cfg.User, cfg.Password, cfg.Host, cfg.Port, name)
}

func each(t *testing.T, fn func(t *testing.T, a, b Store)) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			a, b := open(t)
			fn(t, a, b)
		})
	}
}

func TestJournalsAreSharedBetweenNodes(t *testing.T) {
	each(t, func(t *testing.T, a, b Store) {
		if _, err := a.LoadTx("tx_x"); err != ErrNotFound {
			t.Fatalf("missing transaction: %v", err)
		}
		if err := a.SaveTx("tx_1", []byte(`{"id":"tx_1","created":1}`)); err != nil {
			t.Fatal(err)
		}
		_ = a.SaveTx("tx_1", []byte(`{"id":"tx_1","created":1,"state":"committed"}`))
		_ = a.SaveTx("tx_2", []byte(`{"id":"tx_2","created":2}`))
		got, err := b.LoadTx("tx_1")
		if err != nil || !bytes.Contains(got, []byte("committed")) {
			t.Fatalf("the other node does not see the latest journal: %s %v", got, err)
		}
		if l, _ := b.ListTx(); len(l) != 2 {
			t.Fatalf("list: %d", len(l))
		}
	})
}

func TestOwnershipIsExclusiveAndFreedWhenTheOwnerDies(t *testing.T) {
	each(t, func(t *testing.T, a, b Store) {
		la, ok := a.TryLock("tx_1")
		if !ok {
			t.Fatal("could not take a free lock")
		}
		if _, ok := b.TryLock("tx_1"); ok {
			t.Fatal("two nodes owned one transaction")
		}
		if _, ok := b.TryLock("tx_2"); !ok {
			t.Fatal("an unrelated lock was blocked")
		}
		la.Release()
		lb, ok := b.TryLock("tx_1")
		if !ok {
			t.Fatal("a released lock could not be taken")
		}
		lb.Release()

		// the owner dies: its connection (or file descriptor) goes away
		if _, ok := a.TryLock("tx_3"); !ok {
			t.Fatal("lock")
		}
		if p, isPG := a.(*Postgres); isPG {
			p.Close()
		} else {
			// a dead process's flocks are released by the kernel; model it by releasing
			// every lock this instance holds by closing its descriptors
			t.Skip("file locks are per process; process death is covered by the e2e zombie test")
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if l, ok := b.TryLock("tx_3"); ok {
				l.Release()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("a dead owner's lock was never released")
	})
}

func TestApprovalsKeysAndSharedDocs(t *testing.T) {
	each(t, func(t *testing.T, a, b Store) {
		_ = a.AppendApproval("tx_1", []byte(`{"n":1}`))
		_ = b.AppendApproval("tx_1", []byte(`{"n":2}`))
		_ = a.AppendApproval("tx_2", []byte(`{"n":9}`))
		got, _ := a.Approvals("tx_1")
		if len(got) != 2 || string(got[0]) != `{"n": 1}` && string(got[0]) != `{"n":1}` {
			t.Fatalf("approvals: %q", got)
		}
		ka, _ := a.Key("audit.key")
		kb, _ := b.Key("audit.key")
		if len(ka) != 32 || !bytes.Equal(ka, kb) {
			t.Fatal("nodes disagree on a key")
		}
		if v, _ := b.Get("doc"); v != nil {
			t.Fatal("absent document returned")
		}
		_ = a.Put("doc", []byte("v1"))
		_ = a.Put("doc", []byte("v2"))
		if v, _ := b.Get("doc"); string(v) != "v2" {
			t.Fatalf("shared doc: %q", v)
		}
	})
}

func TestTheAuditChainStaysLinkedUnderConcurrentAppends(t *testing.T) {
	each(t, func(t *testing.T, a, b Store) {
		var wg sync.WaitGroup
		for i, s := range []Store{a, b} {
			wg.Add(1)
			go func(i int, s Store) {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					err := s.AppendAudit(func(prev []byte) ([][]byte, error) {
						return [][]byte{[]byte(fmt.Sprintf(`{"node":%d,"n":%d,"prev":"%s"}`, i, j, hash(prev)))}, nil
					})
					if err != nil {
						t.Error(err)
						return
					}
				}
			}(i, s)
		}
		wg.Wait()
		prev, n := []byte(nil), 0
		err := a.AuditLines(func(line []byte) error {
			n++
			want := fmt.Sprintf(`"prev":"%s"`, hash(prev))
			if !bytes.Contains(line, []byte(want)) {
				return fmt.Errorf("line %d does not link to the one before it", n)
			}
			prev = append([]byte(nil), line...)
			return nil
		})
		if err != nil || n != 200 {
			t.Fatalf("chain: %v (%d lines)", err, n)
		}
	})
}

func hash(b []byte) string {
	if b == nil {
		return "genesis"
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}
