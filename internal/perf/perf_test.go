// Package perf measures what Countersign adds to each request on the hot path.
package perf

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"undolayer/internal/connectors/sqlite"
	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

func setup(b *testing.B, withVault bool) (*tx.Manager, string) {
	d := b.TempDir()
	db := filepath.Join(d, "app.db")
	c, _ := sql.Open("sqlite3", db)
	_, _ = c.Exec(`CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, plan TEXT);
		WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 10000)
		INSERT INTO users(email, plan) SELECT 'u'||i||'@ex.com', 'free' FROM n;`)
	c.Close()
	m, err := tx.NewManager(filepath.Join(d, "state"), policy.Default())
	if err != nil {
		b.Fatal(err)
	}
	m.Register(sqlite.New(db))
	if withVault {
		k, _ := vault.OpenKeyring(filepath.Join(d, "keys"))
		v, _ := vault.Open(vault.Options{Replicas: []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")},
			LockPath: filepath.Join(d, "l"), Keys: k})
		m.Vault = v
	}
	return m, db
}

func BenchmarkPolicyEvaluate(b *testing.B) {
	p := policy.Default()
	a := &model.Action{Connector: "sql", Operation: "query", Effect: model.Read,
		Facts: model.Facts{"is_write": false, "tables_written": []string{}, "sql_injection_signals": []string{}}}
	for i := 0; i < b.N; i++ {
		p.Evaluate(a)
	}
}

func BenchmarkReadInATask(b *testing.B) {
	m, _ := setup(b, true)
	x := m.Begin("reads")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := x.Call("sql", "query", map[string]any{"sql": "SELECT email FROM users WHERE id = ?", "params": []any{i%10000 + 1}}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteTaskCommit(b *testing.B) {
	m, _ := setup(b, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := m.Begin("one update")
		if _, err := x.Call("sql", "execute", map[string]any{"sql": fmt.Sprintf("UPDATE users SET plan = 'pro%d' WHERE id = %d", i, i%10000+1)}); err != nil {
			b.Fatal(err)
		}
		if _, err := x.Commit(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVaultAppend(b *testing.B) {
	d := b.TempDir()
	v, _ := vault.Open(vault.Options{Replicas: []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")}, LockPath: filepath.Join(d, "l")})
	e := vault.Entry{Tx: "t", Connector: "sql", Phase: "intent", Rows: []vault.Row{{Table: "users", Op: "update", Key: map[string]any{"id": 1}}}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Append(e); err != nil {
			b.Fatal(err)
		}
	}
}

// Many tasks at once, as many agents or requests would run them.
func BenchmarkWriteTaskCommitParallel(b *testing.B) {
	m, _ := setup(b, true)
	var n int64
	var mu sync.Mutex
	b.SetParallelism(8)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			n++
			i := n
			mu.Unlock()
			x := m.Begin("one update")
			if _, err := x.Call("sql", "execute", map[string]any{"sql": fmt.Sprintf("UPDATE users SET plan = 'p%d' WHERE id = %d", i, i%10000+1)}); err != nil {
				b.Error(err)
				return
			}
			if _, err := x.Commit(); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkVaultAppendParallel(b *testing.B) {
	d := b.TempDir()
	v, _ := vault.Open(vault.Options{Replicas: []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")}, LockPath: filepath.Join(d, "l")})
	e := vault.Entry{Tx: "t", Connector: "sql", Phase: "intent", Rows: []vault.Row{{Table: "users", Op: "update", Key: map[string]any{"id": 1}}}}
	b.SetParallelism(16)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := v.Append(e); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func setupT(t *testing.T) (*tx.Manager, string) {
	b := &testing.B{}
	_ = b
	d := t.TempDir()
	db := filepath.Join(d, "app.db")
	c, _ := sql.Open("sqlite3", db)
	_, _ = c.Exec(`CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, plan TEXT);
		WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 10000)
		INSERT INTO users(email, plan) SELECT 'u'||i||'@ex.com', 'free' FROM n;`)
	c.Close()
	m, _ := tx.NewManager(filepath.Join(d, "state"), policy.Default())
	m.Register(sqlite.New(db))
	k, _ := vault.OpenKeyring(filepath.Join(d, "keys"))
	v, _ := vault.Open(vault.Options{Replicas: []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")},
		LockPath: filepath.Join(d, "l"), Keys: k})
	m.Vault = v
	return m, db
}
