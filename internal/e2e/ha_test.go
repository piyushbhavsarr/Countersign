package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"undolayer/internal/model"
	"undolayer/internal/store"
	"undolayer/internal/tx"
)

// Several gateway nodes sharing one PostgreSQL state store (UNDOLAYER_TEST_STATE_PG).

func sharedStore(t *testing.T) func() *store.Postgres {
	dsn := os.Getenv("UNDOLAYER_TEST_STATE_PG")
	if dsn == "" {
		t.Skip("set UNDOLAYER_TEST_STATE_PG to run multi-node tests")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("ul_ha_%d", time.Now().UnixNano())
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	cfg, _ := pgx.ParseConfig(dsn)
	db := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", cfg.User, cfg.Password, cfg.Host, cfg.Port, name)
	return func() *store.Postgres {
		s, err := store.OpenPostgres(db)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
}

func TestAnotherNodeRecoversADeadNodesTask(t *testing.T) {
	open := sharedStore(t)
	w := world(t)
	a := w.MakeManagerOn(open(), "node-a")
	b := w.MakeManagerOn(open(), "node-b")

	x := a.Begin("charge the customer")
	call(t, x, "stripe", "charge", map[string]any{"amount_cents": 700, "currency": "usd", "customer": "cus_1"})
	if w.NetCharges() == 0 {
		t.Fatal("the charge did not run")
	}
	if r := b.Recover(); len(r) != 0 {
		t.Fatalf("node b recovered a task node a is still running: %+v", r)
	}

	a.Store.Close() // node a dies: the database drops its connection and its locks
	var rec []tx.Recovered
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(rec) == 0 {
		rec = b.Recover()
		time.Sleep(100 * time.Millisecond)
	}
	if len(rec) != 1 || rec[0].To != "rolled_back" {
		t.Fatalf("node b did not recover node a's task: %+v", rec)
	}
	if w.NetCharges() != 0 {
		t.Fatal("the charge was not refunded by the recovering node")
	}
	var no *model.NotOwner
	if _, err := x.Commit(); !errors.As(err, &no) {
		t.Fatalf("the dead node's session still committed: %v", err)
	}
}

func TestNodeLocalTasksAreLeftToTheirOwnNode(t *testing.T) {
	open := sharedStore(t)
	w := world(t)
	a := w.MakeManagerOn(open(), "node-a")
	b := w.MakeManagerOn(open(), "node-b")
	x := a.Begin("edit the app")
	call(t, x, "fs", "write", map[string]any{"path": "app.py", "content": "print('v2')\n"})
	a.Store.Close()
	time.Sleep(500 * time.Millisecond)
	if r := b.Recover(); len(r) != 0 {
		t.Fatalf("node b recovered a task whose workspace is on node a: %+v", r)
	}
	// node a comes back and recovers its own task
	a2 := w.MakeManagerOn(open(), "node-a")
	if r := a2.Recover(); len(r) != 1 {
		t.Fatalf("node a did not recover its own task: %+v", r)
	}
	if f, _ := w.File("app.py"); f != "print('v1')\n" {
		t.Fatal("staged write leaked")
	}
}

func TestTheAuditChainSpansNodes(t *testing.T) {
	open := sharedStore(t)
	w := world(t)
	a := w.MakeManagerOn(open(), "node-a")
	b := w.MakeManagerOn(open(), "node-b")
	for i := 0; i < 5; i++ {
		x := a.Begin("a")
		_, _ = x.Rollback("t")
		y := b.Begin("b")
		_, _ = y.Rollback("t")
	}
	if ok, msg := b.Audit.Verify(); !ok {
		t.Fatalf("chain across nodes broken: %s", msg)
	}
}
