package pggw

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"undolayer/internal/connectors/postgres"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

type env struct {
	dsn string // direct, for checking
	gw  *Gateway
	m   *tx.Manager
	url string // through the gateway
	v   *vault.Vault
}

func setup(t *testing.T, mod func(*Route)) *env {
	t.Helper()
	base := os.Getenv("UNDOLAYER_TEST_PG")
	if base == "" {
		t.Skip("set UNDOLAYER_TEST_PG to run the gateway tests")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	db := "gw_" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+db+" WITH (FORCE)")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	admin.Close(ctx)
	dsn := base[:strings.LastIndex(base, "/")+1] + db
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `CREATE TABLE accounts(id int PRIMARY KEY, owner text, balance numeric(12,2), tags text[]);
		INSERT INTO accounts SELECT i, 'o' || i, i * 10.5, ARRAY['a'] FROM generate_series(1, 3000) i;
		CREATE TABLE nokey(v int); INSERT INTO nokey VALUES (1);`); err != nil {
		t.Fatal(err)
	}
	c.Close(ctx)
	if err := postgres.Install(dsn); err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	m, err := tx.NewManager(filepath.Join(d, "state"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(vault.Options{Replicas: []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")},
		LockPath: filepath.Join(d, "l")})
	if err != nil {
		t.Fatal(err)
	}
	m.Vault = v
	r := Route{Name: "main", Listen: "127.0.0.1:0", Primary: dsn, Trust: true}
	if mod != nil {
		mod(&r)
	}
	g, err := New(r, m)
	if err != nil {
		t.Fatal(err)
	}
	m.Register(g.Conn)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Serve(l) }()
	t.Cleanup(func() { g.Close(); _ = l.Close(); _ = m.Flush() })
	url := fmt.Sprintf("postgres://app@%s/%s?sslmode=disable", l.Addr(), db)
	return &env{dsn: dsn, gw: g, m: m, url: url, v: v}
}

func (e *env) connect(t *testing.T, simple bool) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(e.url)
	if err != nil {
		t.Fatal(err)
	}
	if simple {
		cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	}
	c, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func (e *env) scalar(t *testing.T, q string) string {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, e.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var s *string
	if err := c.QueryRow(ctx, q).Scan(&s); err != nil {
		t.Fatal(err)
	}
	if s == nil {
		return ""
	}
	return *s
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// Reads and writes in both protocols; every committed write is in the vault, and can be
// undone from it.
func TestReadsWritesAndUndo(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	for _, simple := range []bool{false, true} {
		c := e.connect(t, simple)
		var owner string
		if err := c.QueryRow(ctx, "SELECT owner FROM accounts WHERE id = $1", 7).Scan(&owner); err != nil || owner != "o7" {
			t.Fatalf("simple=%v read: %v %q", simple, err, owner)
		}
		// autocommit write
		if _, err := c.Exec(ctx, "UPDATE accounts SET balance = balance + 1 WHERE id = $1", 7); err != nil {
			t.Fatalf("simple=%v update: %v", simple, err)
		}
		// explicit transaction
		tx1, err := c.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx1.Exec(ctx, "DELETE FROM accounts WHERE id = $1", 8); err != nil {
			t.Fatal(err)
		}
		if _, err := tx1.Exec(ctx, "INSERT INTO accounts VALUES ($1, 'new', 1, '{}')", 100000); err != nil {
			t.Fatal(err)
		}
		if err := tx1.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		// a rolled-back transaction keeps nothing
		tx2, _ := c.Begin(ctx)
		_, _ = tx2.Exec(ctx, "DELETE FROM accounts WHERE id = 9")
		_ = tx2.Rollback(ctx)
		if n := e.scalar(t, "SELECT count(*)::text FROM accounts WHERE id = 9"); n != "1" {
			t.Fatal("rollback did not hold")
		}
		before := e.scalar(t, "SELECT balance::text FROM accounts WHERE id = 7")
		// find the gateway transactions in the vault and undo the delete+insert one
		bs, _, err := e.v.Batches(func(r *vault.Record) bool { return r.Phase == "intent" })
		if err != nil {
			t.Fatal(err)
		}
		var del string
		for _, b := range bs {
			for _, r := range b.Rows {
				if r.Op == "delete" && fmt.Sprint(r.Key["id"]) == "8" {
					del = b.Tx
				}
			}
		}
		if del == "" {
			t.Fatalf("simple=%v: the delete is not in the vault (%d entries)", simple, len(bs))
		}
		_ = e.gw.waitBG()
		if rep, err := e.m.UndoFromVault(del); err != nil || !rep.Clean() {
			t.Fatalf("undo: %v %+v", err, rep)
		}
		if e.scalar(t, "SELECT count(*)::text FROM accounts WHERE id = 8") != "1" || e.scalar(t, "SELECT count(*)::text FROM accounts WHERE id = 100000") != "0" {
			t.Fatal("undo did not put the rows back")
		}
		if got := e.scalar(t, "SELECT balance::text FROM accounts WHERE id = 7"); got != before {
			t.Fatal("undo touched another transaction's change")
		}
		if _, err := e.m.UndoFromVault(del); err == nil {
			t.Fatal("undone twice")
		}
	}
}

// Refusals come from the server itself: a refused statement in a transaction aborts it,
// as any error would.
func TestRefusalsBehaveLikeServerErrors(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	for _, simple := range []bool{false, true} {
		c := e.connect(t, simple)
		_, err := c.Exec(ctx, "SELECT * FROM accounts WHERE owner = 'x' OR 1=1")
		if pgCode(err) != "42501" || !strings.Contains(err.Error(), "refused by Countersign") {
			t.Fatalf("simple=%v injection: %v", simple, err)
		}
		if err := c.Ping(ctx); err != nil {
			t.Fatalf("session unusable after a refusal: %v", err)
		}
		tx1, _ := c.Begin(ctx)
		_, _ = tx1.Exec(ctx, "UPDATE accounts SET owner = 'z' WHERE id = 1")
		_, err = tx1.Exec(ctx, "DROP TABLE accounts")
		if pgCode(err) != "42501" {
			t.Fatalf("drop: %v", err)
		}
		_, err = tx1.Exec(ctx, "SELECT 1")
		if pgCode(err) != "25P02" { // current transaction is aborted
			t.Fatalf("the transaction should be aborted: %v", err)
		}
		_ = tx1.Rollback(ctx)
		if e.scalar(t, "SELECT owner FROM accounts WHERE id = 1") != "o1" {
			t.Fatal("a statement of the aborted transaction was applied")
		}
	}
}

// A transaction that changes too much is measured and refused at COMMIT; nothing is kept.
func TestMassChangeRefusedAtCommit(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	for _, simple := range []bool{false, true} {
		c := e.connect(t, simple)
		_, err := c.Exec(ctx, "DELETE FROM accounts WHERE id > 100")
		if pgCode(err) != "42501" || !strings.Contains(err.Error(), "over half of a table") {
			t.Fatalf("simple=%v mass delete: %v", simple, err)
		}
		if n := e.scalar(t, "SELECT count(*)::text FROM accounts"); n != "3000" {
			t.Fatalf("rows deleted: %s left", n)
		}
		var one int
		if err := c.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
			t.Fatalf("session after refusal: %v", err)
		}
		_, err = c.Exec(ctx, "UPDATE nokey SET v = 2")
		if pgCode(err) != "42501" || !strings.Contains(err.Error(), "primary key") {
			t.Fatalf("no primary key: %v", err)
		}
	}
}

// Watch mode refuses nothing and audits what it would have refused.
func TestWatchModeOnlyAudits(t *testing.T) {
	e := setup(t, func(r *Route) { r.Mode = "watch" })
	ctx := context.Background()
	c := e.connect(t, false)
	if _, err := c.Exec(ctx, "DELETE FROM accounts WHERE id > 100"); err != nil {
		t.Fatal(err)
	}
	_ = e.m.Flush()
	found := false
	_ = e.m.Store.AuditLines(func(l []byte) error {
		found = found || strings.Contains(string(l), "gateway_refused") && strings.Contains(string(l), `"mode":"watch"`)
		return nil
	})
	if !found {
		t.Fatal("watch mode did not audit what it would have refused")
	}
}

// No vault quorum: COMMIT does not happen.
func TestNoVaultQuorumNoCommit(t *testing.T) {
	e := setup(t, nil)
	for _, r := range e.v.Replicas()[1:] {
		_ = os.RemoveAll(r)
		_ = os.WriteFile(r, []byte("x"), 0o600)
	}
	c := e.connect(t, false)
	_, err := c.Exec(context.Background(), "UPDATE accounts SET owner = 'q' WHERE id = 3")
	if err == nil || !strings.Contains(err.Error(), "vault") {
		t.Fatalf("want refusal: %v", err)
	}
	if e.scalar(t, "SELECT owner FROM accounts WHERE id = 3") != "o3" {
		t.Fatal("committed without a stored before state")
	}
}

// Passwords: SCRAM-SHA-256 against the gateway's users; the database's own credentials
// stay in the gateway.
func TestSCRAMLogin(t *testing.T) {
	e := setup(t, func(r *Route) { r.Trust = false; r.Users = map[string]string{"app": "s3cret"} })
	ctx := context.Background()
	good := strings.Replace(e.url, "app@", "app:s3cret@", 1)
	c, err := pgx.Connect(ctx, good)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	c.Close(ctx)
	if _, err := pgx.Connect(ctx, strings.Replace(e.url, "app@", "app:wrong@", 1)); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := pgx.Connect(ctx, strings.Replace(e.url, "app@", "nobody:s3cret@", 1)); err == nil {
		t.Fatal("unknown user accepted")
	}
}

// COPY, multi-statement queries with transaction control, errors in a batch, reuse of
// pooled server connections.
func TestCopyMultiStatementErrorsAndPool(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	c := e.connect(t, false)
	n, err := c.CopyFrom(ctx, pgx.Identifier{"accounts"}, []string{"id", "owner", "balance", "tags"},
		pgx.CopyFromRows([][]any{{200001, "c1", 1.5, []string{"x"}}, {200002, "c2", 2.5, []string{}}}))
	if err != nil || n != 2 {
		t.Fatalf("copy: %v %d", err, n)
	}
	s := e.connect(t, true)
	if _, err := s.Exec(ctx, "BEGIN; UPDATE accounts SET owner = 'm' WHERE id = 10; COMMIT; SELECT 1"); err != nil {
		t.Fatalf("multi: %v", err)
	}
	if e.scalar(t, "SELECT owner FROM accounts WHERE id = 10") != "m" {
		t.Fatal("multi-statement update lost")
	}
	// a constraint error in an autocommit write: an error, then a usable idle session
	_, err = c.Exec(ctx, "INSERT INTO accounts VALUES (1, 'dup', 0, '{}')")
	if pgCode(err) != "23505" {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := c.Exec(ctx, "UPDATE accounts SET owner = 'after' WHERE id = 11"); err != nil {
		t.Fatalf("after an error: %v", err)
	}
	// pooled connections: a new session after DISCARD ALL still captures
	for i := 0; i < 3; i++ {
		p := e.connect(t, false)
		if _, err := p.Exec(ctx, "UPDATE accounts SET owner = $1 WHERE id = 12", fmt.Sprint("p", i)); err != nil {
			t.Fatal(err)
		}
		p.Close(ctx)
	}
	_ = e.m.Flush()
	_ = e.gw.waitBG()
	cnt := 0
	bs, _, _ := e.v.Batches(func(r *vault.Record) bool { return r.Phase == "intent" })
	for _, b := range bs {
		for _, r := range b.Rows {
			if fmt.Sprint(r.Key["id"]) == "12" || fmt.Sprint(r.Key["id"]) == "200001" || fmt.Sprint(r.Key["id"]) == "10" {
				cnt++
			}
		}
	}
	if cnt != 5 {
		t.Fatalf("vault holds %d of the 5 changed rows", cnt)
	}
}

// A client's cancel request reaches the query on the server.
func TestCancelReachesTheServer(t *testing.T) {
	e := setup(t, nil)
	c := e.connect(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Exec(ctx, "SELECT count(*) FROM generate_series(1, 2000000000)")
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("cancel: %v after %s", err, time.Since(start))
	}
}
