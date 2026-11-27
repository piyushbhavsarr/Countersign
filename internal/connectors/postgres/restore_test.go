package postgres

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"undolayer/internal/model"
	"undolayer/internal/vault"
)

func rowsJSON(t *testing.T, dsn, q string) string {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
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

func pgExec(t *testing.T, dsn, q string) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, q); err != nil {
		t.Fatal(err)
	}
}

// Rows deleted (with their cascaded children) and updated by one task come back exactly,
// every type included, except a row someone changed since, which is reported and kept.
func TestPGRestoreRowsExactlyWithConflicts(t *testing.T) {
	dsn, m := setup(t)
	d := t.TempDir()
	v, err := vault.Open(vault.Options{Replicas: []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")},
		LockPath: filepath.Join(d, "l")})
	if err != nil {
		t.Fatal(err)
	}
	m.Vault = v
	uq := "SELECT string_agg(to_jsonb(u)::text, E'\\n' ORDER BY id) FROM u WHERE id <= 3"
	oq := "SELECT string_agg(to_jsonb(o)::text, E'\\n' ORDER BY id) FROM o WHERE uid <= 3"
	u0, o0 := rowsJSON(t, dsn, uq), rowsJSON(t, dsn, oq)
	if u0 == "" || o0 == "" {
		t.Fatal("fixture")
	}
	x := m.Begin("remove three users, downgrade one")
	for _, s := range []string{"DELETE FROM u WHERE id <= 3", "UPDATE u SET plan = 'gold' WHERE id = 4"} {
		if _, err := x.Call("sql", "execute", map[string]any{"sql": s}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	pgExec(t, dsn, "UPDATE u SET plan = 'vip' WHERE id = 4") // a newer change, outside the task

	y := m.Begin("restore")
	_, err = y.Call("sql", "restore_rows", map[string]any{"source_tx": x.ID})
	var cc *model.CommitConflict
	if !errors.As(err, &cc) || !strings.Contains(err.Error(), "1 of") {
		t.Fatalf("want conflict on user 4: %v", err)
	}
	r, err := y.Call("sql", "restore_rows", map[string]any{"source_tx": x.ID, "on_conflict": "skip"})
	if err != nil {
		t.Fatal(err)
	}
	res := r.(map[string]any)
	if !strings.Contains(fmt.Sprint(res["conflicts"]), "vip") {
		t.Fatalf("conflict not reported: %v", res)
	}
	if _, err := y.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := rowsJSON(t, dsn, uq); got != u0 {
		t.Fatalf("users not restored exactly:\n got %s\nwant %s", got, u0)
	}
	if got := rowsJSON(t, dsn, oq); got != o0 {
		t.Fatalf("orders not restored exactly:\n got %s\nwant %s", got, o0)
	}
	if p := rowsJSON(t, dsn, "SELECT plan FROM u WHERE id = 4"); p != "vip" {
		t.Fatalf("newer change overwritten: %s", p)
	}
	// only chosen rows: restore again by key finds them already back
	z := m.Begin("again")
	r, err = z.Call("sql", "restore_rows", map[string]any{"source_tx": x.ID, "tables": []any{"u"},
		"keys": []any{map[string]any{"id": 2}}})
	if err != nil || fmt.Sprint(r.(map[string]any)["rows_already_as_before"]) != "1" {
		t.Fatalf("%v %v", r, err)
	}
	_, _ = z.Rollback("nothing to do")
	// the restore itself is undoable
	if _, err := y.Undo(""); err != nil {
		t.Fatal(err)
	}
	if got := rowsJSON(t, dsn, uq); got != "" {
		t.Fatalf("undo of the restore left %s", got)
	}
	if !v.Check().Healthy {
		t.Fatal("vault")
	}
}

// The exported SQL, run by hand, puts the rows back exactly; data that looks like SQL or
// like the dollar-quote tag stays data.
func TestPGExportedSQLRestoresExactly(t *testing.T) {
	dsn, m := setup(t)
	pgExec(t, dsn, `UPDATE u SET email = 'x$cs$''; DROP TABLE o; --' WHERE id = 2`)
	uq := "SELECT string_agg(to_jsonb(u)::text, E'\\n' ORDER BY id) FROM u WHERE id <= 4"
	oq := "SELECT string_agg(to_jsonb(o)::text, E'\\n' ORDER BY id) FROM o"
	u0, o0 := rowsJSON(t, dsn, uq), rowsJSON(t, dsn, oq)
	x := m.Begin("delete and change")
	for _, s := range []string{"DELETE FROM o WHERE uid <= 3", "DELETE FROM u WHERE id <= 3", "UPDATE u SET plan = 'gold', ratio = 2 WHERE id = 4",
		"INSERT INTO u(email, plan) VALUES ('created', 'pro')"} {
		if _, err := x.Call("sql", "execute", map[string]any{"sql": s}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	crs, err := m.ChangedRows(x.ID)
	if err != nil || len(crs) != 1 {
		t.Fatal(err)
	}
	c, _ := m.Connector("sql")
	stmts, err := c.(*Connector).ExportSQL(crs[0].Record, nil)
	if err != nil {
		t.Fatal(err)
	}
	// parents first for inserts, as a person would run them: users, then orders
	var users, rest []string
	for _, s := range stmts {
		if strings.Contains(s, "public.u'") || strings.HasPrefix(s, "DELETE FROM public.u ") {
			users = append(users, s)
		} else {
			rest = append(rest, s)
		}
	}
	for _, s := range append(users, rest...) {
		pgExec(t, dsn, s)
	}
	if got := rowsJSON(t, dsn, uq); got != u0 {
		t.Fatalf("users:\n got %s\nwant %s", got, u0)
	}
	if got := rowsJSON(t, dsn, oq); got != o0 {
		t.Fatalf("orders:\n got %s\nwant %s", got, o0)
	}
	if n := rowsJSON(t, dsn, "SELECT count(*)::text FROM u WHERE email = 'created'"); n != "0" {
		t.Fatalf("created row not removed: %s", n)
	}
}
