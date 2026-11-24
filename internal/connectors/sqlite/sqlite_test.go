package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

func setup(t *testing.T, schema string) (string, *tx.Manager) {
	t.Helper()
	d := t.TempDir()
	db := filepath.Join(d, "a.db")
	c, err := sql.Open("sqlite3", db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(schema); err != nil {
		t.Fatal(err)
	}
	c.Close()
	m, err := tx.NewManager(filepath.Join(d, "state"), policy.Empty())
	if err != nil {
		t.Fatal(err)
	}
	m.Register(New(db))
	return db, m
}

// snap: every row of every table (rowid included, values exact) + structural signature.
func snap(t *testing.T, db string) []any {
	c, _ := sql.Open("sqlite3", db)
	defer c.Close()
	ctx := context.Background()
	out := []any{}
	tables, _ := query(ctx, c, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	for _, tb := range tables {
		info, _ := xinfo(ctx, c, tb[0].S)
		m := tableMeta(ctx, c, tb[0].S, info)
		sel := selectList(m, true)
		if m.Rowid && m.Alias != "" {
			sel = "rowid, " + sel
		}
		rows, err := query(ctx, c, "SELECT "+sel+" FROM "+q(tb[0].S)+" ORDER BY 1")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tb[0].S, fmt.Sprint(rows))
	}
	sig, _ := signature(ctx, c, true)
	trig, _ := query(ctx, c, "SELECT name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name")
	return append(out, sig, fmt.Sprint(trig))
}

const fixture = `
CREATE TABLE u(id INTEGER PRIMARY KEY, email TEXT, plan TEXT, seen DATETIME);
CREATE TABLE o(id INTEGER PRIMARY KEY, uid INT REFERENCES u(id) ON DELETE CASCADE, t INT);
CREATE TABLE kv(k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID;
CREATE TABLE nr(a, b REAL, g TEXT GENERATED ALWAYS AS (a || 'x') VIRTUAL);
CREATE TABLE audit(id INTEGER PRIMARY KEY, what TEXT);
CREATE TRIGGER au AFTER UPDATE ON kv BEGIN INSERT INTO audit(what) VALUES ('kv:' || NEW.k); END;
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 30)
  INSERT INTO u(email, plan, seen) SELECT 'u' || i, 'free', '2024-01-0' || (i % 9 + 1) FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < 39) INSERT INTO o(uid, t) SELECT i % 30 + 1, i FROM n;
INSERT INTO kv VALUES ('a', x'00ff'), ('mixed', 'text-not-blob');
INSERT INTO nr(a, b) VALUES (0, 0.0), (1, 1.0/3), (2, 2.0/3), (3, 1e308), (4, 'x');
CREATE TABLE dyn(id INTEGER PRIMARY KEY, x);
INSERT INTO dyn(x) VALUES (1), ('1'), (x'31'), (1.0), (NULL), ('');
`

func TestExactUndoOfDataAndSchema(t *testing.T) {
	db, m := setup(t, fixture)
	s0 := snap(t, db)
	x := m.Begin("everything")
	stmts := []string{
		"WITH x AS (SELECT id FROM u WHERE id < 4) UPDATE u SET plan='pro' WHERE id IN (SELECT id FROM x)",
		"DELETE FROM dyn WHERE id IN (1, 2, 3, 4)", "UPDATE dyn SET x = 'changed' WHERE id = 5",
		"DELETE FROM u AS z WHERE z.id = 5",
		"INSERT OR REPLACE INTO u(id, email) VALUES (6, 'r')",
		"INSERT INTO u(id, email, plan) VALUES (7, 'x', 'y') ON CONFLICT(id) DO UPDATE SET plan = excluded.plan",
		"UPDATE kv SET k = k || '2', v = x'01'",
		"DELETE FROM nr WHERE a = 2", "UPDATE nr SET b = b * 2 WHERE typeof(b) = 'real'",
		"ALTER TABLE u ADD COLUMN nick TEXT", "UPDATE u SET nick = 'n' WHERE id = 1",
		"ALTER TABLE o DROP COLUMN t", "CREATE INDEX ix ON u(email)",
		"ALTER TABLE u RENAME TO users_old", "CREATE TABLE u(id INTEGER PRIMARY KEY)",
		"INSERT INTO u VALUES (1)", "CREATE TRIGGER t2 AFTER DELETE ON kv BEGIN SELECT 1; END",
		"DROP TABLE nr",
	}
	for _, s := range stmts {
		r, err := x.Call("sql", "execute", map[string]any{"sql": s})
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if s == "DELETE FROM u AS z WHERE z.id = 5" {
			if n := r.(map[string]any)["rows_affected"]; fmt.Sprint(n) != "3" {
				t.Fatalf("cascade not captured: %v", r)
			}
		}
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(snap(t, db), s0) {
		t.Fatal("commit changed nothing")
	}
	rep, err := x.Undo("")
	if err != nil || rep.State != model.Undone {
		t.Fatalf("undo: %v %+v", err, rep)
	}
	if got := snap(t, db); !reflect.DeepEqual(got, s0) {
		for i := range got {
			if !reflect.DeepEqual(got[i], s0[i]) {
				t.Fatalf("not restored exactly at %d:\n got %v\nwant %v", i, got[i], s0[i])
			}
		}
	}
}

func TestEngineRefusesEscapes(t *testing.T) {
	db, m := setup(t, fixture)
	x := m.Begin("t")
	if _, err := x.Call("sql", "execute", map[string]any{"sql": "DELETE FROM o WHERE id = 1"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"COMMIT", "ATTACH 'x.db' AS x", "PRAGMA foreign_keys=OFF", "SAVEPOINT s"} {
		_, err := x.Call("sql", "execute", map[string]any{"sql": s})
		if err == nil {
			t.Fatalf("%s was allowed", s)
		}
	}
	if _, err := x.Rollback("t"); err != nil {
		t.Fatal(err)
	}
	c, _ := sql.Open("sqlite3", db)
	defer c.Close()
	var n int
	_ = c.QueryRow("SELECT COUNT(*) FROM o").Scan(&n)
	if n != 40 {
		t.Fatalf("COMMIT escaped staging: %d rows", n)
	}
}

func TestUndoRefusesToClobberLaterWrites(t *testing.T) {
	db, m := setup(t, fixture)
	x := m.Begin("t")
	if _, err := x.Call("sql", "execute", map[string]any{"sql": "UPDATE u SET plan='gold' WHERE id = 3"}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	c, _ := sql.Open("sqlite3", db)
	_, _ = c.Exec("UPDATE u SET plan='human' WHERE id = 3")
	c.Close()
	rep, err := x.Undo("")
	if err != nil || len(rep.Conflicts) == 0 {
		t.Fatalf("expected a conflict: %v %+v", err, rep)
	}
	c, _ = sql.Open("sqlite3", db)
	defer c.Close()
	var plan string
	_ = c.QueryRow("SELECT plan FROM u WHERE id = 3").Scan(&plan)
	if plan != "human" {
		t.Fatalf("human edit overwritten: %s", plan)
	}
}

func TestDeniedStatementDiscardedAlone(t *testing.T) {
	db, m := setup(t, fixture)
	m.Policy = policy.Default()
	x := m.Begin("t")
	if _, err := x.Call("sql", "execute", map[string]any{"sql": "UPDATE u SET plan='gold' WHERE id = 1"}); err != nil {
		t.Fatal(err)
	}
	_, err := x.Call("sql", "execute", map[string]any{"sql": "ALTER TABLE u DROP COLUMN email"})
	var pv *model.PolicyViolation
	if !errors.As(err, &pv) || fmt.Sprint(pv.Action.Facts["data_lost_rows"]) != "30" {
		t.Fatalf("drop column not measured/denied: %v", err)
	}
	if _, err := x.Call("sql", "execute", map[string]any{"sql": "UPDATE o SET t = 0; DROP TABLE o"}); err == nil {
		t.Fatal("script with DROP allowed")
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	c, _ := sql.Open("sqlite3", db)
	defer c.Close()
	var n, z int
	_ = c.QueryRow("SELECT COUNT(*) FROM u WHERE plan='gold' AND email IS NOT NULL").Scan(&n)
	_ = c.QueryRow("SELECT COUNT(*) FROM o WHERE t = 0").Scan(&z)
	if n != 1 || z != 1 { // only the original t=0 row
		t.Fatalf("expected the allowed update only: gold=%d zeros=%d", n, z)
	}
}

func TestSplitStatements(t *testing.T) {
	got := SplitStatements("CREATE TRIGGER x AFTER INSERT ON p BEGIN SELECT 1; SELECT ';'; END; SELECT 2;")
	if len(got) != 2 {
		t.Fatalf("%q", got)
	}
}
