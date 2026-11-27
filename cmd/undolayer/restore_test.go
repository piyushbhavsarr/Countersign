package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rowsIn(t *testing.T, db string) string {
	t.Helper()
	c, err := sql.Open("sqlite3", db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var s sql.NullString
	if err := c.QueryRow("SELECT group_concat(id, ',') FROM (SELECT id FROM orders WHERE id <= 4 ORDER BY id)").Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s.String
}

func run(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

// From the shipped binary: an agent deletes rows; an operator lists them, exports them,
// restores one, and reverts everything the requester did.
func TestChangesRestoreRevertFromTheCLI(t *testing.T) {
	f := newFixture(t, 10)
	cmd := exec.Command(f.bin, "serve", "-c", f.cfg)
	in, _ := cmd.StdinPipe()
	outp, _ := cmd.StdoutPipe()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &mcpClient{in: in, out: bufio.NewReader(outp)}
	c.send("initialize", map[string]any{"protocolVersion": "2025-06-18"})
	_, _ = c.recv()
	r, err := c.tool("undolayer_begin", map[string]any{"task": "close orders 1-3"})
	if err != nil {
		t.Fatal(err)
	}
	src := fmt.Sprint(r["tx"])
	if _, err := c.tool("sql_execute", map[string]any{"sql": "DELETE FROM orders WHERE id <= 3"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.tool("undolayer_commit", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	_ = in.Close()
	_ = cmd.Wait()
	if got := rowsIn(t, f.db); got != "4" {
		t.Fatalf("after delete: %s", got)
	}

	var doc struct {
		Rows    int `json:"rows"`
		Changes []struct {
			Source string `json:"source"`
		} `json:"changes"`
	}
	if err := json.Unmarshal([]byte(run(t, f.bin, "changes", src, "--op", "delete", "-c", f.cfg)), &doc); err != nil || doc.Rows != 3 {
		t.Fatalf("changes: %v %+v", err, doc)
	}
	csvPath := filepath.Join(t.TempDir(), "deleted.csv")
	run(t, f.bin, "changes", src, "--format", "csv", "--out", csvPath, "-c", f.cfg)
	b, _ := os.ReadFile(csvPath)
	if fi, _ := os.Stat(csvPath); fi.Mode().Perm() != 0o600 || strings.Count(string(b), "\n") != 4 {
		t.Fatalf("csv (%v):\n%s", fi.Mode(), b)
	}
	sqlOut := run(t, f.bin, "changes", src, "--format", "sql", "-c", f.cfg)
	if !strings.Contains(sqlOut, `INSERT INTO "orders" ("id", "note") VALUES (2, 'x');`) {
		t.Fatalf("sql export:\n%s", sqlOut)
	}

	if out := run(t, f.bin, "restore", src, "--key", `{"id": 2}`, "--dry-run", "-c", f.cfg); !strings.Contains(out, "nothing was changed") {
		t.Fatalf("dry run: %s", out)
	}
	if got := rowsIn(t, f.db); got != "4" {
		t.Fatalf("dry run changed data: %s", got)
	}
	run(t, f.bin, "restore", src, "--key", `{"id": 2}`, "--yes", "-c", f.cfg)
	if got := rowsIn(t, f.db); got != "2,4" {
		t.Fatalf("after restore of 2: %s", got)
	}

	u, _ := user.Current()
	run(t, f.bin, "revert", "--requester", u.Username, "--since", "1h", "--yes", "-c", f.cfg)
	if got := rowsIn(t, f.db); got != "1,2,3,4" {
		t.Fatalf("after revert: %s", got)
	}
	run(t, f.bin, "vault", "check", "-c", f.cfg)
}

func notes(t *testing.T, db string) string {
	t.Helper()
	c, err := sql.Open("sqlite3", db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var s string
	if err := c.QueryRow("SELECT group_concat(note, ',') FROM (SELECT note FROM orders WHERE id IN (5, 6, 7) ORDER BY id)").Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func agentTask(t *testing.T, f *fixture, stmts ...string) {
	t.Helper()
	cmd := exec.Command(f.bin, "serve", "-c", f.cfg)
	in, _ := cmd.StdinPipe()
	outp, _ := cmd.StdoutPipe()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &mcpClient{in: in, out: bufio.NewReader(outp)}
	c.send("initialize", map[string]any{"protocolVersion": "2025-06-18"})
	_, _ = c.recv()
	if _, err := c.tool("undolayer_begin", map[string]any{"task": "edit notes"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		if _, err := c.tool("sql_execute", map[string]any{"sql": s}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.tool("undolayer_commit", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	_ = in.Close()
	_ = cmd.Wait()
}

// One table back to a moment: two tasks' changes to it are undone newest first; another
// table they changed is left alone; the vault on disk holds no readable row data.
func TestRevertATableToAMoment(t *testing.T) {
	f := newFixture(t, 10)
	db, _ := sql.Open("sqlite3", f.db)
	_, _ = db.Exec("CREATE TABLE audit(id INTEGER PRIMARY KEY, what TEXT)")
	db.Close()
	before := time.Now().UTC().Add(-time.Second).Format(time.RFC3339)
	agentTask(t, f, "UPDATE orders SET note = 'a' WHERE id IN (5, 6)", "INSERT INTO audit(what) VALUES ('first')")
	agentTask(t, f, "UPDATE orders SET note = 'b' WHERE id IN (6, 7)", "INSERT INTO audit(what) VALUES ('second')")
	if got := notes(t, f.db); got != "a,b,b" {
		t.Fatalf("after tasks: %s", got)
	}
	run(t, f.bin, "revert", "--table", "orders", "--since", before, "--yes", "-c", f.cfg)
	if got := notes(t, f.db); got != "x,x,x" {
		t.Fatalf("after revert: %s", got)
	}
	db, _ = sql.Open("sqlite3", f.db)
	var n int
	_ = db.QueryRow("SELECT count(*) FROM audit").Scan(&n)
	db.Close()
	if n != 2 {
		t.Fatalf("the other table was reverted too: %d rows", n)
	}
	reps, _ := filepath.Glob(filepath.Join(filepath.Dir(f.cfg), "vault-*", "seg", "*.log"))
	if len(reps) == 0 {
		t.Fatal("no vault segments")
	}
	for _, p := range reps {
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), `"note"`) || strings.Contains(string(b), "first") {
			t.Fatalf("%s holds row data in the clear", p)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(f.cfg), "state", "vault.keys")); err != nil {
		t.Fatal("no keyring")
	}
	keys := run(t, f.bin, "vault", "keys", "-c", f.cfg)
	if !strings.Contains(keys, `"active"`) || strings.Contains(keys, "==") {
		t.Fatalf("keys listing: %s", keys)
	}
}
