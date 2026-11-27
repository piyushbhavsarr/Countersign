package e2e

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"undolayer/internal/bench"
	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

func withVault(t *testing.T, w *bench.World, m *tx.Manager) []string {
	t.Helper()
	d := t.TempDir()
	reps := []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")}
	keys, err := vault.OpenKeyring(filepath.Join(d, "keys", "vault.keys"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(vault.Options{Replicas: reps, LockPath: filepath.Join(d, "vault.lock"), Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	m.Vault = v
	t.Cleanup(func() { _ = m.Flush() }) // background vault writes finish before the directories go
	return v.Replicas()
}

func commit(t *testing.T, m *tx.Manager, x *tx.Tx) {
	t.Helper()
	approve(t, m, x)
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
}

func dbRows(t *testing.T, w *bench.World, q string) [][]any {
	t.Helper()
	c, err := sql.Open("sqlite3", w.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rows, err := c.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out [][]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		out = append(out, vals)
	}
	return out
}

func dbExec(t *testing.T, w *bench.World, q string) {
	t.Helper()
	c, err := sql.Open("sqlite3", w.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Exec(q); err != nil {
		t.Fatal(err)
	}
}

// What a delete removes is in every vault replica before the delete runs, and stays
// readable when the task's own journal is gone.
func TestVaultKeepsDeletedRowsEvenWithoutTheJournal(t *testing.T) {
	w := world(t)
	reps := withVault(t, w, w.Mgr)
	x := w.Mgr.Begin("remove free users 1 to 5")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM users WHERE id <= 5 AND plan = 'free'"})
	commit(t, w.Mgr, x)
	if n := w.Count("users", "id <= 5"); n != 2 {
		t.Fatalf("users left %d", n)
	}
	for _, r := range reps {
		if fi, err := os.ReadDir(filepath.Join(r, "seg")); err != nil || len(fi) == 0 {
			t.Fatalf("replica %s holds nothing", r)
		}
	}
	if !w.Mgr.Vault.Check().Healthy {
		t.Fatal("vault not healthy")
	}
	// the journal is lost; a new process still finds every deleted row in the vault
	if err := os.Remove(filepath.Join(w.State, "tx", x.ID+".json")); err != nil {
		t.Fatal(err)
	}
	_ = w.Mgr.Flush() // another process reads what this one wrote
	m2 := w.MakeManager()
	m2.Vault = w.Mgr.Vault
	crs, err := m2.ChangedRows(x.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(crs) != 1 || crs[0].Source != "vault" || len(crs[0].Rows) != 3 {
		t.Fatalf("changed rows: %+v", crs)
	}
	got := map[string]bool{}
	for _, r := range crs[0].Rows {
		if r.Op != "delete" || r.After != nil || r.Before["plan"] != "free" {
			t.Fatalf("row %+v", r)
		}
		got[fmt.Sprint(r.Key["id"])] = true
		if r.Before["email"] != fmt.Sprintf("u%v@ex.com", r.Key["id"]) {
			t.Fatalf("row content %+v", r.Before)
		}
	}
	if !got["1"] || !got["3"] || !got["5"] {
		t.Fatalf("keys %v", got)
	}
	// and they can be put back from there
	y := m2.Begin("bring back user 3")
	if _, err := y.Call("sql", "restore_rows", map[string]any{"source_tx": x.ID, "keys": []any{map[string]any{"id": 3}}}); err != nil {
		t.Fatal(err)
	}
	commit(t, m2, y)
	if r := dbRows(t, w, "SELECT email, plan FROM users WHERE id = 3"); len(r) != 1 || r[0][0] != "u3@ex.com" || r[0][1] != "free" {
		t.Fatalf("user 3: %v", r)
	}
}

// No quorum, no change: the database is untouched.
func TestNoVaultQuorumMeansTheChangeDoesNotRun(t *testing.T) {
	w := world(t)
	reps := withVault(t, w, w.Mgr)
	for _, r := range reps[1:] {
		if err := os.RemoveAll(r); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(r, []byte("not a directory"), 0o600); err != nil { // two replicas broken
			t.Fatal(err)
		}
	}
	before := w.Count("orders", "")
	x := w.Mgr.Begin("clear orders")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders"})
	approve(t, w.Mgr, x)
	_, err := x.Commit()
	if err == nil || !strings.Contains(err.Error(), "vault could not store the before state") {
		t.Fatalf("commit should be refused: %v", err)
	}
	if n := w.Count("orders", ""); n != before {
		t.Fatalf("orders changed without a stored before state: %d -> %d", before, n)
	}
}

// Restore puts back only the chosen rows, refuses rows changed since, and is itself undoable.
func TestRestoreChosenRowsWithConflictCheck(t *testing.T) {
	w := world(t)
	withVault(t, w, w.Mgr)
	x := w.Mgr.Begin("downgrade users 1-4")
	call(t, x, "sql", "execute", map[string]any{"sql": "UPDATE users SET plan = 'cancelled' WHERE id <= 4"})
	commit(t, w.Mgr, x)
	// someone changes user 2 again afterwards, outside the earlier task
	dbExec(t, w, "UPDATE users SET plan = 'vip' WHERE id = 2")

	y := w.Mgr.Begin("restore 1 and 2")
	_, err := y.Call("sql", "restore_rows", map[string]any{"source_tx": x.ID,
		"keys": []any{map[string]any{"id": 1}, map[string]any{"id": 2}}})
	var cc *model.CommitConflict
	if !errors.As(err, &cc) || !strings.Contains(err.Error(), "1 of 2 rows") {
		t.Fatalf("want a conflict for user 2: %v", err)
	}
	r, err := y.Call("sql", "restore_rows", map[string]any{"source_tx": x.ID, "on_conflict": "skip",
		"keys": []any{map[string]any{"id": 1}, map[string]any{"id": 2}}})
	if err != nil {
		t.Fatal(err)
	}
	if m := r.(map[string]any); fmt.Sprint(m["rows_restored"]) != "1" || !strings.Contains(fmt.Sprint(m["conflicts"]), "plan:vip") {
		t.Fatalf("result %v", m)
	}
	commit(t, w.Mgr, y)
	plans := dbRows(t, w, "SELECT id, plan FROM users WHERE id <= 4 ORDER BY id")
	want := []string{"free", "vip", "cancelled", "cancelled"} // 1 back; 2 kept the newer change; 3, 4 not chosen
	for i, p := range plans {
		if p[1] != want[i] {
			t.Fatalf("plans %v", plans)
		}
	}
	// restoring again finds user 1 already as before and changes nothing
	z := w.Mgr.Begin("restore 1 again")
	r, err = z.Call("sql", "restore_rows", map[string]any{"source_tx": x.ID, "keys": []any{map[string]any{"id": 1}}})
	if err != nil || fmt.Sprint(r.(map[string]any)["rows_already_as_before"]) != "1" {
		t.Fatalf("%v %v", r, err)
	}
	_, _ = z.Rollback("nothing to do")
	// the restore can be undone like any task
	if _, err := y.Undo(""); err != nil {
		t.Fatal(err)
	}
	if p := dbRows(t, w, "SELECT plan FROM users WHERE id = 1"); p[0][0] != "cancelled" {
		t.Fatalf("undo of restore: %v", p)
	}
}

// Values come back with their exact storage class: integers past 2^53, reals that look
// like integers, text that looks like a number, blobs, NULLs.
func TestRestoreKeepsExactTypes(t *testing.T) {
	w := world(t)
	withVault(t, w, w.Mgr)
	dbExec(t, w, `CREATE TABLE vals(id INTEGER PRIMARY KEY, big INT, r REAL, txt TEXT, b BLOB, n);
		INSERT INTO vals VALUES (1, 9007199254740993, 2.0, '0042', x'00ff10', NULL),
		                        (2, -1, 1e300, 'it''s', x'', 3.5)`)
	before := dbRows(t, w, "SELECT id, big, typeof(big), r, typeof(r), txt, typeof(txt), hex(b), typeof(b), n, typeof(n) FROM vals ORDER BY id")
	x := w.Mgr.Begin("drop all vals rows")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM vals"})
	commit(t, w.Mgr, x)
	y := w.Mgr.Begin("put them back")
	call(t, y, "sql", "restore_rows", map[string]any{"source_tx": x.ID, "tables": []any{"vals"}})
	commit(t, w.Mgr, y)
	after := dbRows(t, w, "SELECT id, big, typeof(big), r, typeof(r), txt, typeof(txt), hex(b), typeof(b), n, typeof(n) FROM vals ORDER BY id")
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("types changed:\n before %v\n after  %v", before, after)
	}
}

// Parents come back before their children, so foreign keys hold.
func TestRestoreRespectsForeignKeys(t *testing.T) {
	w := world(t)
	withVault(t, w, w.Mgr)
	dbExec(t, w, `CREATE TABLE teams(id INTEGER PRIMARY KEY, name TEXT);
		CREATE TABLE members(id INTEGER PRIMARY KEY, team INT REFERENCES teams(id), name TEXT);
		INSERT INTO teams VALUES (1, 'core'), (2, 'web');
		INSERT INTO members VALUES (10, 1, 'ana'), (11, 1, 'bo'), (12, 2, 'cy');`)
	x := w.Mgr.Begin("disband core")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM members WHERE team = 1"})
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM teams WHERE id = 1"})
	commit(t, w.Mgr, x)
	y := w.Mgr.Begin("bring core back")
	call(t, y, "sql", "restore_rows", map[string]any{"source_tx": x.ID})
	commit(t, w.Mgr, y)
	if n := w.Count("members", "team = 1"); n != 2 {
		t.Fatalf("members %d", n)
	}
	if n := w.Count("teams", ""); n != 2 {
		t.Fatalf("teams %d", n)
	}
}

// A row changed by someone else after the restore was staged, before it commits: the
// commit is refused and nothing is written.
func TestRestoreRefusedWhenTheRowChangesBeforeCommit(t *testing.T) {
	w := world(t)
	withVault(t, w, w.Mgr)
	x := w.Mgr.Begin("delete user 7")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM users WHERE id = 7"})
	commit(t, w.Mgr, x)
	y := w.Mgr.Begin("bring back user 7")
	call(t, y, "sql", "restore_rows", map[string]any{"source_tx": x.ID})
	dbExec(t, w, "INSERT INTO users(id, email, plan) VALUES (7, 'someone-else@ex.com', 'pro')") // races the restore
	approve(t, w.Mgr, y)
	if _, err := y.Commit(); err == nil {
		t.Fatal("commit should be refused")
	}
	if r := dbRows(t, w, "SELECT email FROM users WHERE id = 7"); len(r) != 1 || r[0][0] != "someone-else@ex.com" {
		t.Fatalf("the newer row was touched: %v", r)
	}
}

// The exported SQL, run by hand, restores exact values; text that looks like SQL stays text.
func TestSQLiteExportedSQLRestoresExactly(t *testing.T) {
	w := world(t)
	dbExec(t, w, `CREATE TABLE vals(id INTEGER PRIMARY KEY, big INT, r REAL, txt TEXT, b BLOB, n);
		INSERT INTO vals VALUES (1, 9007199254740993, 2.0, 'it''s''; DROP TABLE users; --', x'00ff10', NULL),
		                        (2, -1, 1e300, '0042', x'', 3.5), (3, 5, 0.1, 'keep', NULL, 'x')`)
	q := "SELECT id, big, typeof(big), r, typeof(r), txt, typeof(txt), hex(b), typeof(b), n, typeof(n) FROM vals ORDER BY id"
	before := dbRows(t, w, q)
	x := w.Mgr.Begin("change vals")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM vals WHERE id <= 2"})
	call(t, x, "sql", "execute", map[string]any{"sql": "UPDATE vals SET txt = 'changed', r = 9 WHERE id = 3"})
	call(t, x, "sql", "execute", map[string]any{"sql": "INSERT INTO vals(id, txt) VALUES (4, 'new')"})
	commit(t, w.Mgr, x)
	crs, err := w.Mgr.ChangedRows(x.ID)
	if err != nil || len(crs) != 1 {
		t.Fatal(err)
	}
	c, _ := w.Mgr.Connector("sql")
	stmts, err := c.(interface {
		ExportSQL(json.RawMessage, func(string, map[string]any) bool) ([]string, error)
	}).ExportSQL(crs[0].Record, nil)
	if err != nil {
		t.Fatal(err)
	}
	dbExec(t, w, strings.Join(stmts, "\n"))
	if after := dbRows(t, w, q); fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("export did not restore exactly:\n before %v\n after  %v", before, after)
	}
	if w.Count("users", "") != 250 {
		t.Fatal("text was run as SQL")
	}
}

// Injection signs stop a read before it runs, and send a write to a human.
func TestInjectionSignsBlockReadsAndHoldWrites(t *testing.T) {
	w := world(t)
	x := w.Mgr.Begin("look up user 5")
	_, err := x.Call("sql", "query", map[string]any{"sql": "SELECT * FROM users WHERE id = 5 OR 1=1"})
	if !isViolation(err) || !strings.Contains(err.Error(), "always-true OR") {
		t.Fatalf("injected read should be denied: %v", err)
	}
	r := call(t, x, "sql", "query", map[string]any{"sql": "SELECT * FROM users WHERE 1=1 AND id = 5"}) // a builder idiom
	if fmt.Sprint(r["row_count"]) != "1" {
		t.Fatalf("idiomatic query: %v", r)
	}
	call(t, x, "sql", "execute", map[string]any{"sql": "UPDATE users SET plan = 'x' WHERE id = 5 OR 'a'='a'"})
	pv := x.Preview()
	if pv["approval_required"] != true || !strings.Contains(fmt.Sprint(pv["approval_reasons"]), "always-true OR") {
		t.Fatalf("injected write should need approval: %v", pv["approval_reasons"])
	}
	_, _ = x.Rollback("test")
}

// A requester's shapes are learned when its tasks commit, not before.
func TestShapesAreLearnedOnlyFromCommittedTasks(t *testing.T) {
	w := world(t)
	q := map[string]any{"sql": "SELECT email FROM users WHERE id = ?", "params": []any{3}}
	x := w.Mgr.Begin("read")
	x.Call("sql", "query", q)
	if x.Actions[0].Facts["shape_new"] != true {
		t.Fatal("first use should be new")
	}
	_, _ = x.Rollback("no")
	y := w.Mgr.Begin("read again")
	y.Call("sql", "query", map[string]any{"sql": "SELECT email FROM users WHERE id = 9"})
	if y.Actions[0].Facts["shape_new"] != true {
		t.Fatal("a rolled-back task must not teach its shapes")
	}
	commit(t, w.Mgr, y)
	z := w.Mgr.Begin("third")
	z.Call("sql", "query", map[string]any{"sql": "select EMAIL from users where ID = 12"})
	if z.Actions[0].Facts["shape_new"] != false {
		t.Fatalf("same shape after commit: %v", z.Actions[0].Facts["shape_new"])
	}
	z.Call("sql", "query", map[string]any{"sql": "SELECT email FROM users WHERE id = 12 UNION SELECT plan FROM users"})
	if z.Actions[1].Facts["shape_new"] != true {
		t.Fatal("a UNION added to a known query is a new shape")
	}
	_, _ = z.Rollback("done")
}

// SQLite itself reports the functions a statement calls and the catalog tables it reads.
func TestSQLiteReportsCodeLoadingAndCatalogReads(t *testing.T) {
	w := world(t)
	x := w.Mgr.Begin("inspect")
	_, err := x.Call("sql", "query", map[string]any{"sql": "SELECT load_extension('/tmp/evil')"})
	if !isViolation(err) || !strings.Contains(err.Error(), "loads code") {
		t.Fatalf("load_extension should be denied: %v", err)
	}
	call(t, x, "sql", "query", map[string]any{"sql": "SELECT name FROM sqlite_master WHERE type = 'table'"})
	last := x.Actions[len(x.Actions)-1]
	if !strings.Contains(fmt.Sprint(last.Facts["sql_injection_signals"]), "system_catalog") {
		t.Fatalf("catalog read not reported: %v", last.Facts)
	}
	_, _ = x.Rollback("done")
}

// Files come back from the vault even when this machine's backup is gone: bytes, mode and
// links exactly, and a file changed since is not overwritten.
func TestRestoreFilesFromTheVault(t *testing.T) {
	w := world(t)
	bin := []byte{0, 1, 2, 255, 254, 10, 13, 0}
	if err := os.WriteFile(filepath.Join(w.WS, "logo.bin"), bin, 0o640); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(w.WS, "notes.txt"), []byte("v1\n"), 0o644)
	_ = os.Symlink("notes.txt", filepath.Join(w.WS, "link"))
	x := w.Mgr.Begin("tidy up")
	call(t, x, "fs", "delete", map[string]any{"path": "logo.bin"})
	call(t, x, "fs", "write", map[string]any{"path": "notes.txt", "content": "v2\n"})
	call(t, x, "fs", "delete", map[string]any{"path": "link"})
	call(t, x, "fs", "write", map[string]any{"path": "new.txt", "content": "new\n"})
	commit(t, w.Mgr, x)
	if err := os.RemoveAll(filepath.Join(w.State, "backups", x.ID)); err != nil { // the local backup is lost
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(w.State, "tx", x.ID+".json")) // and the journal
	_ = w.Mgr.Flush()                                         // another process reads what this one wrote
	m2 := w.MakeManager()
	m2.Vault = w.Mgr.Vault
	y := m2.Begin("bring them back")
	r, err := y.Call("fs", "restore_files", map[string]any{"source_tx": x.ID})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(r.(map[string]any)["files_restored"]) != "4" {
		t.Fatalf("result %v", r)
	}
	commit(t, m2, y)
	got, _ := os.ReadFile(filepath.Join(w.WS, "logo.bin"))
	fi, _ := os.Stat(filepath.Join(w.WS, "logo.bin"))
	if string(got) != string(bin) || fi.Mode().Perm() != 0o640 {
		t.Fatalf("logo.bin: %v %v", got, fi.Mode())
	}
	if b, _ := os.ReadFile(filepath.Join(w.WS, "notes.txt")); string(b) != "v1\n" {
		t.Fatalf("notes.txt: %q", b)
	}
	if l, _ := os.Readlink(filepath.Join(w.WS, "link")); l != "notes.txt" {
		t.Fatalf("link: %q", l)
	}
	if _, err := os.Stat(filepath.Join(w.WS, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("new.txt should be gone")
	}
	// a file changed since is a conflict, and nothing is written
	_ = os.WriteFile(filepath.Join(w.WS, "notes.txt"), []byte("human edit\n"), 0o644)
	z := m2.Begin("again")
	if _, err := z.Call("fs", "restore_files", map[string]any{"source_tx": y.ID}); err == nil ||
		!strings.Contains(err.Error(), "cannot be put back") {
		t.Fatalf("want conflict: %v", err)
	}
	_, _ = z.Rollback("done")
}

// Every scenario above ran with the vault: it holds what each committed change replaced,
// for every kind of connector that describes its changes.
func TestVaultRowsForEveryConnector(t *testing.T) {
	w := world(t)
	x := w.Mgr.Begin("several systems")
	call(t, x, "sql", "execute", map[string]any{"sql": "DELETE FROM orders WHERE id = 1"})
	call(t, x, "fs", "write", map[string]any{"path": "README.md", "content": "changed\n"})
	commit(t, w.Mgr, x)
	bs, err := w.Mgr.Vault.ForTx(x.ID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, b := range bs {
		if b.Phase == "intent" && len(b.Rows) > 0 {
			seen[b.Connector] = true
		}
	}
	if !seen["sql"] || !seen["fs"] {
		t.Fatalf("vault entries: %v", seen)
	}
}

// A dropped table comes back with its rows, indexes and triggers; a dropped column comes
// back with its values. (The default policy refuses drops; this world allows them.)
func TestRestoreDroppedTableAndColumn(t *testing.T) {
	w := bench.NewWorld(policy.Empty(), true)
	t.Cleanup(w.Close)
	withVault(t, w, w.Mgr)
	dbExec(t, w, `CREATE TABLE invoices(id INTEGER PRIMARY KEY, n INT, note TEXT);
		CREATE INDEX ix_inv_n ON invoices(n);
		CREATE TABLE log(id INTEGER PRIMARY KEY, what TEXT);
		CREATE TRIGGER inv_log AFTER INSERT ON invoices BEGIN INSERT INTO log(what) VALUES ('inv'); END;
		INSERT INTO invoices VALUES (1, 10, 'a'), (2, 20, NULL), (3, 30, 'c');
		DELETE FROM log;
		ALTER TABLE users ADD COLUMN phone TEXT DEFAULT 'none';
		UPDATE users SET phone = '555-01' || id WHERE id <= 3;`)
	inv := dbRows(t, w, "SELECT * FROM invoices ORDER BY id")
	phones := dbRows(t, w, "SELECT id, phone FROM users WHERE id <= 5 ORDER BY id")
	x := w.Mgr.Begin("drop things")
	call(t, x, "sql", "execute", map[string]any{"sql": "DROP TABLE invoices"})
	call(t, x, "sql", "execute", map[string]any{"sql": "ALTER TABLE users DROP COLUMN phone"})
	commit(t, w.Mgr, x)
	y := w.Mgr.Begin("bring them back")
	r := call(t, y, "sql", "restore_rows", map[string]any{"source_tx": x.ID})
	if !strings.Contains(fmt.Sprint(r["schema_restored"]), "invoices") {
		t.Fatalf("result %v", r)
	}
	commit(t, w.Mgr, y)
	if got := dbRows(t, w, "SELECT * FROM invoices ORDER BY id"); fmt.Sprint(got) != fmt.Sprint(inv) {
		t.Fatalf("invoices %v want %v", got, inv)
	}
	if got := dbRows(t, w, "SELECT id, phone FROM users WHERE id <= 5 ORDER BY id"); fmt.Sprint(got) != fmt.Sprint(phones) {
		t.Fatalf("phones %v want %v", got, phones)
	}
	if n := dbRows(t, w, "SELECT count(*) FROM sqlite_master WHERE name IN ('ix_inv_n', 'inv_log')"); fmt.Sprint(n[0][0]) != "2" {
		t.Fatalf("index and trigger: %v", n)
	}
	if n := w.Count("log", ""); n != 0 {
		t.Fatalf("restoring the rows fired the trigger %d times", n)
	}
	// and the restore can be undone
	if _, err := y.Undo(""); err != nil {
		t.Fatal(err)
	}
	if n := dbRows(t, w, "SELECT count(*) FROM sqlite_master WHERE name = 'invoices'"); fmt.Sprint(n[0][0]) != "0" {
		t.Fatal("undo of the restore left the table")
	}
}
