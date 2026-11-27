package mysqlgw

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	_ "github.com/go-sql-driver/mysql"

	"undolayer/internal/connectors/mysql"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

// UNDOLAYER_TEST_MYSQL: mysql://root:pw@127.0.0.1:53306/
type env struct {
	direct *sql.DB
	gw     *Gateway
	m      *tx.Manager
	v      *vault.Vault
	addr   string
	db     string
}

func setup(t *testing.T, mod func(*Route)) *env {
	t.Helper()
	base := os.Getenv("UNDOLAYER_TEST_MYSQL")
	if base == "" {
		t.Skip("set UNDOLAYER_TEST_MYSQL to run the MySQL gateway tests")
	}
	a, err := mysql.ParseURI(base)
	if err != nil {
		t.Fatal(err)
	}
	db := "gw_" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))
	root, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/?multiStatements=true", a.User, a.Password, a.Host))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	for _, q := range []string{"DROP DATABASE IF EXISTS " + db, "CREATE DATABASE " + db, "USE " + db, "SET SESSION cte_max_recursion_depth = 10000",
		`CREATE TABLE accounts(id INT PRIMARY KEY, owner VARCHAR(50), balance DECIMAL(12,2), note TEXT NULL,
			blob_col VARBINARY(16) NULL, doc JSON NULL, at TIMESTAMP(6) NULL, d DATETIME NULL, f DOUBLE NULL,
			total DECIMAL(13,2) AS (balance + 1) VIRTUAL)`,
		`INSERT INTO accounts(id, owner, balance, blob_col, doc, at, d, f)
			WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM s WHERE i < 3000)
			SELECT i, CONCAT('o', i), i * 10.5, UNHEX('00FF10'), JSON_OBJECT('k', i), '2024-05-01 10:00:00.123456', '2024-01-01 00:00:00', i / 3 FROM s`,
		"CREATE TABLE parent(id INT PRIMARY KEY)", "CREATE TABLE child(id INT PRIMARY KEY, p INT, FOREIGN KEY (p) REFERENCES parent(id) ON DELETE CASCADE)",
		"INSERT INTO parent VALUES (1)", "INSERT INTO child VALUES (1, 1)",
		"CREATE TABLE nokey(v INT)", "INSERT INTO nokey VALUES (1)",
	} {
		if _, err := root.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	direct, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=false", a.User, a.Password, a.Host, db))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { direct.Close() })
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
	r := Route{Name: "main", Listen: "127.0.0.1:0", URI: strings.TrimSuffix(base, "/") + "/" + db, Trust: true}
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
	ready := make(chan struct{})
	go func() {
		if err := g.Sync(); err != nil {
			t.Error(err)
		}
		close(ready)
		_ = g.Serve(l)
	}()
	<-ready
	t.Cleanup(func() { g.Close(); _ = l.Close(); _ = m.Flush() })
	return &env{direct: direct, gw: g, m: m, v: v, addr: l.Addr().String(), db: db}
}

func (e *env) client(t *testing.T, cred string, interpolate bool) *sql.DB {
	t.Helper()
	if cred == "" {
		cred = "app"
	}
	c, err := sql.Open("mysql", fmt.Sprintf("%s@tcp(%s)/%s?interpolateParams=%v", cred, e.addr, e.db, interpolate))
	if err != nil {
		t.Fatal(err)
	}
	c.SetMaxOpenConns(4)
	t.Cleanup(func() { c.Close() })
	return c
}

func (e *env) row(t *testing.T, id int) string {
	t.Helper()
	var s sql.NullString
	err := e.direct.QueryRow("SELECT CONCAT_WS('|', owner, balance, IFNULL(note,'-'), HEX(blob_col), doc, at, d, f, total) FROM accounts WHERE id = ?", id).Scan(&s)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return s.String
}

func (e *env) scalar(t *testing.T, q string) string {
	t.Helper()
	var s sql.NullString
	if err := e.direct.QueryRow(q).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s.String
}

func (e *env) txWith(t *testing.T, table, op string, id int) string {
	t.Helper()
	_ = e.v.Flush()
	bs, _, err := e.v.Batches(func(r *vault.Record) bool { return r.Phase == "intent" })
	if err != nil {
		t.Fatal(err)
	}
	last := "" // the newest
	for _, b := range bs {
		for _, r := range b.Rows {
			if r.Table == e.db+"."+table && r.Op == op && fmt.Sprint(r.Key["id"]) == fmt.Sprint(id) {
				last = b.Tx
			}
		}
	}
	return last
}

func refused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "refused by Countersign")
}

// Reads and writes with prepared statements and with text queries; every committed write
// is in the vault and undone from it exactly, every type kept.
func TestWritesAreCapturedAndUndone(t *testing.T) {
	e := setup(t, nil)
	for _, interp := range []bool{false, true} {
		c := e.client(t, "", interp)
		base := 10000
		if interp {
			base = 20000
		}
		var owner string
		if err := c.QueryRow("SELECT owner FROM accounts WHERE id = ?", 7).Scan(&owner); err != nil || owner != "o7" {
			t.Fatalf("interp=%v read: %v %q", interp, err, owner)
		}
		before5, before6 := e.row(t, 5), e.row(t, 6)
		if _, err := c.Exec("UPDATE accounts SET balance = balance + 1, note = ?, blob_col = UNHEX('ABCD'), doc = JSON_ARRAY(1, 'x'), at = NOW(6) WHERE id = ?", "n", 5); err != nil {
			t.Fatalf("interp=%v update: %v", interp, err)
		}
		tx1, err := c.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx1.Exec("DELETE FROM accounts WHERE id = ?", 6); err != nil {
			t.Fatal(err)
		}
		if _, err := tx1.Exec("INSERT INTO accounts(id, owner, balance) VALUES (?, 'new', 1)", base); err != nil {
			t.Fatal(err)
		}
		if _, err := tx1.Exec("UPDATE accounts SET owner = 'twice' WHERE id = ?", base); err != nil {
			t.Fatal(err)
		}
		if err := tx1.Commit(); err != nil {
			t.Fatal(err)
		}
		tx2, _ := c.Begin()
		_, _ = tx2.Exec("DELETE FROM accounts WHERE id = 9")
		_ = tx2.Rollback()
		if e.row(t, 9) == "" {
			t.Fatal("rollback did not hold")
		}
		del := e.txWith(t, "accounts", "delete", 6)
		if del == "" || del != e.txWith(t, "accounts", "insert", base) {
			t.Fatalf("interp=%v: the transaction is not one vault entry", interp)
		}
		if rep, err := e.m.UndoFromVault(del); err != nil || !rep.Clean() {
			t.Fatalf("undo: %v %+v", err, rep)
		}
		if e.row(t, 6) != before6 || e.row(t, base) != "" {
			t.Fatalf("undo did not restore the transaction: %q vs %q", e.row(t, 6), before6)
		}
		upd := e.txWith(t, "accounts", "update", 5)
		if rep, err := e.m.UndoFromVault(upd); err != nil || !rep.Clean() {
			t.Fatalf("undo update: %v %+v", err, rep)
		}
		if got := e.row(t, 5); got != before5 {
			t.Fatalf("undo did not restore every type:\n got %q\nwant %q", got, before5)
		}
		if _, err := e.m.UndoFromVault(upd); err == nil {
			t.Fatal("undone twice")
		}
	}
	// a row changed after the write is a conflict, and nothing is written
	c := e.client(t, "", false)
	if _, err := c.Exec("UPDATE accounts SET owner = 'a' WHERE id = 40"); err != nil {
		t.Fatal(err)
	}
	id := e.txWith(t, "accounts", "update", 40)
	if _, err := e.direct.Exec("UPDATE accounts SET owner = 'later' WHERE id = 40"); err != nil {
		t.Fatal(err)
	}
	if rep, err := e.m.UndoFromVault(id); err == nil && rep.Clean() {
		t.Fatal("undo overwrote a later change")
	}
	if !strings.HasPrefix(e.row(t, 40), "later|") {
		t.Fatal("a refused undo wrote")
	}
	// direct sessions are not captured and not slowed
	if _, err := e.direct.Exec("UPDATE accounts SET owner = 'd' WHERE id = 41"); err != nil {
		t.Fatalf("a direct write failed: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	e := setup(t, nil)
	c := e.client(t, "", true)
	for name, q := range map[string]string{
		"tautology":   "SELECT * FROM accounts WHERE owner = 'x' OR 1=1",
		"sleep":       "SELECT SLEEP(1)",
		"versioned":   "SELECT 1 /*!50000 , SLEEP(1) */",
		"outfile":     "SELECT * FROM accounts INTO OUTFILE '/tmp/x'",
		"drop":        "DROP TABLE accounts",
		"truncate":    "TRUNCATE accounts",
		"drop column": "ALTER TABLE accounts DROP COLUMN note",
		"grant":       "GRANT ALL ON *.* TO 'app'@'%'",
		"capture off": "SET @countersign_capture = 0",
		"dynamic":     "PREPARE s FROM 'DELETE FROM accounts'",
		"procedure":   "CREATE PROCEDURE p() DELETE FROM accounts",
		"global":      "SET GLOBAL max_connections = 1",
		"mass":        "UPDATE accounts SET owner = 'all'",
		"cascade":     "DELETE FROM parent WHERE id = 1",
		"no key":      "UPDATE nokey SET v = 2",
		"processlist": "SHOW FULL PROCESSLIST",
		"perf schema": "SELECT * FROM performance_schema.events_statements_current",
	} {
		if _, err := c.Exec(q); !refused(err) {
			t.Errorf("%s was not refused: %v", name, err)
		}
	}
	if n := e.scalar(t, "SELECT COUNT(*) FROM accounts WHERE owner = 'all'"); n != "0" {
		t.Fatal("a refused write changed rows")
	}
	if n := e.scalar(t, "SELECT COUNT(*) FROM child"); n != "1" {
		t.Fatal("a refused cascade deleted rows")
	}
	// a transaction refused at COMMIT is rolled back
	tx1, _ := c.Begin()
	if _, err := tx1.Exec("UPDATE accounts SET owner = 'all' WHERE id > 0"); err != nil {
		t.Fatal(err)
	}
	if err := tx1.Commit(); !refused(err) {
		t.Fatalf("a mass change in a transaction was not refused: %v", err)
	}
	if n := e.scalar(t, "SELECT COUNT(*) FROM accounts WHERE owner = 'all'"); n != "0" {
		t.Fatal("a refused transaction committed")
	}
}

// A table created through the gateway gets capture at once; one created behind its back
// cannot be written until capture reaches it, and a column added behind its back makes the
// next capture refuse and reinstall.
func TestSchemaChanges(t *testing.T) {
	e := setup(t, nil)
	c := e.client(t, "", false)
	if _, err := c.Exec("CREATE TABLE t2(id INT PRIMARY KEY, v INT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec("INSERT INTO t2 VALUES (1, 1)"); err != nil {
		t.Fatalf("a table made through the gateway: %v", err)
	}
	if e.txWith(t, "t2", "insert", 1) == "" {
		t.Fatal("the new table's write is not in the vault")
	}
	if _, err := e.direct.Exec("CREATE TABLE t3(id INT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec("INSERT INTO t3 VALUES (1)"); !refused(err) {
		t.Fatalf("an uncaptured write was not refused: %v", err)
	}
	if e.scalar(t, "SELECT COUNT(*) FROM t3") != "0" {
		t.Fatal("an uncaptured write stayed")
	}
	if _, err := e.direct.Exec("ALTER TABLE t2 ADD COLUMN w INT DEFAULT 5"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec("UPDATE t2 SET v = 2 WHERE id = 1"); !refused(err) {
		t.Fatalf("a write with stale capture was not refused: %v", err)
	}
	if err := e.gw.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec("UPDATE t2 SET v = 2, w = 6 WHERE id = 1"); err != nil {
		t.Fatalf("after reinstalling: %v", err)
	}
	id := e.txWith(t, "t2", "update", 1)
	if rep, err := e.m.UndoFromVault(id); err != nil || !rep.Clean() {
		t.Fatalf("undo: %v %+v", err, rep)
	}
	if got := e.scalar(t, "SELECT CONCAT(v, ',', w) FROM t2 WHERE id = 1"); got != "1,5" {
		t.Fatalf("undo restored %q", got)
	}
}

func TestLogin(t *testing.T) {
	e := setup(t, func(r *Route) { r.Trust = false; r.Users = map[string]string{"app": "s3cret"} })
	if err := e.client(t, "app:s3cret", false).Ping(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := e.client(t, "app:wrong", false).Ping(); err == nil {
		t.Fatal("a wrong password logged in")
	}
}

// A pool's connection reset (COM_RESET_CONNECTION) leaves capture in place.
func TestConnectionReset(t *testing.T) {
	e := setup(t, nil)
	c, err := mysql.Dial(mysql.Addr{Host: e.addr, User: "app"}, e.db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Execute("UPDATE accounts SET owner = 'r1' WHERE id = 50"); err != nil {
		t.Fatal(err)
	}
	c.ResetSequence()
	if err := c.WritePacket([]byte{0, 0, 0, 0, gomysql.COM_RESET_CONNECTION}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadOKPacket(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := c.Execute("UPDATE accounts SET owner = 'r2' WHERE id = 50"); err != nil {
		t.Fatalf("a write after the reset: %v", err)
	}
	if e.txWith(t, "accounts", "update", 50) == "" {
		t.Fatal("the write after the reset is not in the vault")
	}
}
