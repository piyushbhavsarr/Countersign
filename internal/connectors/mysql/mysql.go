// Package mysql captures, undoes and restores row changes made through the MySQL gateway.
//
// Capture is by triggers the gateway installs (and keeps in step with the schema): AFTER
// INSERT, UPDATE and DELETE on every base table write the row before and after, as JSON,
// to countersign_log, but only in a session that has turned capture on. In a gateway
// session countersign_log is a TEMPORARY table shadowing the permanent one, so captured
// rows never reach the binary log or other sessions, and roll back with the transaction.
// The permanent table refuses inserts: a gateway session that somehow lost its temporary
// table fails its writes instead of writing uncaptured.
//
// Values keep their exact type: binary columns as hex, TIMESTAMP as epoch seconds (so a
// session time zone cannot shift them), JSON as JSON, the rest as MySQL renders them.
// Each trigger carries a hash of its table's columns; a capture whose hash no longer
// matches the table is refused, so a column added behind the gateway's back is never
// silently left out of a before state.
package mysql

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-mysql-org/go-mysql/client"

	"undolayer/internal/model"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

// Col is one captured column. Kind: plain, bin (hex), ts (epoch seconds), json.
type Col struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Table is what capture and restore need of one table.
type Table struct {
	DB   string   `json:"db"`
	Name string   `json:"name"`
	Cols []Col    `json:"cols"`
	PK   []string `json:"pk"`
	Hash string   `json:"hash"`
}

func (t *Table) Key() string { return t.DB + "." + t.Name }

// Row is one row's net change; Before and After are JSON objects ("" when absent).
type Row struct {
	DB     string `json:"db"`
	Table  string `json:"table"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// UndoRecord is what the gateway keeps for one transaction.
type UndoRecord struct {
	Tables map[string]*Table `json:"tables"` // db.table -> its columns when captured
	Rows   []Row             `json:"rows"`
}

// Addr is where a MySQL server is and how to log in.
type Addr struct {
	Host, User, Password, DB string
}

// ParseURI reads mysql://user:password@host:port/db.
func ParseURI(s string) (Addr, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "mysql" || u.Host == "" {
		return Addr{}, fmt.Errorf("a MySQL address is mysql://user:password@host:port/db")
	}
	a := Addr{Host: u.Host, DB: strings.TrimPrefix(u.Path, "/")}
	if !strings.Contains(a.Host, ":") {
		a.Host += ":3306"
	}
	if u.User != nil {
		a.User = u.User.Username()
		a.Password, _ = u.User.Password()
	}
	return a, nil
}

// Dial logs in.
func Dial(a Addr, db string) (*client.Conn, error) {
	c, err := client.ConnectWithTimeout(a.Host, a.User, a.Password, db, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if err := c.SetCharset("utf8mb4"); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Q quotes an identifier.
func Q(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// Lit quotes a string literal.
func Lit(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `''`).Replace(s) + "'"
}

func kindOf(dataType string) string {
	switch strings.ToLower(dataType) {
	case "binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "bit", "geometry", "point", "linestring",
		"polygon", "multipoint", "multilinestring", "multipolygon", "geometrycollection", "geomcollection", "vector":
		return "bin"
	case "timestamp":
		return "ts"
	case "json":
		return "json"
	}
	return "plain"
}

// Columns reads the tables' columns, keys and hashes from the server, as they are now.
// With no names, every base table of db (but countersign_log).
func Columns(c *client.Conn, db string, names []string) (map[string]*Table, error) {
	q := "SELECT c.TABLE_NAME, c.COLUMN_NAME, c.DATA_TYPE, c.COLUMN_TYPE, c.COLUMN_KEY, c.EXTRA FROM information_schema.COLUMNS c " +
		"JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_TYPE = 'BASE TABLE' " +
		"WHERE c.TABLE_SCHEMA = " + Lit(db) + " AND c.TABLE_NAME <> 'countersign_log'"
	if len(names) > 0 {
		var ls []string
		for _, n := range names {
			ls = append(ls, Lit(n))
		}
		q += " AND c.TABLE_NAME IN (" + strings.Join(ls, ",") + ")"
	}
	q += " ORDER BY c.TABLE_NAME, c.ORDINAL_POSITION"
	r, err := c.Execute(q)
	if err != nil {
		return nil, err
	}
	out := map[string]*Table{}
	sums := map[string]*strings.Builder{}
	for i := 0; i < r.RowNumber(); i++ {
		tn, _ := r.GetString(i, 0)
		cn, _ := r.GetString(i, 1)
		dt, _ := r.GetString(i, 2)
		ct, _ := r.GetString(i, 3)
		key, _ := r.GetString(i, 4)
		extra, _ := r.GetString(i, 5)
		t := out[tn]
		if t == nil {
			t = &Table{DB: db, Name: tn}
			out[tn] = t
			sums[tn] = &strings.Builder{}
		}
		fmt.Fprintf(sums[tn], "%s\x00%s\x00%s\x00%s\n", cn, ct, key, extra)
		if strings.Contains(strings.ToUpper(extra), "GENERATED") {
			continue // computed from the others: neither captured nor restored
		}
		t.Cols = append(t.Cols, Col{Name: cn, Kind: kindOf(dt)})
		if key == "PRI" {
			t.PK = append(t.PK, cn)
		}
	}
	for tn, t := range out {
		h := md5.Sum([]byte(sums[tn].String()))
		t.Hash = hex.EncodeToString(h[:8])
	}
	return out, nil
}

func capExpr(c Col, alias string) string {
	ref := Q(c.Name)
	if alias != "" {
		ref = alias + "." + ref
	}
	switch c.Kind {
	case "bin":
		return "HEX(" + ref + ")"
	case "ts":
		return "UNIX_TIMESTAMP(" + ref + ")"
	}
	return ref
}

// JSONObject renders a row of t as captured (alias OLD, NEW, or "" for the table itself).
func JSONObject(t *Table, alias string) string {
	var parts []string
	for _, c := range t.Cols {
		parts = append(parts, Lit(c.Name), capExpr(c, alias))
	}
	return "JSON_OBJECT(" + strings.Join(parts, ", ") + ")"
}

func path(name string) string {
	return Lit(`$."` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(name) + `"`)
}

// valueExpr reads column c back from the JSON row in variable v, as its own type.
func valueExpr(c Col, v string) string {
	base := "JSON_EXTRACT(" + v + ", " + path(c.Name) + ")"
	isNull := "JSON_TYPE(" + base + ") = 'NULL'"
	var val string
	switch c.Kind {
	case "bin":
		val = "UNHEX(JSON_UNQUOTE(" + base + "))"
	case "ts":
		val = "FROM_UNIXTIME(JSON_UNQUOTE(" + base + "))"
	case "json":
		val = base
	default:
		val = "JSON_UNQUOTE(" + base + ")"
	}
	return "IF(" + base + " IS NULL OR " + isNull + ", NULL, " + val + ")"
}

func trigName(kind, table string) string {
	n := "cs_" + kind + "_" + table
	if len(n) > 64 {
		h := md5.Sum([]byte(table))
		n = "cs_" + kind + "_" + table[:40] + "_" + hex.EncodeToString(h[:6])
	}
	return n
}

// LogTable is the capture table's definition.
const LogTable = "(seq BIGINT AUTO_INCREMENT PRIMARY KEY, tbl VARCHAR(64) NOT NULL, h CHAR(16) NOT NULL, " +
	"old_row JSON NULL, new_row JSON NULL) ENGINE=InnoDB"

// Sync installs capture in db: the permanent log table that refuses rows, and on every base
// table triggers that match its columns now (made again where they do not). It reports
// the tables whose triggers it (re)made.
func Sync(c *client.Conn, db string) ([]string, error) {
	if _, err := c.Execute("CREATE TABLE IF NOT EXISTS " + Q(db) + ".countersign_log " + LogTable); err != nil {
		return nil, err
	}
	have := map[string]string{} // trigger name -> body
	r, err := c.Execute("SELECT TRIGGER_NAME, ACTION_STATEMENT FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = " + Lit(db) +
		" AND TRIGGER_NAME LIKE 'cs\\_%'")
	if err != nil {
		return nil, err
	}
	for i := 0; i < r.RowNumber(); i++ {
		n, _ := r.GetString(i, 0)
		b, _ := r.GetString(i, 1)
		have[n] = b
	}
	if _, ok := have["cs_guard_countersign_log"]; !ok {
		if _, err := c.Execute("CREATE TRIGGER " + Q(db) + ".cs_guard_countersign_log BEFORE INSERT ON " + Q(db) +
			".countersign_log FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = " +
			Lit("Countersign: this session has no capture table, so its writes cannot be recorded; reconnect through the gateway")); err != nil {
			return nil, err
		}
	}
	tables, err := Columns(c, db, nil)
	if err != nil {
		return nil, err
	}
	var names []string
	for n := range tables {
		names = append(names, n)
	}
	sort.Strings(names)
	var made []string
	for _, n := range names {
		t := tables[n]
		mark := "/*cs:" + t.Hash + "*/"
		redo := false
		for _, k := range []string{"ai", "au", "ad"} {
			if !strings.Contains(have[trigName(k, n)], mark) {
				redo = true
			}
		}
		if !redo {
			continue
		}
		for _, k := range []struct{ kind, event, old, new string }{
			{"ai", "INSERT", "NULL", JSONObject(t, "NEW")},
			{"au", "UPDATE", JSONObject(t, "OLD"), JSONObject(t, "NEW")},
			{"ad", "DELETE", JSONObject(t, "OLD"), "NULL"},
		} {
			name := Q(db) + "." + Q(trigName(k.kind, n))
			body := "IF @countersign_capture = 1 THEN " + mark + " INSERT INTO " + Q(db) + ".countersign_log(tbl, h, old_row, new_row) VALUES (" +
				Lit(n) + ", " + Lit(t.Hash) + ", " + k.old + ", " + k.new + "); END IF"
			if _, err := c.Execute("DROP TRIGGER IF EXISTS " + name); err != nil {
				return made, err
			}
			if _, err := c.Execute("CREATE TRIGGER " + name + " AFTER " + k.event + " ON " + Q(db) + "." + Q(n) + " FOR EACH ROW " + body); err != nil {
				return made, fmt.Errorf("%s.%s: %v", db, n, err)
			}
		}
		made = append(made, n)
	}
	return made, nil
}

// Cascades lists, per table, whether deleting its rows or changing which of its columns
// makes InnoDB change rows elsewhere (foreign key actions do not fire triggers).
type Cascade struct {
	OnDelete bool
	OnUpdate map[string]bool // referenced columns
}

func Cascades(c *client.Conn, db string) (map[string]*Cascade, error) {
	r, err := c.Execute("SELECT rc.REFERENCED_TABLE_NAME, rc.DELETE_RULE, rc.UPDATE_RULE, k.REFERENCED_COLUMN_NAME " +
		"FROM information_schema.REFERENTIAL_CONSTRAINTS rc JOIN information_schema.KEY_COLUMN_USAGE k " +
		"ON k.CONSTRAINT_SCHEMA = rc.CONSTRAINT_SCHEMA AND k.CONSTRAINT_NAME = rc.CONSTRAINT_NAME AND k.TABLE_NAME = rc.TABLE_NAME " +
		"WHERE rc.UNIQUE_CONSTRAINT_SCHEMA = " + Lit(db))
	if err != nil {
		return nil, err
	}
	out := map[string]*Cascade{}
	acts := func(rule string) bool { return rule == "CASCADE" || rule == "SET NULL" || rule == "SET DEFAULT" }
	for i := 0; i < r.RowNumber(); i++ {
		t, _ := r.GetString(i, 0)
		del, _ := r.GetString(i, 1)
		upd, _ := r.GetString(i, 2)
		col, _ := r.GetString(i, 3)
		cs := out[t]
		if cs == nil {
			cs = &Cascade{OnUpdate: map[string]bool{}}
			out[t] = cs
		}
		if acts(del) {
			cs.OnDelete = true
		}
		if acts(upd) {
			cs.OnUpdate[col] = true
		}
	}
	return out, nil
}

// Canon normalizes a JSON row (key order, spacing) so two renderings compare equal.
func Canon(s string) string {
	if s == "" {
		return ""
	}
	var v any
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// Connector reaches the database the gateway is in front of.
type Connector struct {
	tx.Base
	A Addr
}

func New(name string, a Addr) *Connector { return &Connector{Base: tx.Base{ConnName: name}, A: a} }

func (c *Connector) Hidden() bool { return true }

func (c *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	return model.Read, nil, fmt.Errorf("%s: no operations (the MySQL gateway's connector)", c.Name())
}

func keyWhere(t *Table, v string) string {
	var w []string
	for _, k := range t.PK {
		for _, col := range t.Cols {
			if col.Name == k {
				w = append(w, Q(k)+" <=> "+valueExpr(col, v))
			}
		}
	}
	return strings.Join(w, " AND ")
}

func current(conn *client.Conn, t *Table) (string, error) {
	r, err := conn.Execute("SELECT CAST(" + JSONObject(t, "") + " AS CHAR) FROM " + Q(t.DB) + "." + Q(t.Name) +
		" WHERE " + keyWhere(t, "@cs_k") + " FOR UPDATE")
	if err != nil {
		return "", err
	}
	if r.RowNumber() == 0 {
		return "", nil
	}
	s, _ := r.GetString(0, 0)
	return Canon(s), nil
}

// Undo puts every row back as it was, if each is still as the transaction left it.
func (c *Connector) Undo(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	_, err := c.apply(&rec, nil)
	return err
}

func (c *Connector) apply(rec *UndoRecord, pick func(Row) bool) (int, error) {
	conn, err := Dial(c.A, "")
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if _, err := conn.Execute("START TRANSACTION"); err != nil {
		return 0, err
	}
	n := 0
	fail := func(err error) (int, error) {
		_, _ = conn.Execute("ROLLBACK")
		return 0, err
	}
	for i := len(rec.Rows) - 1; i >= 0; i-- {
		row := rec.Rows[i]
		if pick != nil && !pick(row) {
			continue
		}
		t := rec.Tables[row.DB+"."+row.Table]
		if t == nil || len(t.PK) == 0 {
			return fail(fmt.Errorf("%s.%s: no primary key recorded, so the row cannot be found", row.DB, row.Table))
		}
		keyFrom := row.After
		if keyFrom == "" {
			keyFrom = row.Before
		}
		if _, err := conn.Execute("SET @cs_k = CAST(? AS JSON), @cs_v = CAST(? AS JSON)", keyFrom, nullIf(row.Before)); err != nil {
			return fail(err)
		}
		now, err := current(conn, t)
		if err != nil {
			return fail(err)
		}
		switch {
		case now == Canon(row.Before):
			continue
		case now != Canon(row.After):
			return fail(model.Conflict("%s.%s row %s changed after that transaction; refusing to put it back", row.DB, row.Table, keyText(t, keyFrom)))
		}
		var q string
		tbl := Q(t.DB) + "." + Q(t.Name)
		switch {
		case row.Before == "":
			q = "DELETE FROM " + tbl + " WHERE " + keyWhere(t, "@cs_k")
		case row.After == "":
			var cols, vals []string
			for _, col := range t.Cols {
				cols, vals = append(cols, Q(col.Name)), append(vals, valueExpr(col, "@cs_v"))
			}
			q = "INSERT INTO " + tbl + " (" + strings.Join(cols, ", ") + ") SELECT " + strings.Join(vals, ", ")
		default:
			var sets []string
			for _, col := range t.Cols {
				sets = append(sets, Q(col.Name)+" = "+valueExpr(col, "@cs_v"))
			}
			q = "UPDATE " + tbl + " SET " + strings.Join(sets, ", ") + " WHERE " + keyWhere(t, "@cs_k")
		}
		if _, err := conn.Execute(q); err != nil {
			return fail(err)
		}
		n++
	}
	if _, err := conn.Execute("COMMIT"); err != nil {
		return 0, err
	}
	return n, nil
}

func nullIf(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func keyText(t *Table, row string) string {
	m := jsonMap(row)
	var parts []string
	for _, k := range t.PK {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return strings.Join(parts, ",")
}

func jsonMap(s string) map[string]any {
	if s == "" {
		return nil
	}
	var m map[string]any
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	_ = d.Decode(&m)
	return m
}

// DescribeRows lists each changed row.
func (c *Connector) DescribeRows(raw json.RawMessage) ([]vault.Row, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	var out []vault.Row
	for _, r := range rec.Rows {
		vr := vault.Row{Table: r.DB + "." + r.Table, Before: jsonMap(r.Before), After: jsonMap(r.After), Key: map[string]any{}}
		switch {
		case r.Before == "":
			vr.Op = "insert"
		case r.After == "":
			vr.Op = "delete"
		default:
			vr.Op = "update"
		}
		src := vr.After
		if src == nil {
			src = vr.Before
		}
		if t := rec.Tables[r.DB+"."+r.Table]; t != nil {
			for _, k := range t.PK {
				vr.Key[k] = src[k]
			}
		}
		out = append(out, vr)
	}
	return out, nil
}

// ResolveInFlight tells from the rows whether a transaction recorded before its commit
// committed (every row as after) or not (every row as before).
func (c *Connector) ResolveInFlight(raw json.RawMessage) (committed, known bool, err error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return false, false, err
	}
	conn, err := Dial(c.A, "")
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	after, before := 0, 0
	for _, row := range rec.Rows {
		t := rec.Tables[row.DB+"."+row.Table]
		if t == nil || len(t.PK) == 0 {
			return false, false, nil
		}
		k := row.After
		if k == "" {
			k = row.Before
		}
		if _, err := conn.Execute("SET @cs_k = CAST(? AS JSON)", k); err != nil {
			return false, false, err
		}
		r, err := conn.Execute("SELECT CAST(" + JSONObject(t, "") + " AS CHAR) FROM " + Q(t.DB) + "." + Q(t.Name) + " WHERE " + keyWhere(t, "@cs_k"))
		if err != nil {
			return false, false, err
		}
		now := ""
		if r.RowNumber() > 0 {
			s, _ := r.GetString(0, 0)
			now = Canon(s)
		}
		if now == Canon(row.After) {
			after++
		}
		if now == Canon(row.Before) {
			before++
		}
	}
	switch {
	case after == len(rec.Rows) && before == 0:
		return true, true, nil
	case before == len(rec.Rows) && after == 0:
		return false, true, nil
	}
	return false, false, nil
}

// RestoreRows puts back the rows of a recorded transaction in the given tables (db.table
// or table), checking each as Undo does. It returns how many it wrote.
func (c *Connector) RestoreRows(raw json.RawMessage, tables map[string]bool) (int, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return 0, err
	}
	return c.apply(&rec, func(r Row) bool { return len(tables) == 0 || tables[r.DB+"."+r.Table] || tables[r.Table] })
}
