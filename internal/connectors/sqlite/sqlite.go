// Package sqlite: the database engine itself classifies, captures and undoes.
//
// Nothing here parses SQL. A statement is compiled with EXPLAIN under SQLite's
// authorizer, which reports every table it would read, write, create, drop or alter
// (including inside CTEs, sub-queries and trigger bodies), transaction control, ATTACH
// and PRAGMA assignments. Temporary triggers (private to the agent's connection) log
// the exact old/new image of every row any statement touches: direct writes, FK
// cascades, user triggers, and the rows INSERT OR REPLACE deletes (recursive_triggers
// is on). Schema changes are measured by diffing the catalog; a statement that drops
// data is rewound, the data saved, and re-run, so policy sees exact losses.
//
// All statements run in one held transaction; each in its own savepoint, so one that
// policy rejects after seeing its effect is discarded alone. Undo after commit restores
// every touched row (and the schema) to its recorded original, verifying first that
// nothing changed since and refusing if any row outside that set would change.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	sqlite3 "github.com/mattn/go-sqlite3"

	"undolayer/internal/model"
)

const prefix = "__ul_"

// SQLite authorizer action codes (C API, stable).
var actionNames = map[int]string{1: "CREATE_INDEX", 2: "CREATE_TABLE", 3: "CREATE_TEMP_INDEX", 4: "CREATE_TEMP_TABLE",
	5: "CREATE_TEMP_TRIGGER", 6: "CREATE_TEMP_VIEW", 7: "CREATE_TRIGGER", 8: "CREATE_VIEW", 9: "DELETE", 10: "DROP_INDEX",
	11: "DROP_TABLE", 12: "DROP_TEMP_INDEX", 13: "DROP_TEMP_TABLE", 14: "DROP_TEMP_TRIGGER", 15: "DROP_TEMP_VIEW",
	16: "DROP_TRIGGER", 17: "DROP_VIEW", 18: "INSERT", 19: "PRAGMA", 20: "READ", 21: "SELECT", 22: "TRANSACTION",
	23: "UPDATE", 24: "ATTACH", 25: "DETACH", 26: "ALTER_TABLE", 27: "REINDEX", 28: "ANALYZE", 29: "CREATE_VTABLE",
	30: "DROP_VTABLE", 31: "FUNCTION", 32: "SAVEPOINT", 33: "RECURSIVE"}

var catalogTables = map[string]bool{"sqlite_master": true, "sqlite_schema": true, "sqlite_temp_master": true, "sqlite_temp_schema": true}

type authEntry struct{ Name, A1, A2, DB string }

// guard is the authorizer installed on a connection for its whole life.
type guard struct {
	internal atomic.Int32
	logging  atomic.Bool
	log      []authEntry
}

func (g *guard) cb(op int, a1, a2, db string) int {
	if g.internal.Load() > 0 {
		return sqlite3.SQLITE_OK
	}
	name := actionNames[op]
	if g.logging.Load() {
		g.log = append(g.log, authEntry{name, a1, a2, db})
		return sqlite3.SQLITE_OK
	}
	switch name {
	case "TRANSACTION", "SAVEPOINT", "ATTACH", "DETACH":
		return sqlite3.SQLITE_DENY
	case "PRAGMA":
		if a2 != "" {
			return sqlite3.SQLITE_DENY
		}
	}
	return sqlite3.SQLITE_OK
}

func analyze(log []authEntry) model.Facts {
	writes := map[string]map[string]bool{}
	schema, control, altered := map[string]bool{}, map[string]bool{}, map[string]bool{}
	pragma := []string{}
	for _, e := range log {
		switch {
		case e.Name == "INSERT" || e.Name == "UPDATE" || e.Name == "DELETE":
			if catalogTables[e.A1] || e.DB == "temp" {
				continue
			}
			k := strings.ToLower(e.Name)
			if writes[k] == nil {
				writes[k] = map[string]bool{}
			}
			writes[k][e.A1] = true
		case strings.HasPrefix(e.Name, "CREATE_") || strings.HasPrefix(e.Name, "DROP_") || e.Name == "ALTER_TABLE" ||
			e.Name == "REINDEX" || e.Name == "ANALYZE":
			if !strings.Contains(e.Name, "TEMP") {
				schema[strings.ToLower(e.Name)] = true
			}
			if e.Name == "ALTER_TABLE" && e.A1 != "temp" {
				altered[e.A2] = true
			}
		case e.Name == "TRANSACTION" || e.Name == "SAVEPOINT" || e.Name == "ATTACH" || e.Name == "DETACH":
			control[strings.ToLower(e.Name)] = true
		case e.Name == "PRAGMA" && e.A2 != "":
			pragma = append(pragma, e.A1+"="+e.A2)
		}
	}
	tables := map[string]bool{}
	wf := map[string]any{}
	for k, ts := range writes {
		l := []string{}
		for t := range ts {
			l = append(l, t)
			tables[t] = true
		}
		sort.Strings(l)
		wf[k] = l
	}
	sorted := func(m map[string]bool) []string {
		out := []string{}
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	f := model.Facts{"writes": wf, "tables_written": sorted(tables), "schema_ops": sorted(schema),
		"transaction_control": control["transaction"] || control["savepoint"], "attach": control["attach"] || control["detach"],
		"pragma_set": pragma, "altered_tables": sorted(altered)}
	f["is_write"] = len(tables) > 0 || len(schema) > 0 || len(control) > 0 || len(pragma) > 0
	f["destroys_schema"] = schema["drop_table"] || schema["drop_vtable"]
	return f
}

// ---------------------------------------------------------------- live connection

type live struct {
	db    *sql.DB
	c     *sql.Conn
	g     *guard
	ctx   context.Context
	cap   *capture
	saves []string
}

func (l *live) internal(fn func() error) error {
	l.g.internal.Add(1)
	defer l.g.internal.Add(-1)
	return fn()
}

func (l *live) exec(s string, args ...any) error {
	_, err := l.c.ExecContext(l.ctx, s, args...)
	return err
}

func (l *live) iexec(s string, args ...any) error {
	return l.internal(func() error { return l.exec(s, args...) })
}

func (l *live) query(s string, args ...any) ([][]Val, error) { return query(l.ctx, l.c, s, args...) }

func (l *live) iquery(s string, args ...any) (out [][]Val, err error) {
	err = l.internal(func() error { out, err = l.query(s, args...); return err })
	return
}

func (l *live) close() { _ = l.c.Close(); _ = l.db.Close() }

func open(dsn string, foreignKeys bool) (*live, error) {
	db, err := sql.Open("sqlite3", "file:"+dsn+"?_busy_timeout=10000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	c, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	l := &live{db: db, c: c, g: &guard{}, ctx: ctx}
	if err := c.Raw(func(dc any) error {
		dc.(*sqlite3.SQLiteConn).RegisterAuthorizer(l.g.cb)
		return nil
	}); err != nil {
		l.close()
		return nil, err
	}
	fk := "OFF"
	if foreignKeys {
		fk = "ON"
	}
	for _, s := range []string{"PRAGMA foreign_keys=" + fk, "PRAGMA recursive_triggers=ON", "BEGIN IMMEDIATE"} {
		if err := l.iexec(s); err != nil {
			l.close()
			return nil, err
		}
	}
	l.cap = &capture{l: l, version: -1, logs: map[string]string{}}
	if err := l.cap.install(); err != nil {
		l.close()
		return nil, err
	}
	return l, nil
}

// ---------------------------------------------------------------- capture

type capture struct {
	l          *live
	version    int64
	meta       map[string]*Meta
	logs       map[string]string
	uncaptured map[string]bool
	snap       *Snapshot
}

func (c *capture) schemaVersion() int64 {
	r, err := c.l.iquery("PRAGMA main.schema_version")
	if err != nil || len(r) == 0 {
		return -2
	}
	return r[0][0].I
}

func (c *capture) uninstall() error {
	rows, err := c.l.iquery("SELECT name FROM temp.sqlite_master WHERE type='trigger' AND name LIKE ?", prefix+"%")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := c.l.iexec("DROP TRIGGER temp." + q(r[0].S)); err != nil {
			return err
		}
	}
	c.version = -1
	return nil
}

func (c *capture) install() error {
	if v := c.schemaVersion(); v == c.version {
		return nil
	}
	if err := c.uninstall(); err != nil {
		return err
	}
	return c.l.internal(func() error {
		if err := c.l.exec("CREATE TEMP TABLE IF NOT EXISTS " + prefix + "dirty(t TEXT PRIMARY KEY)"); err != nil {
			return err
		}
		snap, err := snapshot(c.l.ctx, c.l.c)
		if err != nil {
			return err
		}
		c.snap, c.meta, c.uncaptured = snap, map[string]*Meta{}, map[string]bool{}
		names := []string{}
		for _, o := range snap.Objects {
			if o.Type == "table" {
				names = append(names, o.Name)
			}
		}
		sort.Strings(names)
		for i, name := range names {
			if strings.HasPrefix(strings.ToUpper(snap.Objects["table:"+name].SQL), "CREATE VIRTUAL") {
				c.uncaptured[name] = true
				continue
			}
			m := tableMeta(c.l.ctx, c.l.c, name, snap.Columns[name])
			c.meta[name] = m
			logT, ok := c.logs[name]
			if !ok {
				logT = fmt.Sprintf("%slog%d", prefix, len(c.logs))
				c.logs[name] = logT
			}
			if err := c.l.exec("DROP TABLE IF EXISTS temp." + q(logT)); err != nil {
				return err
			}
			cols := []string{"op", "side", "k"}
			for j := range m.Cols {
				cols = append(cols, fmt.Sprintf("c%d", j))
			}
			if err := c.l.exec("CREATE TEMP TABLE " + q(logT) + "(" + strings.Join(cols, ", ") + ")"); err != nil {
				return err
			}
			for _, ow := range [][2]string{{"I", "INSERT"}, {"D", "DELETE"}, {"U", "UPDATE"}} {
				sides := map[string][]string{"I": {"new"}, "D": {"old"}, "U": {"old", "new"}}[ow[0]]
				var ins []string
				for _, side := range sides {
					ref := strings.ToUpper(side)
					vals := []string{"'" + ow[0] + "'", "'" + side + "'"}
					if m.Rowid {
						vals = append(vals, ref+".rowid")
					} else {
						vals = append(vals, "NULL")
					}
					for _, col := range m.Cols {
						vals = append(vals, ref+"."+q(col))
					}
					ins = append(ins, "INSERT INTO temp."+q(logT)+" VALUES ("+strings.Join(vals, ", ")+");")
				}
				tn, _ := json.Marshal(name)
				stmt := fmt.Sprintf("CREATE TEMP TRIGGER %s AFTER %s ON main.%s BEGIN INSERT OR IGNORE INTO temp.%sdirty VALUES (%s); %s END",
					q(fmt.Sprintf("%st%d%s", prefix, i, ow[0])), ow[1], q(name), prefix, strings.ReplaceAll(string(tn), `"`, "'"),
					strings.Join(ins, " "))
				if err := c.l.exec(stmt); err != nil {
					return err
				}
			}
		}
		c.version = c.schemaVersionRaw()
		return nil
	})
}

func (c *capture) schemaVersionRaw() int64 {
	r, err := c.l.query("PRAGMA main.schema_version")
	if err != nil || len(r) == 0 {
		return -2
	}
	return r[0][0].I
}

func (c *capture) keyOf(m *Meta, k Val, row []Val) []Val {
	if m.Rowid {
		return []Val{k}
	}
	out := []Val{}
	for _, p := range m.Key {
		for i, col := range m.Cols {
			if col == p {
				out = append(out, row[i])
			}
		}
	}
	return out
}

// drain returns the row events since the last drain.
func (c *capture) drain() ([]Event, error) {
	var events []Event
	err := c.l.internal(func() error {
		dirty, err := c.l.query("SELECT t FROM temp." + prefix + "dirty")
		if err != nil {
			return err
		}
		for _, d := range dirty {
			t := d[0].S
			m, logT := c.meta[t], c.logs[t]
			if m == nil || logT == "" {
				continue
			}
			rows, err := c.l.query("SELECT * FROM temp." + q(logT) + " ORDER BY rowid")
			if err != nil {
				return err
			}
			var pending *Event
			for _, r := range rows {
				op, side, k, vals := r[0].S, r[1].S, r[2], r[3:]
				row := append([]Val{}, vals...)
				key := c.keyOf(m, k, row)
				switch {
				case op == "U" && side == "old":
					pending = &Event{T: t, Op: "U", KO: key, Old: row}
				case op == "U":
					pending.KN, pending.New = key, row
					events = append(events, *pending)
				case op == "I":
					events = append(events, Event{T: t, Op: "I", KN: key, New: row})
				default:
					events = append(events, Event{T: t, Op: "D", KO: key, Old: row})
				}
			}
			if err := c.l.exec("DELETE FROM temp." + q(logT)); err != nil {
				return err
			}
		}
		return c.l.exec("DELETE FROM temp." + prefix + "dirty")
	})
	return events, err
}

// CloseForCrash drops the connection without rolling back, as process death would; the
// database then discards the held transaction itself.
func (l *live) CloseForCrash() { l.close() }
