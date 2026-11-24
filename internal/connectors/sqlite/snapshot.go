package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	sqlite3 "github.com/mattn/go-sqlite3"

	"undolayer/internal/model"
	"undolayer/internal/tx"
)

// Snapshot staging. Each task works on its own copy of the database, taken with SQLite's
// backup API (page for page, so rowids are exactly the original's) under a read lock, so
// it is a consistent picture and other writers are never blocked. At commit, the task's
// statements are run again on the real database inside one short write transaction, with
// the same row capture; the result is kept only if every row event and the final schema
// are exactly what the task staged and previewed. If anyone changed what the task read
// or wrote in the meantime the replay comes out different, and nothing is written.

func (s *Connector) snapshotStaging() bool { return s.Staging != "lock" }

func (s *Connector) snapshotDir() string {
	if s.SnapshotDir != "" {
		return s.SnapshotDir
	}
	return filepath.Join(os.TempDir(), "undolayer-sqlite")
}

func (s *Connector) snapshot(txID string) (string, error) {
	dir := s.snapshotDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, txID+".db")
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		_ = os.Remove(dst + suffix)
	}
	ctx := context.Background()
	src, err := sql.Open("sqlite3", "file:"+s.DSN+"?_busy_timeout=10000")
	if err != nil {
		return "", err
	}
	defer src.Close()
	out, err := sql.Open("sqlite3", "file:"+dst)
	if err != nil {
		return "", err
	}
	defer out.Close()
	sc, err := src.Conn(ctx)
	if err != nil {
		return "", err
	}
	defer sc.Close()
	dc, err := out.Conn(ctx)
	if err != nil {
		return "", err
	}
	defer dc.Close()
	err = dc.Raw(func(d any) error {
		return sc.Raw(func(srcRaw any) error {
			b, err := d.(*sqlite3.SQLiteConn).Backup("main", srcRaw.(*sqlite3.SQLiteConn), "main")
			if err != nil {
				return err
			}
			for {
				done, err := b.Step(-1) // the whole database in one step: one consistent read
				if err != nil {
					_ = b.Finish()
					return err
				}
				if done {
					break
				}
			}
			return b.Finish()
		})
	})
	if err != nil {
		return "", fmt.Errorf("snapshot of %s: %v", s.DSN, err)
	}
	return dst, os.Chmod(dst, 0o600)
}

func removeSnapshot(p string) {
	if p == "" {
		return
	}
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		_ = os.Remove(p + suffix)
	}
}

// replay runs the staged statements on the real database (held by r, in BEGIN IMMEDIATE)
// and checks each one produced exactly the staged row events.
func (s *Connector) replay(t *tx.Tx, r *live, changes []*Change) error {
	args := map[string]map[string]any{}
	for _, a := range t.Actions {
		if a.Connector == s.Name() {
			args[a.ID] = a.Args
		}
	}
	for _, ch := range changes {
		if err := r.cap.install(); err != nil {
			return err
		}
		if len(ch.Schema) > 0 { // DDL runs without the capture triggers, as it was staged
			if err := r.cap.uninstall(); err != nil {
				return err
			}
		}
		var ps []any
		if a, ok := args[ch.ActionID]; ok && a["sql"] == ch.SQL {
			ps = params(a)
		}
		rows, err := r.c.QueryContext(r.ctx, ch.SQL, ps...)
		if err != nil {
			return model.Conflict("replaying %q on the real database failed (%v): it changed since this task's snapshot", short(ch.SQL), err)
		}
		_, err = scanAll(rows)
		if err != nil {
			return model.Conflict("replaying %q on the real database failed (%v)", short(ch.SQL), err)
		}
		got, err := r.cap.drain()
		if err != nil {
			return err
		}
		if !sameEvents(ch.Events, got) {
			return model.Conflict("the database changed since this task's snapshot: %q now changes other rows than "+
				"the ones previewed; nothing was written (run the task again to see the current data)", short(ch.SQL))
		}
	}
	return nil
}

func sameEvents(a, b []Event) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.T != y.T || x.Op != y.Op || !RowEqual(x.KO, y.KO) || !RowEqual(x.KN, y.KN) ||
			!RowEqual(x.Old, y.Old) || !RowEqual(x.New, y.New) {
			return false
		}
	}
	return true
}

func short(q string) string {
	if len(q) > 80 {
		return q[:80] + "…"
	}
	return q
}

// commitSnapshot commits a snapshot-staged task: replay on the real database, verify,
// then COMMIT. finalSig is the staged copy's schema signature.
func (s *Connector) commitSnapshot(t *tx.Tx, st *State, finalSig string) error {
	r, err := open(s.DSN, s.ForeignKeys) // BEGIN IMMEDIATE: held only for the replay
	if err != nil {
		return err
	}
	defer r.close()
	if err := s.replay(t, r, st.Changes); err != nil {
		_ = r.iexec("ROLLBACK")
		return err
	}
	var sig string
	if err := r.internal(func() error { sig, err = signature(r.ctx, r.c, true); return err }); err != nil {
		_ = r.iexec("ROLLBACK")
		return err
	}
	if sig != finalSig {
		_ = r.iexec("ROLLBACK")
		return model.Conflict("the database's schema changed since this task's snapshot; nothing was written")
	}
	if err := r.cap.uninstall(); err != nil {
		_ = r.iexec("ROLLBACK")
		return err
	}
	return r.iexec("COMMIT")
}
