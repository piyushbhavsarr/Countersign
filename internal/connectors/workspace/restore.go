package workspace

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"undolayer/internal/model"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

// File contents go into the vault with the rest of a task's before state, so a deleted or
// overwritten file can be put back even if this machine's backup directory is gone. Each
// file is one row (its identity, size and mode, or its link target); its bytes follow as
// "content" rows of 1 MiB, in order.

const chunk = 1 << 20

// DescribeRows lists the files a task added, changed or deleted, with the bytes of every
// file it changed or deleted (read from the backup taken before the commit).
func (w *FS) DescribeRows(raw json.RawMessage) ([]vault.Row, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	var out []vault.Row
	for _, e := range rec.Entries {
		r := vault.Row{Table: "files", Key: map[string]any{"path": e.Path}}
		switch e.Kind {
		case "added":
			r.Op = "insert"
		case "modified":
			r.Op = "update"
		default:
			r.Op = "delete"
		}
		if e.After != "" {
			r.After = map[string]any{"identity": e.After}
		}
		var content []vault.Row
		if e.Kind != "added" {
			r.Before = map[string]any{"identity": e.Before}
			p := filepath.Join(rec.Backup, e.Path)
			info, err := os.Lstat(p)
			switch {
			case err != nil:
				r.Before["backup_missing"] = true
			case info.Mode()&os.ModeSymlink != 0:
				l, _ := os.Readlink(p)
				r.Before["symlink"] = l
			default:
				r.Before["size"], r.Before["mode"] = info.Size(), strconv.FormatUint(uint64(info.Mode().Perm()), 8)
				f, err := os.Open(p)
				if err != nil {
					return nil, err
				}
				buf := make([]byte, chunk)
				for off := int64(0); ; {
					n, err := io.ReadFull(f, buf)
					if n > 0 {
						content = append(content, vault.Row{Table: "files", Op: "content",
							Key:    map[string]any{"path": e.Path, "offset": off},
							Before: map[string]any{"data": base64.StdEncoding.EncodeToString(buf[:n])}})
						off += int64(n)
					}
					if err == io.EOF || err == io.ErrUnexpectedEOF {
						break
					}
					if err != nil {
						f.Close()
						return nil, err
					}
				}
				f.Close()
			}
		}
		out = append(out, r)
		out = append(out, content...)
	}
	return out, nil
}

type fileSource struct {
	rec  UndoRecord
	rows []vault.Row
}

func (w *FS) restoreSource(t *tx.Tx, src string) (*fileSource, error) {
	if src == "" {
		return nil, errors.New("restore_files needs source_tx: the task whose file changes to put back")
	}
	if src == t.ID {
		return nil, errors.New("a task cannot restore its own changes; roll it back instead")
	}
	crs, err := t.Mgr.ChangedRows(src)
	if err != nil {
		return nil, err
	}
	for _, cr := range crs {
		if cr.Connector != w.Name() || len(cr.Record) == 0 {
			continue
		}
		fs := &fileSource{rows: cr.Rows}
		if err := json.Unmarshal(cr.Record, &fs.rec); err != nil {
			return nil, err
		}
		if fs.rec.Root != w.Root {
			return nil, fmt.Errorf("%s changed another workspace (%s)", src, fs.rec.Root)
		}
		return fs, nil
	}
	return nil, fmt.Errorf("%s changed no files in %s", src, w.Root)
}

func wantPaths(args map[string]any) (map[string]bool, error) {
	out := map[string]bool{}
	switch ps := args["paths"].(type) {
	case nil:
	case []any:
		for _, p := range ps {
			s, ok := p.(string)
			if !ok {
				return nil, errors.New("paths must be a list of paths")
			}
			out[filepath.Clean(s)] = true
		}
	case []string:
		for _, s := range ps {
			out[filepath.Clean(s)] = true
		}
	default:
		return nil, errors.New("paths must be a list of paths")
	}
	return out, nil
}

func (w *FS) classifyRestore(t *tx.Tx, args map[string]any) (model.Effect, model.Facts, error) {
	src, _ := args["source_tx"].(string)
	fs, err := w.restoreSource(t, src)
	if err != nil {
		return "", nil, err
	}
	want, err := wantPaths(args)
	if err != nil {
		return "", nil, err
	}
	var ps []string
	for _, e := range fs.rec.Entries {
		if len(want) == 0 || want[filepath.Clean(e.Path)] {
			ps = append(ps, e.Path)
		}
	}
	sort.Strings(ps)
	return model.Reversible, model.Facts{"paths": ps, "outside_workspace": false, "restore_from": src}, nil
}

// content returns a file's bytes as they were before the source task: from the local
// backup if it is intact, else from the vault's rows. Either way they must hash to the
// identity recorded before the commit.
func (fs *fileSource) content(e UndoEntry) ([]byte, os.FileMode, error) {
	var mode os.FileMode = 0o644
	for _, r := range fs.rows {
		if r.Op != "content" && r.Key["path"] == e.Path && r.Before != nil {
			if m, ok := r.Before["mode"].(string); ok {
				if v, err := strconv.ParseUint(m, 8, 32); err == nil {
					mode = os.FileMode(v)
				}
			}
		}
	}
	p := filepath.Join(fs.rec.Backup, e.Path)
	if b, err := os.ReadFile(p); err == nil {
		if info, err := os.Lstat(p); err == nil {
			mode = info.Mode().Perm()
		}
		if hashOf(b) == e.Before {
			return b, mode, nil
		}
	}
	type part struct {
		off  int64
		data []byte
	}
	var parts []part
	for _, r := range fs.rows {
		if r.Op != "content" || r.Key["path"] != e.Path {
			continue
		}
		off, _ := strconv.ParseInt(fmt.Sprint(r.Key["offset"]), 10, 64)
		d, err := base64.StdEncoding.DecodeString(fmt.Sprint(r.Before["data"]))
		if err != nil {
			return nil, 0, err
		}
		parts = append(parts, part{off, d})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].off < parts[j].off })
	var b []byte
	for _, p := range parts {
		if p.off != int64(len(b)) {
			return nil, 0, fmt.Errorf("%s: the vault holds its content with a gap at byte %d", e.Path, len(b))
		}
		b = append(b, p.data...)
	}
	if hashOf(b) != e.Before {
		return nil, 0, fmt.Errorf("%s: neither the backup nor the vault holds its content as it was", e.Path)
	}
	return b, mode, nil
}

func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (w *FS) stageRestore(t *tx.Tx, a *model.Action) (any, error) {
	src, _ := a.Args["source_tx"].(string)
	onConflict, _ := a.Args["on_conflict"].(string)
	if onConflict == "" {
		onConflict = "fail"
	}
	if onConflict != "fail" && onConflict != "skip" {
		return nil, errors.New(`on_conflict must be "fail" or "skip"`)
	}
	fs, err := w.restoreSource(t, src)
	if err != nil {
		return nil, err
	}
	want, err := wantPaths(a.Args)
	if err != nil {
		return nil, err
	}
	shadow, err := w.Shadow(t)
	if err != nil {
		return nil, err
	}
	st := tx.GetState[State](t, w.Name())
	type step struct {
		e      UndoEntry
		target string
		remove bool
		data   []byte
		mode   os.FileMode
		link   string
	}
	var plan []step
	var conflicts []map[string]any
	already := 0
	for _, e := range fs.rec.Entries {
		if len(want) > 0 && !want[filepath.Clean(e.Path)] {
			continue
		}
		target, ok := w.resolve(e.Path, shadow)
		if !ok {
			return nil, &model.PolicyViolation{Action: a}
		}
		if contains(st.Masked, e.Path) {
			conflicts = append(conflicts, map[string]any{"path": e.Path,
				"reason": "it holds secrets masked from agents; restore it with undo of the whole task"})
			continue
		}
		cur := entry(target)
		switch {
		case cur == e.Before:
			already++
			continue
		case cur != e.After:
			conflicts = append(conflicts, map[string]any{"path": e.Path,
				"reason": "changed since that task; putting it back would overwrite the newer change"})
			continue
		}
		s := step{e: e, target: target}
		switch {
		case e.Kind == "added":
			s.remove = true
		case len(e.Before) > 5 && e.Before[:5] == "link:":
			s.link = e.Before[5:]
		default:
			if s.data, s.mode, err = fs.content(e); err != nil {
				return nil, err
			}
		}
		plan = append(plan, s)
	}
	if len(conflicts) > 0 && onConflict == "fail" {
		b, _ := json.Marshal(conflicts[:min(len(conflicts), 5)])
		return nil, model.Conflict("%d files cannot be put back without overwriting newer changes; nothing was restored "+
			"(on_conflict: \"skip\" restores the others): %s", len(conflicts), b)
	}
	for _, s := range plan {
		switch {
		case s.remove:
			if err := os.Remove(s.target); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
		case s.link != "":
			_ = os.Remove(s.target)
			if err := os.MkdirAll(filepath.Dir(s.target), 0o755); err != nil {
				return nil, err
			}
			if err := os.Symlink(s.link, s.target); err != nil {
				return nil, err
			}
		default:
			if err := os.MkdirAll(filepath.Dir(s.target), 0o755); err != nil {
				return nil, err
			}
			tmp := s.target + ".undolayer-restore"
			if err := os.WriteFile(tmp, s.data, s.mode); err != nil {
				return nil, err
			}
			if err := os.Chmod(tmp, s.mode); err != nil {
				return nil, err
			}
			if err := os.Rename(tmp, s.target); err != nil {
				return nil, err
			}
		}
	}
	if conflicts == nil {
		conflicts = []map[string]any{}
	}
	return map[string]any{"staged": true, "source_tx": src, "files_restored": len(plan),
		"files_already_as_before": already, "conflicts": conflicts}, nil
}
