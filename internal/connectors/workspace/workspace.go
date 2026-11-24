// Package workspace: filesystem + shell connectors on a copy-on-write shadow workspace.
//
// On first use the workspace is cloned (APFS clonefile / reflink / copy) and a manifest
// of content hashes recorded. File operations and shell commands act on the shadow; the
// real workspace is untouched until commit. The shell runs under the kernel sandbox:
// writes only in the shadow and a private temp dir, no network (no DNS either), the real
// $HOME, the real workspace and the runtime's state directory unreadable, and no
// process outlives the command. What a command did is measured by diffing the shadow.
package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/pmezard/go-difflib/difflib"

	"undolayer/internal/egress"
	"undolayer/internal/model"
	"undolayer/internal/sandbox"
	"undolayer/internal/scanner"
	"undolayer/internal/taint"
	"undolayer/internal/tx"
)

type State struct {
	Shadow         string            `json:"shadow"`
	CloneMethod    string            `json:"clone_method"`
	Manifest       map[string]string `json:"manifest"`
	SensitiveFiles []string          `json:"sensitive_files"`
	Pending        *Changes          `json:"pending,omitempty"`
	Masked         []string          `json:"masked,omitempty"` // sensitive files whose values are masked in the shadow
}

type Changes struct {
	Added    []string `json:"added"`
	Modified []string `json:"modified"`
	Deleted  []string `json:"deleted"`
}

func (c Changes) Empty() bool { return len(c.Added)+len(c.Modified)+len(c.Deleted) == 0 }

type UndoEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Before string `json:"before,omitempty"` // content identity before the commit ("" = absent)
	After  string `json:"after,omitempty"`
}

type UndoRecord struct {
	Root    string      `json:"root"`
	Backup  string      `json:"backup"`
	Entries []UndoEntry `json:"entries"`
}

type FS struct {
	tx.Base
	Root, StateDir     string
	Exclude, Sensitive []string
	Visibility         string // "" = detect
	Scanner            bool
	// MaskSensitive replaces the values in provenance-sensitive files inside the shadow, so
	// nothing the agent runs can read, transform or encode them: they are not there.
	MaskSensitive bool
	MaxDiffBytes  int
	MaxScanBytes  int64
}

func NewFS(root, stateDir string) *FS {
	r, _ := filepath.Abs(root)
	if e, err := filepath.EvalSymlinks(r); err == nil {
		r = e
	}
	s, _ := filepath.Abs(stateDir)
	_ = os.MkdirAll(s, 0o700)
	if e, err := filepath.EvalSymlinks(s); err == nil {
		s = e
	}
	return &FS{Base: tx.Base{ConnName: "fs"}, Root: r, StateDir: s, Scanner: true, MaskSensitive: true,
		MaxDiffBytes: 200_000, MaxScanBytes: 1_000_000}
}

func (w *FS) Operations() map[string]tx.OpSchema {
	p := map[string]any{"path": map[string]any{"type": "string", "description": "Path relative to the workspace root"}}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range p {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	return map[string]tx.OpSchema{
		"read":   {Description: "Read a file (sees staged changes).", Properties: p, Required: []string{"path"}},
		"list":   {Description: "List a directory.", Properties: p, Required: []string{"path"}},
		"write":  {Description: "Write a file. Staged in the shadow workspace until commit.", Properties: with(map[string]any{"content": map[string]any{"type": "string"}}), Required: []string{"path", "content"}},
		"delete": {Description: "Delete a file or directory (staged).", Properties: p, Required: []string{"path"}},
		"move": {Description: "Move/rename (staged).", Properties: map[string]any{"src": map[string]any{"type": "string"}, "dst": map[string]any{"type": "string"}},
			Required: []string{"src", "dst"}},
	}
}

// resolve maps a user path onto base; inside=false if it leaves base on the filesystem.
func (w *FS) resolve(rel, base string) (string, bool) {
	var p string
	if filepath.IsAbs(rel) {
		r := rel
		if e, err := filepath.EvalSymlinks(rel); err == nil {
			r = e
		}
		inner, err := filepath.Rel(w.Root, r)
		if err != nil || inner == ".." || strings.HasPrefix(inner, "../") {
			return rel, false
		}
		p = filepath.Join(base, inner)
	} else {
		p = filepath.Join(base, rel)
	}
	if r, err := filepath.Rel(base, p); err != nil || r == ".." || strings.HasPrefix(r, "../") {
		return p, false
	}
	anc := p
	for {
		if _, err := os.Lstat(anc); err == nil || anc == base {
			break
		}
		anc = filepath.Dir(anc)
	}
	ra, err1 := filepath.EvalSymlinks(anc)
	rb, err2 := filepath.EvalSymlinks(base)
	if err1 != nil || err2 != nil {
		return p, false
	}
	if r, err := filepath.Rel(rb, ra); err != nil || r == ".." || strings.HasPrefix(r, "../") {
		return p, false
	}
	return p, true
}

func paths(args map[string]any) []string {
	var out []string
	for _, k := range []string{"path", "src", "dst"} {
		if s, ok := args[k].(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (w *FS) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	ps := paths(args)
	inside := true
	for _, p := range ps {
		if _, ok := w.resolve(p, w.Root); !ok {
			inside = false
		}
	}
	facts := model.Facts{"paths": ps, "outside_workspace": !inside}
	if st := tx.PeekState[State](t, w.Name()); st != nil && st.SensitiveFiles != nil {
		sens := false
		for _, p := range ps {
			for _, s := range st.SensitiveFiles {
				sens = sens || filepath.Clean(p) == s
			}
		}
		facts["touches_sensitive"] = sens
	}
	if op == "read" || op == "list" {
		return model.Read, facts, nil
	}
	return model.Reversible, facts, nil
}

// ---------------------------------------------------------------- shadow

func cloneTree(src, dst string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		if exec.Command("cp", "-c", "-R", "-p", src, dst).Run() == nil {
			return "apfs-clone", nil
		}
	case "linux":
		if exec.Command("cp", "-a", "--reflink=auto", src, dst).Run() == nil {
			return "reflink-auto", nil
		}
	}
	_ = os.RemoveAll(dst)
	return "copy", copyTree(src, dst)
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			return os.Symlink(l, target)
		case info.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		default:
			return copyFile(p, target, info.Mode().Perm())
		}
	})
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copyEntry copies a file or symlink (not following it), via a temp name + rename.
func copyEntry(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".undolayer-tmp")
	_ = os.Remove(tmp)
	if info.Mode()&os.ModeSymlink != 0 {
		l, _ := os.Readlink(src)
		if err := os.Symlink(l, tmp); err != nil {
			return err
		}
	} else if err := copyFile(src, tmp, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func fileHash(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

func (w *FS) excluded(rel string) bool {
	for _, g := range w.Exclude {
		if ok, _ := filepath.Match(g, rel); ok || strings.HasPrefix(rel, strings.TrimSuffix(g, "/*")+"/") {
			return true
		}
	}
	return false
}

func entry(p string) string {
	info, err := os.Lstat(p)
	if err != nil {
		return ""
	}
	if info.Mode()&os.ModeSymlink != 0 {
		l, _ := os.Readlink(p)
		return "link:" + l
	}
	if info.Mode().IsRegular() {
		return fileHash(p)
	}
	return ""
}

func (w *FS) manifest(base string) map[string]string {
	out := map[string]string{}
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == base {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		if w.excluded(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 { // a symlink (even to a directory) is one entry
			out[rel] = entry(p)
			return nil
		}
		if d.Type().IsRegular() {
			out[rel] = fileHash(p)
		}
		return nil
	})
	return out
}

func gitFiles(root string, args ...string) ([]string, bool) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return nil, false
	}
	out, err := exec.Command("git", append([]string{"-C", root, "ls-files", "-z"}, args...)...).Output()
	if err != nil {
		return nil, false
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, filepath.Clean(f))
		}
	}
	return files, true
}

func (w *FS) sensitiveFiles() []string {
	set := map[string]bool{}
	ign, _ := gitFiles(w.Root, "--others", "--ignored", "--exclude-standard")
	for _, f := range ign {
		set[f] = true
	}
	if len(w.Sensitive) > 0 {
		_ = filepath.WalkDir(w.Root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(w.Root, p)
			for _, g := range w.Sensitive {
				a, _ := filepath.Match(g, rel)
				b, _ := filepath.Match(g, d.Name())
				if a || b {
					set[rel] = true
				}
			}
			return nil
		})
	}
	out := []string{}
	for f := range set {
		if !w.excluded(f) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// Shadow returns the transaction's shadow workspace, creating it on first use.
func (w *FS) Shadow(t *tx.Tx) (string, error) {
	st := tx.GetState[State](t, w.Name())
	if st.Shadow == "" {
		shadow := filepath.Join(w.StateDir, "shadow", t.ID, "ws")
		// shared lock: no commit is half-applied while the workspace is copied
		release, err := w.wsLock(false)
		if err != nil {
			return "", err
		}
		m, err := cloneTree(w.Root, shadow)
		release()
		if err != nil {
			return "", err
		}
		// the baseline is exactly what was copied, so a file committed by someone else just
		// after the copy is never mistaken for one this transaction deleted
		st.Shadow, st.CloneMethod, st.Manifest, st.SensitiveFiles = shadow, m, w.manifest(shadow), w.sensitiveFiles()
		if w.MaskSensitive {
			if err := w.mask(t, st); err != nil {
				return "", err
			}
		}
		t.Mgr.Journal(t)
	}
	if info, err := os.Stat(st.Shadow); err != nil || !info.IsDir() {
		return "", model.Conflict("shadow workspace %s is gone (transaction recovered elsewhere?)", st.Shadow)
	}
	return st.Shadow, nil
}

// mask rewrites each sensitive file in the shadow with its sensitive values replaced by
// placeholders (structure, key names and comments stay, so tools still parse it). The
// manifest records the masked content as the baseline, so an untouched masked file is
// not a change; any change to one is refused (it would overwrite the real secrets).
func (w *FS) mask(t *tx.Tx, st *State) error {
	idx := t.Sensitive()
	for _, rel := range st.SensitiveFiles {
		txt, ok := w.readText(rel)
		if !ok {
			continue
		}
		masked, n := idx.Redact(txt)
		if n == 0 {
			continue
		}
		p := filepath.Join(st.Shadow, rel)
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := os.WriteFile(p, []byte(masked.(string)), info.Mode().Perm()); err != nil {
			return err
		}
		st.Manifest[rel] = fileHash(p)
		st.Masked = append(st.Masked, rel)
	}
	return nil
}

func (w *FS) readText(rel string) (string, bool) {
	p := filepath.Join(w.Root, rel)
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > w.MaxScanBytes {
		return "", false
	}
	b, err := os.ReadFile(p)
	if err != nil || !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

func (w *FS) ContributeSensitive(t *tx.Tx, idx *taint.Index) {
	var sens []string
	if st := tx.PeekState[State](t, w.Name()); st != nil && st.SensitiveFiles != nil {
		sens = st.SensitiveFiles
	} else {
		sens = w.sensitiveFiles()
	}
	isSens := map[string]bool{}
	for _, s := range sens {
		isSens[s] = true
	}
	tracked, ok := gitFiles(w.Root)
	if !ok {
		for rel := range w.manifest(w.Root) {
			if !isSens[rel] {
				tracked = append(tracked, rel)
			}
		}
	}
	for _, rel := range tracked {
		if txt, ok := w.readText(rel); ok && !isSens[rel] {
			idx.AddPublic(txt)
		}
	}
	for _, rel := range sens {
		if txt, ok := w.readText(rel); ok {
			idx.AddSource(txt, rel)
		}
	}
	vis := scanner.Visibility(w.Root, w.Visibility)
	switch {
	case !w.Scanner:
		idx.Scanner = "disabled"
	case vis == "public":
		idx.Scanner = "skipped: public repository (committed content is already public)"
	case !scanner.Available():
		idx.Scanner = "unavailable: gitleaks not installed"
	default:
		hits := scanner.ScanDir(w.Root)
		for _, h := range hits {
			rel, _ := filepath.Rel(w.Root, h.File)
			idx.AddFlagged(h.Secret, "gitleaks:"+h.RuleID+":"+rel)
		}
		idx.Scanner = fmt.Sprintf("gitleaks: %d finding(s) in a %s repository", len(hits), vis)
	}
}

// ---------------------------------------------------------------- stage

func (w *FS) Stage(t *tx.Tx, a *model.Action) (any, error) {
	shadow, err := w.Shadow(t)
	if err != nil {
		return nil, err
	}
	str := func(k string) string { s, _ := a.Args[k].(string); return s }
	var p string
	if a.Operation != "move" {
		var ok bool
		if p, ok = w.resolve(str("path"), shadow); !ok {
			return nil, &model.PolicyViolation{Action: a}
		}
	}
	switch a.Operation {
	case "read":
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return map[string]any{"binary": true, "size": len(b)}, nil
		}
		return map[string]any{"content": string(b)}, nil
	case "list":
		ents, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		names := []any{}
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() {
				n += "/"
			}
			names = append(names, n)
		}
		return map[string]any{"entries": names}, nil
	case "write":
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, []byte(str("content")), 0o644); err != nil {
			return nil, err
		}
		return map[string]any{"written": str("path"), "bytes": len(str("content")), "staged": true}, nil
	case "delete":
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			err = os.RemoveAll(p)
		} else {
			err = os.Remove(p)
		}
		return map[string]any{"deleted": str("path"), "staged": true}, err
	case "move":
		s, ok1 := w.resolve(str("src"), shadow)
		d, ok2 := w.resolve(str("dst"), shadow)
		if !ok1 || !ok2 {
			return nil, &model.PolicyViolation{Action: a}
		}
		if err := os.MkdirAll(filepath.Dir(d), 0o755); err != nil {
			return nil, err
		}
		return map[string]any{"moved": []any{str("src"), str("dst")}, "staged": true}, os.Rename(s, d)
	}
	return nil, fmt.Errorf("unknown fs operation %s", a.Operation)
}

// ---------------------------------------------------------------- diff

func (w *FS) changes(t *tx.Tx) (Changes, error) {
	st := tx.PeekState[State](t, w.Name())
	if st == nil || st.Shadow == "" {
		return Changes{}, nil
	}
	if info, err := os.Stat(st.Shadow); err != nil || !info.IsDir() {
		return Changes{}, model.Conflict("shadow workspace %s is gone (transaction recovered elsewhere?)", st.Shadow)
	}
	now := w.manifest(st.Shadow)
	c := Changes{Added: []string{}, Modified: []string{}, Deleted: []string{}}
	for k, v := range now {
		if old, ok := st.Manifest[k]; !ok {
			c.Added = append(c.Added, k)
		} else if old != v {
			c.Modified = append(c.Modified, k)
		}
	}
	for k := range st.Manifest {
		if _, ok := now[k]; !ok {
			c.Deleted = append(c.Deleted, k)
		}
	}
	sort.Strings(c.Added)
	sort.Strings(c.Modified)
	sort.Strings(c.Deleted)
	return c, nil
}

func lines(p string) ([]string, bool) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, true
	}
	if info.Mode()&os.ModeSymlink != 0 {
		l, _ := os.Readlink(p)
		return []string{"-> " + l + "\n"}, true
	}
	b, err := os.ReadFile(p)
	if err != nil || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return nil, false
	}
	return difflib.SplitLines(string(b)), true
}

func (w *FS) Preview(t *tx.Tx) map[string]any {
	c, err := w.changes(t)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	if c.Empty() {
		return nil
	}
	st := tx.GetState[State](t, w.Name())
	diffs := map[string]any{}
	budget := w.MaxDiffBytes
	for _, rel := range append(append([]string{}, c.Modified...), c.Added...) {
		if budget <= 0 {
			diffs[rel] = "(diff truncated)"
			continue
		}
		var a []string
		ok1 := true
		if contains(c.Modified, rel) {
			a, ok1 = lines(filepath.Join(w.Root, rel))
		}
		b, ok2 := lines(filepath.Join(st.Shadow, rel))
		if !ok1 || !ok2 {
			diffs[rel] = "(binary)"
			continue
		}
		d, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{A: a, B: b, FromFile: "a/" + rel, ToFile: "b/" + rel, Context: 3})
		budget -= len(d)
		diffs[rel] = d
	}
	return map[string]any{"root": w.Root, "added": c.Added, "modified": c.Modified, "deleted": c.Deleted, "diffs": diffs}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (w *FS) Totals(t *tx.Tx) map[string]float64 {
	c, _ := w.changes(t)
	st := tx.PeekState[State](t, w.Name())
	// A deleted file whose exact content was added elsewhere was moved, not lost.
	lost := len(c.Deleted)
	if st != nil && st.Shadow != "" && len(c.Deleted) > 0 {
		added := map[string]int{}
		for _, a := range c.Added {
			added[entry(filepath.Join(st.Shadow, a))]++
		}
		for _, d := range c.Deleted {
			if h := st.Manifest[d]; added[h] > 0 {
				added[h]--
				lost--
			}
		}
	}
	return map[string]float64{"files_deleted": float64(lost),
		"files_changed": float64(len(c.Added) + len(c.Modified) + len(c.Deleted))}
}

// ---------------------------------------------------------------- commit

func (w *FS) Prepare(t *tx.Tx) error {
	st := tx.PeekState[State](t, w.Name())
	if st == nil || st.Shadow == "" {
		return nil
	}
	// exclusive from the conflict check to the last file written: nobody else can change,
	// snapshot or commit to the workspace in between
	release, err := w.wsLock(true)
	if err != nil {
		return err
	}
	t.Handles[w.Name()+":lock"] = releaser(release)
	c, err := w.changes(t)
	if err != nil {
		return err
	}
	for _, rel := range append(append([]string{}, c.Modified...), c.Deleted...) {
		if contains(st.Masked, rel) {
			return &model.NotUndoable{Msg: rel + " holds secrets that are masked from the agent; the agent cannot change or delete it " +
				"(edit it yourself, outside the agent)"}
		}
		if entry(filepath.Join(w.Root, rel)) != st.Manifest[rel] {
			return model.Conflict("%s changed in the real workspace since the transaction began", rel)
		}
	}
	for _, rel := range c.Added {
		if _, err := os.Lstat(filepath.Join(w.Root, rel)); err == nil {
			return model.Conflict("%s was created in the real workspace since the transaction began", rel)
		}
	}
	for _, rel := range append(append([]string{}, c.Added...), c.Modified...) {
		if _, ok := w.resolve(rel, w.Root); !ok {
			return model.Conflict("%s would be written through a symlink that leaves the workspace", rel)
		}
	}
	st.Pending = &c
	return nil
}

// Intent backs up every file the commit will overwrite or delete and records, for each
// path, its identity before and after. It runs before anything in the workspace changes.
func (w *FS) Intent(t *tx.Tx) (any, error) {
	st := tx.PeekState[State](t, w.Name())
	if st == nil || st.Shadow == "" {
		return nil, nil
	}
	var c Changes
	if st.Pending != nil {
		c = *st.Pending
	} else {
		var err error
		if c, err = w.changes(t); err != nil {
			return nil, err
		}
	}
	if c.Empty() {
		return nil, nil
	}
	backup := filepath.Join(w.StateDir, "backups", t.ID)
	rec := &UndoRecord{Root: w.Root, Backup: backup}
	for _, rel := range append(append([]string{}, c.Modified...), c.Deleted...) {
		if err := copyEntry(filepath.Join(w.Root, rel), filepath.Join(backup, rel)); err != nil {
			return nil, err
		}
	}
	for _, rel := range c.Added {
		rec.Entries = append(rec.Entries, UndoEntry{Path: rel, Kind: "added", After: entry(filepath.Join(st.Shadow, rel))})
	}
	for _, rel := range c.Modified {
		rec.Entries = append(rec.Entries, UndoEntry{Path: rel, Kind: "modified", Before: st.Manifest[rel],
			After: entry(filepath.Join(st.Shadow, rel))})
	}
	for _, rel := range c.Deleted {
		rec.Entries = append(rec.Entries, UndoEntry{Path: rel, Kind: "deleted", Before: st.Manifest[rel]})
	}
	return rec, nil
}

// UndoInFlight puts the workspace back as it was before a commit that may have been cut
// short: each path is reverted if it holds its after-state, left if it still holds its
// before-state, and anything else is a conflict. Every path is checked before any is written.
func (w *FS) UndoInFlight(raw json.RawMessage) error {
	release, err := w.wsLock(true)
	if err != nil {
		return err
	}
	defer release()
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	type step struct {
		e       UndoEntry
		restore bool // copy the backup back
		remove  bool
	}
	var plan []step
	for _, e := range rec.Entries {
		p := filepath.Join(rec.Root, e.Path)
		cur := entry(p)
		switch e.Kind {
		case "added":
			switch cur {
			case "":
			case e.After:
				plan = append(plan, step{e: e, remove: true})
			default:
				return model.Conflict("%s is neither what the commit wrote nor absent; refusing to touch it", e.Path)
			}
		case "modified":
			switch cur {
			case e.Before:
			case e.After:
				plan = append(plan, step{e: e, restore: true})
			default:
				return model.Conflict("%s is neither its old nor its committed content; refusing to touch it", e.Path)
			}
		case "deleted":
			switch cur {
			case e.Before:
			case "":
				plan = append(plan, step{e: e, restore: true})
			default:
				return model.Conflict("%s was re-created with other content; refusing to touch it", e.Path)
			}
		}
	}
	for i := len(plan) - 1; i >= 0; i-- {
		st := plan[i]
		p := filepath.Join(rec.Root, st.e.Path)
		if st.remove {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return err
			}
			prune(p, rec.Root)
			continue
		}
		if err := copyEntry(filepath.Join(rec.Backup, st.e.Path), p); err != nil {
			return err
		}
	}
	return nil
}

func (w *FS) Commit(t *tx.Tx) (any, error) {
	defer w.unlock(t)
	st := tx.PeekState[State](t, w.Name())
	if st == nil || st.Shadow == "" {
		return nil, nil
	}
	var c Changes
	if st.Pending != nil {
		c = *st.Pending
		st.Pending = nil
	} else {
		var err error
		if c, err = w.changes(t); err != nil {
			return nil, err
		}
	}
	backup := filepath.Join(w.StateDir, "backups", t.ID)
	rec := &UndoRecord{Root: w.Root, Backup: backup}
	for _, rel := range append(append([]string{}, c.Modified...), c.Deleted...) {
		if err := copyEntry(filepath.Join(w.Root, rel), filepath.Join(backup, rel)); err != nil {
			return nil, err
		}
	}
	for _, rel := range append(append([]string{}, c.Added...), c.Modified...) {
		dst := filepath.Join(w.Root, rel)
		if err := copyEntry(filepath.Join(st.Shadow, rel), dst); err != nil {
			return nil, err
		}
		kind := "modified"
		if contains(c.Added, rel) {
			kind = "added"
		}
		rec.Entries = append(rec.Entries, UndoEntry{Path: rel, Kind: kind, After: entry(dst)})
	}
	for _, rel := range c.Deleted {
		if err := os.Remove(filepath.Join(w.Root, rel)); err != nil {
			return nil, err
		}
		rec.Entries = append(rec.Entries, UndoEntry{Path: rel, Kind: "deleted"})
		prune(filepath.Join(w.Root, rel), w.Root)
	}
	_ = os.RemoveAll(filepath.Dir(st.Shadow))
	if len(rec.Entries) == 0 {
		return nil, nil
	}
	return rec, nil
}

func (w *FS) Rollback(t *tx.Tx) error {
	w.unlock(t)
	if st := tx.PeekState[State](t, w.Name()); st != nil && st.Shadow != "" {
		return os.RemoveAll(filepath.Dir(st.Shadow))
	}
	return nil
}

func (w *FS) Recover(t *tx.Tx) error { return w.Rollback(t) }

func (w *FS) Undo(raw json.RawMessage) error {
	release, err := w.wsLock(true)
	if err != nil {
		return err
	}
	defer release()
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	for _, e := range rec.Entries {
		p := filepath.Join(rec.Root, e.Path)
		_, err := os.Lstat(p)
		exists := err == nil
		if (e.Kind == "added" || e.Kind == "modified") && exists && entry(p) != e.After {
			return model.Conflict("%s changed after commit; refusing to overwrite", e.Path)
		}
		if e.Kind == "deleted" && exists {
			return model.Conflict("%s was recreated after commit; refusing to overwrite", e.Path)
		}
	}
	for i := len(rec.Entries) - 1; i >= 0; i-- {
		e := rec.Entries[i]
		p := filepath.Join(rec.Root, e.Path)
		if e.Kind == "added" {
			_ = os.Remove(p)
			prune(p, rec.Root)
			continue
		}
		if err := copyEntry(filepath.Join(rec.Backup, e.Path), p); err != nil {
			return err
		}
	}
	return nil
}

func prune(p, root string) {
	for d := filepath.Dir(p); d != root && strings.HasPrefix(d, root); d = filepath.Dir(d) {
		ents, err := os.ReadDir(d)
		if err != nil || len(ents) > 0 {
			return
		}
		_ = os.Remove(d)
	}
}

// ====================================================================== shell

var ErrSandboxUnavailable = errors.New(sandbox.ErrUnavailable.Error() + ". Install bubblewrap, run inside gVisor/Firecracker, " +
	"or set sandbox = false to accept unconfined commands (each one will then need approval)")

type Shell struct {
	tx.Base
	FS           *FS
	Timeout      time.Duration
	AllowNetwork bool
	ReadAllow    []string
	DenyRead     []string
	EnvPass      []string
	// AllowHosts: hosts commands may read from, through the egress proxy. Only methods HTTP
	// defines as safe pass (HTTPS is inspected with a private CA only the sandbox trusts),
	// so `kubectl get` or `terraform plan` work while anything that modifies is refused
	// before it leaves the machine. Empty (the default) means no network at all.
	AllowHosts []string
	// Resolve overrides where the proxy dials (tests only).
	Resolve func(hostport string) string
	backend string

	pxOnce  sync.Once
	pxErr   error
	px      *egress.Proxy
	pxPort  int
	pxSock  string
	pxEnv   []string
	pxAudit func(egress.Decision)
}

// NewShell refuses to exist without a sandbox unless sandbox=false is explicit.
func NewShell(fsc *FS, useSandbox bool) (*Shell, error) {
	s := &Shell{Base: tx.Base{ConnName: "shell"}, FS: fsc, Timeout: 300 * time.Second,
		EnvPass: []string{"PATH", "LANG", "LC_ALL", "TERM"}}
	if useSandbox {
		s.backend = sandbox.Backend()
		if s.backend == "" {
			return nil, ErrSandboxUnavailable
		}
	}
	return s, nil
}

func (s *Shell) Operations() map[string]tx.OpSchema {
	return map[string]tx.OpSchema{"run": {Description: "Run a shell command in the staged (shadow) workspace. File changes are staged " +
		"until commit. No network; files outside the workspace are not readable.",
		Properties: map[string]any{"command": map[string]any{"type": "string"}, "timeout": map[string]any{"type": "integer"}},
		Required:   []string{"command"}}}
}

func (s *Shell) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	cmd, _ := args["command"].(string)
	return model.Reversible, model.Facts{"command": cmd, "sandboxed": s.backend != "", "network": s.AllowNetwork,
		"read_hosts": s.AllowHosts}, nil
}

// proxy starts the shell's egress proxy once (reads only, listed hosts only).
func (s *Shell) proxy() error {
	s.pxOnce.Do(func() {
		ca, err := egress.LoadOrCreateCA(s.FS.StateDir)
		if err != nil {
			s.pxErr = err
			return
		}
		bundle := filepath.Join(s.FS.StateDir, "egress-ca-bundle.pem")
		if err := ca.Bundle(bundle); err != nil {
			s.pxErr = err
			return
		}
		s.px = &egress.Proxy{Allow: s.AllowHosts, SafeOnly: true, CA: ca, Resolve: s.Resolve,
			OnDecision: func(d egress.Decision) {
				if s.pxAudit != nil {
					s.pxAudit(d)
				}
			}}
		dir, err := os.MkdirTemp("/tmp", "ul-sh-")
		if err != nil {
			s.pxErr = err
			return
		}
		if runtime.GOOS == "linux" {
			s.pxSock = filepath.Join(dir, "egress.sock")
			l, err := egress.ListenUnix(s.pxSock)
			if err != nil {
				s.pxErr = err
				return
			}
			go s.px.Serve(l)
			s.pxPort = 18081
		} else {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				s.pxErr = err
				return
			}
			go s.px.Serve(l)
			s.pxPort = l.Addr().(*net.TCPAddr).Port
		}
		u := fmt.Sprintf("http://127.0.0.1:%d", s.pxPort)
		s.pxEnv = append([]string{"HTTP_PROXY=" + u, "HTTPS_PROXY=" + u, "http_proxy=" + u, "https_proxy=" + u, "NO_PROXY=", "no_proxy="},
			egress.CAEnv(bundle)...)
	})
	return s.pxErr
}

func (s *Shell) hidden() []string {
	home, _ := os.UserHomeDir()
	if h := os.Getenv("HOME"); h != "" {
		home = h
	}
	return append([]string{home, s.FS.StateDir, s.FS.Root}, s.DenyRead...)
}

func (s *Shell) Stage(t *tx.Tx, a *model.Action) (any, error) {
	shadow, err := s.FS.Shadow(t)
	if err != nil {
		return nil, err
	}
	cmdline, _ := a.Args["command"].(string)
	priv := filepath.Join(filepath.Dir(shadow), "tmp")
	_ = os.MkdirAll(priv, 0o700)
	env := []string{"HOME=" + shadow, "TMPDIR=" + priv, "UNDOLAYER_TX=" + t.ID}
	for _, k := range s.EnvPass {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	argv := []string{"/bin/sh", "-c", cmdline}
	if s.backend != "" {
		spec := sandbox.Spec{Write: []string{shadow, priv}, Hide: s.hidden(), ReadAllow: s.ReadAllow, Network: "none", Workdir: shadow}
		switch {
		case s.AllowNetwork:
			spec.Network = "full"
		case len(s.AllowHosts) > 0:
			s.pxAudit = func(d egress.Decision) {
				_ = t.Mgr.Audit.Record("shell_egress", map[string]any{"tx": t.ID, "host": d.Host, "method": d.Method, "allowed": d.Allowed})
			}
			if err := s.proxy(); err != nil {
				return nil, err
			}
			spec.Network, spec.ProxyPort = "proxy", s.pxPort
			if s.pxSock != "" {
				self, _ := os.Executable()
				spec.UnixSockets = []string{s.pxSock}
				spec.ReadAllow = append(spec.ReadAllow, filepath.Dir(s.pxSock))
				spec.LinuxInit = []string{self, "__netinit", "--proxy-sock", s.pxSock, "--port", fmt.Sprint(s.pxPort)}
			}
			env = append(env, s.pxEnv...)
		}
		argv, err = sandbox.Command(spec, argv)
		if err != nil {
			return nil, err
		}
	}
	timeout := s.Timeout
	if n, ok := model.Num(a.Args["timeout"]); ok && time.Duration(n)*time.Second < timeout && n > 0 {
		timeout = time.Duration(n) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.Command(argv[0], argv[1:]...)
	c.Dir, c.Env = shadow, env
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	timedOut := false
	select {
	case <-done:
	case <-ctx.Done():
		timedOut = true
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		<-done
	}
	_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL) // nothing the command started may outlive it
	tail := func(b bytes.Buffer) string {
		s := b.String()
		if len(s) > 20000 {
			return s[len(s)-20000:]
		}
		return s
	}
	res := map[string]any{"timed_out": timedOut, "stdout": tail(out), "stderr": tail(errb), "staged": true,
		"sandbox": map[bool]string{true: s.backend, false: "none"}[s.backend != ""]}
	if timedOut {
		res["exit_code"] = nil
	} else {
		res["exit_code"] = c.ProcessState.ExitCode()
	}
	return res, nil
}

// StagedPaths: every path this task has added, changed or deleted.
func (w *FS) StagedPaths(t *tx.Tx) []string {
	c, err := w.changes(t)
	if err != nil {
		return nil
	}
	return append(append(append([]string{}, c.Added...), c.Modified...), c.Deleted...)
}

// wsLock is a reader-writer lock on the workspace (flock: shared for snapshots, exclusive
// for commits and undo), shared by every gateway using this state directory. The kernel
// releases it if the holder dies.
func (w *FS) wsLock(exclusive bool) (func(), error) {
	dir := filepath.Join(w.StateDir, "locks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte(w.Root))
	f, err := os.OpenFile(filepath.Join(dir, "workspace-"+hex.EncodeToString(h[:8])+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			f.Close()
		})
	}, nil
}

type releaser func()

func (w *FS) unlock(t *tx.Tx) {
	if r, ok := t.Handles[w.Name()+":lock"].(releaser); ok {
		r()
		delete(t.Handles, w.Name()+":lock")
	}
}

// NodeLocal: the workspace, its shadows and backups exist only on this node.
func (*FS) NodeLocal() bool { return true }

// NodeLocal: the sandboxed shell runs against this node's workspace.
func (*Shell) NodeLocal() bool { return true }

// Contained: file operations work on the shadow copy until commit.
func (*FS) Contained(string) bool { return true }

// Contained: commands run in the sandbox against the shadow; their network is reads only.
func (*Shell) Contained(string) bool { return true }
