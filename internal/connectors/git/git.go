// Package git: pushes go to a staging ref on the remote; commit fast-forwards the target
// branch to exactly the staged SHA (never force); undo moves it back with
// --force-with-lease only if nobody pushed on top; rollback deletes the staging ref.
package git

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"undolayer/internal/connectors/workspace"
	"undolayer/internal/model"
	"undolayer/internal/scanner"
	"undolayer/internal/tx"
)

type Push struct {
	URL, Branch, SHA, Staging, Base string
}

type State struct {
	Pushes []*Push `json:"pushes"`
}

type UndoRecord struct {
	Pushes []Push `json:"pushes"`
}

type Connector struct {
	tx.Base
	FS        *workspace.FS
	StateDir  string
	RepoSub   string
	Protected []string
	Mode      string // push | pr
}

func New(fs *workspace.FS, stateDir string) *Connector {
	// No branch needs approval by default: pushes are fast-forward only (force is refused),
	// staged on a review ref and undoable, and the remote's own branch protection still
	// applies. If a push to a branch deploys to production, list it in [git] protected.
	return &Connector{Base: tx.Base{ConnName: "git"}, FS: fs, StateDir: stateDir, RepoSub: ".", Mode: "push"}
}

func (*Connector) Egress() bool { return true }

// hardening applies to every git the gateway runs: no hooks, no fsmonitor, no ext:: remotes.
var hardening = []string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.ext.allow=never"}

func git(dir string, args ...string) (string, error) {
	c := exec.Command("git", append(append([]string{}, hardening...), args...)...)
	c.Dir = dir
	out, err := c.Output()
	if err != nil {
		msg := err.Error()
		if ee, ok := err.(*exec.ExitError); ok {
			msg = strings.TrimSpace(string(ee.Stderr))
		}
		return "", fmt.Errorf("git %s failed: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimSpace(string(out)), nil
}

func (g *Connector) Operations() map[string]tx.OpSchema {
	return map[string]tx.OpSchema{"push": {Description: "Push the current HEAD of the staged repo to a remote branch. " +
		"Goes to a staging ref until the transaction commits.",
		Properties: map[string]any{"remote": map[string]any{"type": "string"}, "branch": map[string]any{"type": "string"},
			"force": map[string]any{"type": "boolean"}}, Required: []string{"branch"}}}
}

func (g *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	b, _ := args["branch"].(string)
	prot := false
	for _, p := range g.Protected {
		if ok, _ := path.Match(p, b); ok {
			prot = true
		}
	}
	return model.Reversible, model.Facts{"branch": b, "force": args["force"] == true, "protected": prot}, nil
}

func remoteHead(url, branch string) string {
	out, _ := git(os.TempDir(), "ls-remote", url, "refs/heads/"+branch)
	if f := strings.Fields(out); len(f) > 0 {
		return f[0]
	}
	return ""
}

// validRemote: a remote name, as git config keys allow, never an option.
func validRemote(r string) error {
	if r == "" || strings.HasPrefix(r, "-") {
		return fmt.Errorf("invalid remote name %q", r)
	}
	for _, c := range r {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("invalid remote name %q", r)
		}
	}
	return nil
}

// validBranch: git's own rules for a branch name (check-ref-format), never an option.
func validBranch(b string) error {
	if b == "" || strings.HasPrefix(b, "-") {
		return fmt.Errorf("invalid branch name %q", b)
	}
	if _, err := git(os.TempDir(), "check-ref-format", "refs/heads/"+b); err != nil {
		return fmt.Errorf("invalid branch name %q", b)
	}
	return nil
}

// importRepo copies a repository's objects and refs, as plain files (symlinks and
// alternates refused), into a fresh bare repository the gateway owns.
func (g *Connector) importRepo(t *tx.Tx, worktree string) (string, error) {
	src := filepath.Join(worktree, ".git")
	if info, err := os.Lstat(src); err != nil || !info.IsDir() {
		return "", errors.New("the repository's .git is not a directory (linked worktrees and gitdir files are not supported)")
	}
	dst := filepath.Join(g.StateDir, "git", "import", t.ID+".git")
	_ = os.RemoveAll(dst)
	if _, err := git("", "init", "--bare", "-q", dst); err != nil {
		return "", err
	}
	for _, sub := range []string{"objects", "refs"} {
		if err := copyPlain(filepath.Join(src, sub), filepath.Join(dst, sub)); err != nil {
			return "", err
		}
	}
	for _, f := range []string{"HEAD", "packed-refs"} {
		if err := copyPlain(filepath.Join(src, f), filepath.Join(dst, f)); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	_ = os.Remove(filepath.Join(dst, "objects", "info", "alternates")) // never read another repository's objects
	_ = os.Remove(filepath.Join(dst, "objects", "info", "http-alternates"))
	return dst, nil
}

// copyPlain copies regular files and directories only.
func copyPlain(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return nil // a symlink could point anywhere on this machine
	case info.IsDir():
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return err
		}
		ents, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := copyPlain(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	case info.Mode().IsRegular():
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	}
	return nil
}

func (g *Connector) cache(url string) (string, error) {
	h := sha256.Sum256([]byte(url))
	p := filepath.Join(g.StateDir, "git", hex.EncodeToString(h[:8])+".git")
	if _, err := os.Stat(p); err != nil {
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if _, err := git("", "init", "--bare", "-q", p); err != nil {
			return "", err
		}
	}
	return p, nil
}

func (g *Connector) Stage(t *tx.Tx, a *model.Action) (any, error) {
	shadow, err := g.FS.Shadow(t)
	if err != nil {
		return nil, err
	}
	remote, _ := a.Args["remote"].(string)
	if remote == "" {
		remote = "origin"
	}
	branch, _ := a.Args["branch"].(string)
	if err := validRemote(remote); err != nil {
		return nil, err
	}
	if err := validBranch(branch); err != nil {
		return nil, err
	}
	// where a push goes is the operator's: read from the real repository, never the copy
	url, err := git(filepath.Join(g.FS.Root, g.RepoSub), "config", "--get", "remote."+remote+".url")
	if err != nil || url == "" {
		return nil, fmt.Errorf("the repository has no remote %q", remote)
	}
	// the agent's copy is data: its objects and refs are imported into a repository the
	// gateway owns, and git runs only there (no hook or config of the agent's ever runs)
	repo, err := g.importRepo(t, filepath.Join(shadow, g.RepoSub))
	if err != nil {
		return nil, err
	}
	sha, err := git(repo, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return nil, fmt.Errorf("the repository has no commit to push: %v", err)
	}
	if _, err := git(repo, "fetch", "-q", "--no-tags", url, "+refs/heads/*:refs/remotes/target/*"); err != nil {
		return nil, err
	}
	staging := "undolayer/" + t.ID + "/" + branch
	if _, err := git(repo, "push", "-q", url, sha+":refs/heads/"+staging); err != nil {
		return nil, err
	}
	st := tx.GetState[State](t, g.Name())
	st.Pushes = append(st.Pushes, &Push{URL: url, Branch: branch, SHA: sha, Staging: staging, Base: remoteHead(url, branch)})
	// A push is egress: inspect exactly what it carries - the commits the remote lacks.
	files, diff := g.outgoing(repo, sha)
	sens := map[string]bool{}
	if ws := tx.PeekState[workspace.State](t, "fs"); ws != nil {
		for _, f := range ws.SensitiveFiles {
			sens[f] = true
		}
	}
	var leaked []string
	for _, f := range files {
		if sens[f] {
			leaked = append(leaked, f)
		}
	}
	labels := t.Sensitive().LabelsIn(diff)
	flagged := t.Sensitive().FlaggedIn(diff)
	for _, h := range scanner.ScanText(diff) {
		flagged = append(flagged, "gitleaks:"+h.RuleID)
	}
	a.Facts["pushed_files"] = len(files)
	if len(leaked) > 0 || len(labels) > 0 {
		a.Facts["contains_sensitive"], a.Facts["sensitive_sources"] = true, append(leaked, labels...)
	}
	if len(flagged) > 0 {
		a.Facts["contains_flagged"], a.Facts["flagged_by"] = true, flagged
	}
	a.Facts["_reevaluate"] = true
	return map[string]any{"staged_ref": staging, "sha": sha, "target": branch, "files": len(files),
		"note": "pushed to a staging ref; the target branch updates on commit"}, nil
}

// outgoing lists the files touched by commits not yet on any remote ref, and their diff.
func (g *Connector) outgoing(repo, sha string) ([]string, string) {
	revs, err := git(repo, "rev-list", sha, "--not", "--remotes")
	if err != nil || revs == "" {
		return nil, ""
	}
	set := map[string]bool{}
	var diff strings.Builder
	for _, c := range strings.Fields(revs) {
		names, _ := git(repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", c)
		for _, n := range strings.Split(names, "\n") {
			if n != "" {
				set[n] = true
			}
		}
		patch, _ := git(repo, "show", "--format=", "--no-color", "--binary", c)
		diff.WriteString(patch)
	}
	out := []string{}
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, diff.String()
}

// Discard deletes the staging ref of a push that policy rejected after inspecting it.
func (g *Connector) Discard(t *tx.Tx, a *model.Action) bool {
	st := tx.PeekState[State](t, g.Name())
	if st == nil || len(st.Pushes) == 0 {
		return false
	}
	p := st.Pushes[len(st.Pushes)-1]
	if c, err := g.cache(p.URL); err == nil {
		_, _ = git(c, "push", "-q", p.URL, ":refs/heads/"+p.Staging)
	}
	st.Pushes = st.Pushes[:len(st.Pushes)-1]
	return true
}

func (g *Connector) Preview(t *tx.Tx) map[string]any {
	st := tx.PeekState[State](t, g.Name())
	if st == nil || len(st.Pushes) == 0 {
		return nil
	}
	out := []any{}
	for _, p := range st.Pushes {
		out = append(out, map[string]any{"target": p.Branch, "from": p.Base, "to": p.SHA, "staging_ref": p.Staging})
	}
	return map[string]any{"pushes": out}
}

func (g *Connector) Prepare(t *tx.Tx) error {
	st := tx.PeekState[State](t, g.Name())
	if st == nil {
		return nil
	}
	for _, p := range st.Pushes {
		head := remoteHead(p.URL, p.Branch)
		if head == p.Base {
			continue
		}
		c, err := g.cache(p.URL)
		if err != nil {
			return err
		}
		if _, err := git(c, "fetch", "-q", p.URL, "+refs/heads/"+p.Staging+":refs/staged", "+refs/heads/"+p.Branch+":refs/target"); err != nil {
			return err
		}
		if exec.Command("git", "-C", c, "merge-base", "--is-ancestor", "refs/target", "refs/staged").Run() != nil {
			return model.Conflict("%s moved on the remote and is no longer a fast-forward", p.Branch)
		}
		p.Base = head
	}
	return nil
}

func (g *Connector) Commit(t *tx.Tx) (any, error) {
	st := tx.PeekState[State](t, g.Name())
	if st == nil || len(st.Pushes) == 0 {
		return nil, nil
	}
	rec := &UndoRecord{}
	for _, p := range st.Pushes {
		c, err := g.cache(p.URL)
		if err != nil {
			return nil, err
		}
		if _, err := git(c, "fetch", "-q", p.URL, "+refs/heads/"+p.Staging+":refs/staged"); err != nil {
			return nil, err
		}
		if _, err := git(c, "push", "-q", p.URL, p.SHA+":refs/heads/"+p.Branch); err != nil {
			return nil, err
		}
		rec.Pushes = append(rec.Pushes, *p)
		_, _ = git(c, "push", "-q", p.URL, ":refs/heads/"+p.Staging)
	}
	return rec, nil
}

// Intent: the pushes, each with the branch head it moves from (Base) and to (SHA).
func (g *Connector) Intent(t *tx.Tx) (any, error) {
	st := tx.PeekState[State](t, g.Name())
	if st == nil || len(st.Pushes) == 0 {
		return nil, nil
	}
	rec := &UndoRecord{}
	for _, p := range st.Pushes {
		rec.Pushes = append(rec.Pushes, *p)
	}
	return rec, nil
}

// UndoInFlight: for each push the remote says where the branch is - still at its base
// (the push never happened), at the pushed commit (undo it), or elsewhere (a conflict).
func (g *Connector) UndoInFlight(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	var done UndoRecord
	for _, p := range rec.Pushes {
		switch head := remoteHead(p.URL, p.Branch); head {
		case p.SHA:
			done.Pushes = append(done.Pushes, p)
		case p.Base:
		default:
			return model.Conflict("%s is at %s, neither where the interrupted push started (%s) nor where it went (%s)",
				p.Branch, head, p.Base, p.SHA)
		}
		if c, err := g.cache(p.URL); err == nil { // the staging ref is never part of the result
			_, _ = git(c, "push", "-q", p.URL, ":refs/heads/"+p.Staging)
		}
	}
	if len(done.Pushes) == 0 {
		return nil
	}
	b, _ := json.Marshal(done)
	return g.Undo(b)
}

func (g *Connector) Rollback(t *tx.Tx) error {
	st := tx.PeekState[State](t, g.Name())
	if st == nil {
		return nil
	}
	var errs []string
	for _, p := range st.Pushes {
		c, err := g.cache(p.URL)
		if err == nil {
			_, err = git(c, "push", "-q", p.URL, ":refs/heads/"+p.Staging)
		}
		if err != nil && remoteHead(p.URL, p.Staging) != "" {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("staging refs left on the remote: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (g *Connector) Recover(t *tx.Tx) error { return g.Rollback(t) }

func (g *Connector) Undo(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	for i := len(rec.Pushes) - 1; i >= 0; i-- {
		p := rec.Pushes[i]
		if remoteHead(p.URL, p.Branch) != p.SHA {
			return model.Conflict("%s has new commits since this push; use git revert instead", p.Branch)
		}
		lease := "--force-with-lease=refs/heads/" + p.Branch + ":" + p.SHA
		c, err := g.cache(p.URL) // every remote operation runs inside a repository
		if err != nil {
			return err
		}
		if p.Base == "" {
			if _, err := git(c, "push", "-q", lease, p.URL, ":refs/heads/"+p.Branch); err != nil {
				return err
			}
			continue
		}
		_, _ = git(c, "fetch", "-q", p.URL, p.Base)
		if _, err := git(c, "push", "-q", lease, p.URL, p.Base+":refs/heads/"+p.Branch); err != nil {
			return err
		}
	}
	return nil
}

// NodeLocal: pushes are staged in this node's cache repository.
func (*Connector) NodeLocal() bool { return true }
