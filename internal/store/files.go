package store

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Files keeps state in a directory (0700) on this machine.
type Files struct{ Dir string }

func OpenFiles(dir string) (*Files, error) {
	if err := os.MkdirAll(filepath.Join(dir, "tx"), 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	return &Files{Dir: dir}, nil
}

func (f *Files) path(id, suffix string) string { return filepath.Join(f.Dir, "tx", id+suffix) }

func (f *Files) Shared() bool { return false }
func (f *Files) Close() error { return nil }

func (f *Files) SaveTx(id string, doc []byte) error {
	p := f.path(id, ".json")
	tmp := p + ".tmp"
	fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(doc); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Stamp identifies the current version of a transaction's journal (size and change time),
// so a reader can tell, with one stat, whether it changed since it last read it.
func (f *Files) Stamp(id string) (string, error) {
	fi, err := os.Stat(f.path(id, ".json"))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d.%d.%d", fi.Size(), fi.ModTime().UnixNano(), inode(fi)), nil
}

func (f *Files) LoadTx(id string) ([]byte, error) {
	b, err := os.ReadFile(f.path(id, ".json"))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return b, err
}

func (f *Files) ListTx() ([][]byte, error) {
	files, err := filepath.Glob(filepath.Join(f.Dir, "tx", "tx_*.json"))
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, p := range files {
		if strings.HasSuffix(p, ".approvals.json") {
			continue
		}
		if b, err := os.ReadFile(p); err == nil {
			out = append(out, b)
		}
	}
	return out, nil
}

type flock struct{ fd int }

func (l *flock) Release() {
	if l.fd >= 0 {
		_ = syscall.Flock(l.fd, syscall.LOCK_UN)
		_ = syscall.Close(l.fd)
		l.fd = -1
	}
}

func (f *Files) TryLock(id string) (Lock, bool) {
	fd, err := syscall.Open(f.path(id, ".lock"), syscall.O_RDWR|syscall.O_CREAT, 0o600)
	if err != nil {
		return nil, false
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = syscall.Close(fd)
		return nil, false
	}
	return &flock{fd: fd}, true
}

func (f *Files) AppendApproval(id string, rec []byte) error {
	fh, err := os.OpenFile(f.path(id, ".approvals.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	if _, err := fh.Write(append(rec, '\n')); err != nil {
		return err
	}
	return fh.Sync()
}

func (f *Files) Approvals(id string) ([][]byte, error) {
	b, err := os.ReadFile(f.path(id, ".approvals.jsonl"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			out = append(out, line)
		}
	}
	return out, nil
}

func (f *Files) auditPath() string { return filepath.Join(f.Dir, "audit.jsonl") }

func (f *Files) AppendAudit(next func(prev []byte) ([][]byte, error)) error {
	fh, err := os.OpenFile(f.auditPath(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	if err := syscall.Flock(int(fh.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(fh.Fd()), syscall.LOCK_UN) //nolint:errcheck
	prev, err := lastLine(fh)
	if err != nil {
		return err
	}
	lines, err := next(prev)
	if err != nil {
		return err
	}
	var buf []byte
	for _, l := range lines {
		buf = append(append(buf, l...), '\n')
	}
	if _, err := fh.Write(buf); err != nil {
		return err
	}
	return fh.Sync()
}

func lastLine(f *os.File) ([]byte, error) {
	end, err := f.Seek(0, io.SeekEnd)
	if err != nil || end == 0 {
		return nil, err
	}
	size := int64(4096)
	for {
		start := end - size
		if start < 0 {
			start = 0
		}
		buf := make([]byte, end-start)
		if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
			return nil, err
		}
		lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
		if len(lines) >= 2 || start == 0 {
			last := lines[len(lines)-1]
			if len(bytes.TrimSpace(last)) == 0 {
				return nil, nil
			}
			return last, nil
		}
		size *= 2
	}
}

func (f *Files) AuditLines(fn func(line []byte) error) error {
	b, err := os.ReadFile(f.auditPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	return nil
}

func (f *Files) Key(name string) ([]byte, error) {
	p := filepath.Join(f.Dir, name)
	if b, err := os.ReadFile(p); err == nil {
		return b, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	fh, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return os.ReadFile(p)
		}
		return nil, err
	}
	defer fh.Close()
	_, err = fh.Write(k)
	return k, err
}

func (f *Files) Get(name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(f.Dir, "shared", name))
	if os.IsNotExist(err) {
		return nil, nil
	}
	return b, err
}

func (f *Files) Put(name string, b []byte) error {
	d := filepath.Join(f.Dir, "shared")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(d, name+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d, name))
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino) // a rename (every journal write) gives a new inode
	}
	return 0
}
