package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// The archive is the vault's copy outside its replicas: sealed segments are uploaded to
// object storage (in another region, if the bucket is there), each written once under
// Object Lock in compliance mode, so for the retention period nobody can delete or
// overwrite it, with any credentials. A segment is sealed when the next one starts; with
// an archive configured, segments are also closed by age (MaxSegmentAge), so what is not
// archived yet is never more than that old. Before upload, every record of the segment is
// verified (checksum and chain), so the archive only ever holds intact copies.
//
// Replicas lost entirely are rebuilt from the archive (RestoreReplica), then caught up from
// the other replicas as usual.

// Archive configures where sealed segments go.
type Archive struct {
	S3       *S3
	Prefix   string        // key prefix, e.g. "countersign/vault/"
	LockDays int           // Object Lock retention (0: no lock)
	Every    time.Duration // how often to look for sealed segments (default 30s)
}

type archiveState struct {
	Uploaded map[string]string `json:"uploaded"` // segment first seq -> sha256 of what was uploaded
}

func (v *Vault) archiveStatePath() string {
	return filepath.Join(filepath.Dir(v.o.LockPath), "vault-archive.json")
}

func (v *Vault) readArchiveState() archiveState {
	st := archiveState{Uploaded: map[string]string{}}
	if b, err := os.ReadFile(v.archiveStatePath()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.Uploaded == nil {
		st.Uploaded = map[string]string{}
	}
	return st
}

func (v *Vault) writeArchiveState(st archiveState) error {
	b, _ := json.MarshalIndent(st, "", " ")
	tmp := v.archiveStatePath() + ".tmp-" + rnd()
	if err := writeFileSync(tmp, b); err != nil {
		return err
	}
	return os.Rename(tmp, v.archiveStatePath())
}

// ArchiveReport says what the archive holds.
type ArchiveReport struct {
	Uploaded []string `json:"uploaded"` // segments uploaded by this call
	Pending  int      `json:"pending"`  // sealed segments not in the archive yet
	Total    int      `json:"total"`
}

func archiveKey(prefix string, first uint64) string {
	return fmt.Sprintf("%s%020d.log", prefix, first)
}

// ArchiveSealed uploads every sealed segment that is not in the archive yet. It reads
// them from a replica whose segments verify (falling back to the next replica).
func (v *Vault) ArchiveSealed() (*ArchiveReport, error) {
	a := v.o.Archive
	if a == nil || a.S3 == nil {
		return nil, errors.New("vault: no archive configured")
	}
	v.archiveMu.Lock()
	defer v.archiveMu.Unlock()
	st := v.readArchiveState()
	rep := &ArchiveReport{Uploaded: []string{}}
	var lastErr error
	for _, r := range v.o.Replicas {
		segs, err := segments(r)
		if err != nil || len(segs) < 2 {
			lastErr = err
			continue
		}
		sealed := segs[:len(segs)-1]
		rep.Total = len(sealed)
		ok := true
		for _, p := range sealed {
			name := filepath.Base(p)
			first := strings.TrimSuffix(name, ".log")
			if _, done := st.Uploaded[first]; done {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				ok, lastErr = false, err
				break
			}
			if err := verifySegment(b); err != nil { // never archive a damaged copy
				ok, lastErr = false, fmt.Errorf("%s: %v", p, err)
				break
			}
			var lock time.Time
			if a.LockDays > 0 {
				lock = time.Now().Add(time.Duration(a.LockDays) * 24 * time.Hour)
			}
			var firstSeq uint64
			fmt.Sscanf(first, "%d", &firstSeq)
			key := archiveKey(a.Prefix, firstSeq)
			if h, err := a.S3.Head(key); err == nil && h != nil {
				// already there (another node, or a run cut short): keep it, it is locked
			} else if err := a.S3.Put(key, b, lock); err != nil {
				ok, lastErr = false, err
				break
			}
			st.Uploaded[first] = sha256hex(b)
			if err := v.writeArchiveState(st); err != nil {
				return rep, err
			}
			rep.Uploaded = append(rep.Uploaded, key)
		}
		if ok {
			for _, p := range sealed {
				if _, done := st.Uploaded[strings.TrimSuffix(filepath.Base(p), ".log")]; !done {
					rep.Pending++
				}
			}
			return rep, nil
		}
	}
	if lastErr == nil {
		return rep, nil // nothing sealed yet
	}
	return rep, lastErr
}

// verifySegment checks every line of a segment (checksums, consecutive sequence numbers,
// each linked to the one before).
func verifySegment(b []byte) error {
	var prev *Record
	for i, l := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
		rec, err := decode(l)
		if err != nil {
			return fmt.Errorf("line %d: %v", i+1, err)
		}
		if prev != nil && (rec.Seq != prev.Seq+1 || rec.Prev != prev.sum) {
			return fmt.Errorf("line %d: the chain breaks", i+1)
		}
		prev = rec
	}
	if prev == nil {
		return errors.New("empty")
	}
	return nil
}

// RestoreReplica fills an empty replica directory from the archive; the next append (or
// Repair) catches it up from the other replicas with what came after.
func (v *Vault) RestoreReplica(dir string) (int, error) {
	a := v.o.Archive
	if a == nil || a.S3 == nil {
		return 0, errors.New("vault: no archive configured")
	}
	abs, _ := filepath.Abs(dir)
	found := false
	for _, r := range v.o.Replicas {
		found = found || r == abs
	}
	if !found {
		return 0, fmt.Errorf("%s is not one of this vault's replicas", dir)
	}
	unlock, err := v.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if segs, _ := segments(abs); len(segs) > 0 {
		return 0, fmt.Errorf("%s is not empty; restore only into an empty replica", abs)
	}
	if err := v.prepare(abs); err != nil {
		return 0, err
	}
	keys, err := a.S3.List(a.Prefix)
	if err != nil {
		return 0, err
	}
	sort.Strings(keys)
	var prev *Record
	n := 0
	for _, k := range keys {
		b, err := a.S3.Get(k)
		if err != nil {
			return n, err
		}
		if err := verifySegment(b); err != nil {
			return n, fmt.Errorf("%s: %v", k, err)
		}
		first, _ := decode(bytes.SplitN(b, []byte("\n"), 2)[0])
		if prev != nil && (first.Seq != prev.Seq+1 || first.Prev != prev.sum) {
			return n, fmt.Errorf("%s does not follow the segment before it", k)
		}
		lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
		prev, _ = decode(lines[len(lines)-1])
		if err := writeFileSync(segName(abs, first.Seq), b); err != nil {
			return n, err
		}
		n++
	}
	_ = os.RemoveAll(idxDir(abs))
	return n, syncDir(segDir(abs))
}

// StartArchiver uploads sealed segments in the background until stop is closed.
func (v *Vault) StartArchiver(stop <-chan struct{}, report func(*ArchiveReport, error)) {
	a := v.o.Archive
	if a == nil {
		return
	}
	every := a.Every
	if every <= 0 {
		every = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				rep, err := v.ArchiveSealed()
				if report != nil && (err != nil || len(rep.Uploaded) > 0) {
					report(rep, err)
				}
			}
		}
	}()
}

var _ sync.Locker = (*sync.Mutex)(nil)
