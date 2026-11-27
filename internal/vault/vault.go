// Package vault keeps what every change destroyed or replaced, before the change happens,
// in several independent copies.
//
// The rule it exists for: if a change went through, a verified copy of what it changed was
// already durable on a write quorum of replicas. The runtime appends the change's before
// state here and only then lets the change run; if the append cannot reach the quorum, the
// change does not run.
//
// Storage. Each replica is a directory (another disk, another mount, a network volume)
// holding append-only segment files of records, one JSON line each:
//
//	{"sum":"<sha256 of rec>","rec":{...}}
//
// A record carries a sequence number and the sum of the record before it, so each replica
// is a hash chain: a changed, removed or reordered record shows. Every replica holds the
// same chain; a replica that missed writes while it was down is caught up from the others
// before it takes new ones. What a record holds (rows, the undo record) is sealed with
// AES-256-GCM under a key kept outside the replicas (see Keyring); the sum covers the
// sealed form, so replicas are checked and repaired without the key.
//
// Nothing is ever deleted. A torn last line (a crash in the middle of a write) or a line
// that no longer matches its sum is moved aside into the replica's orphans directory, and
// the record is copied back from a replica that holds it intact. Records that lost a
// quorum race are kept as orphans too, and reads still see them: a record is found by its
// own sum, whichever replica or file it is in.
//
// Quorum. With N replicas and a write quorum W (default a majority), an append succeeds
// once W replicas have it on disk (fsync). Appends also need W replicas reachable to
// decide the next sequence number. Because 2W > N, any W replicas include at least one
// that holds every acknowledged record.
//
// Finding a task's entries does not read the whole vault: each replica keeps an index by
// task, sharded, written after the data and verified against each record's sum when used.
// The index is only a hint: a missing or stale part is rebuilt from the segments.
package vault

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Row is the net change a task made to one row (or document, file or resource): its key,
// and its content before and after. Before is empty for a row the task created, After for
// a row it deleted.
type Row struct {
	Table  string         `json:"table"`
	Op     string         `json:"op"` // insert | update | delete | drop_table | drop_column | content
	Key    map[string]any `json:"key"`
	Before map[string]any `json:"before,omitempty"`
	After  map[string]any `json:"after,omitempty"`
}

// Entry is one append: the before state of one connector's part of one task.
type Entry struct {
	Tx        string
	Task      string
	Requester string
	Connector string
	// Phase: intent (written before the change runs), committed (the change ran; Undo is
	// the precise record when it differs from the intent), failed (the commit returned an
	// error; the change most likely did not happen).
	Phase string
	// Ref is the batch of the intent a committed or failed entry settles.
	Ref  string
	Rows []Row
	// Undo is the connector's own undo record: the exact way back.
	Undo json.RawMessage
}

// Record is one line of a segment. An entry too large for one record is split into parts
// that share a batch id; the entry is complete when every part is present.
type Record struct {
	Seq       uint64  `json:"seq"`
	Prev      string  `json:"prev"`
	TS        float64 `json:"ts"`
	Batch     string  `json:"batch"`
	Part      int     `json:"part"`
	Parts     int     `json:"parts"`
	Tx        string  `json:"tx"`
	Task      string  `json:"task,omitempty"`
	Requester string  `json:"requester,omitempty"`
	Connector string  `json:"connector"`
	Phase     string  `json:"phase"`
	Ref       string  `json:"ref,omitempty"`
	Rows      []Row   `json:"rows,omitempty"`
	Undo      []byte  `json:"undo,omitempty"`
	// Key and Sealed: with a keyring, Rows and Undo are sealed (AES-256-GCM) into Sealed
	// under the key Key, bound to this record's batch, part, task, connector and phase.
	Key    string `json:"key,omitempty"`
	Sealed []byte `json:"sealed,omitempty"`

	sum string
	raw []byte // the exact bytes the sum covers
}

// Sum is the record's checksum (its identity).
func (r *Record) Sum() string { return r.sum }

type line struct {
	Sum string          `json:"sum"`
	Rec json.RawMessage `json:"rec"`
}

func encode(r *Record) ([]byte, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(body)
	r.sum, r.raw = hex.EncodeToString(h[:]), body
	return rawLine(r), nil
}

// decode parses and verifies one line (without its newline).
func decode(b []byte) (*Record, error) {
	var l line
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	h := sha256.Sum256(l.Rec)
	if hex.EncodeToString(h[:]) != l.Sum {
		return nil, errors.New("checksum mismatch")
	}
	dec := json.NewDecoder(bytes.NewReader(l.Rec))
	dec.UseNumber() // values come back exactly as written
	var r Record
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	r.sum, r.raw = l.Sum, append([]byte{}, l.Rec...)
	return &r, nil
}

// rawLine is a record's line exactly as it was first written (copies are byte for byte).
func rawLine(rec *Record) []byte {
	b, _ := json.Marshal(line{Sum: rec.sum, Rec: rec.raw})
	return append(b, '\n')
}

func aad(r *Record) []byte {
	return []byte(fmt.Sprintf("%s\x00%d\x00%d\x00%s\x00%s\x00%s", r.Batch, r.Part, r.Parts, r.Tx, r.Connector, r.Phase))
}

type sealedBody struct {
	Rows []Row  `json:"rows,omitempty"`
	Undo []byte `json:"undo,omitempty"`
}

// Options configure a vault.
type Options struct {
	// Replicas are directories, ideally on independent disks or volumes.
	Replicas []string
	// WriteQuorum is how many replicas must have a record on disk before an append
	// succeeds. Default: a majority. It must be a majority (2W > N).
	WriteQuorum int
	// LockPath serialises appends across processes; a local path, not on a replica (a
	// replica may be the one that is down).
	LockPath string
	// Keys seals what records hold. Nil stores it in the clear.
	Keys *Keyring
	// RequireIndependent refuses to open when two replicas are on the same device (they
	// would be lost together).
	RequireIndependent bool
	// SegmentBytes: a segment is closed once it reaches this size (default 64 MiB).
	SegmentBytes int64
	// PartRows and PartBytes bound one record (defaults 1000 rows, 1 MiB of rows and undo).
	PartRows  int
	PartBytes int
	// Now is the clock (tests).
	Now func() time.Time
}

// ErrNoQuorum: fewer than WriteQuorum replicas could take or confirm the write.
var ErrNoQuorum = errors.New("vault: write quorum not reached")

type Vault struct {
	o  Options
	mu sync.Mutex
	// group commit
	qmu       sync.Mutex
	queue     []*waiter
	lazy      []*waiter
	lazyTimer bool
	leading   bool
	shared    [][]string
	// hook, if set, is called before each replica operation (tests inject faults with it).
	hook func(replica string, op string) error
}

// Open validates the options and creates the replica directories it can.
func Open(o Options) (*Vault, error) {
	n := len(o.Replicas)
	if n == 0 {
		return nil, errors.New("vault: no replicas")
	}
	seen := map[string]bool{}
	reps := make([]string, n)
	for i, r := range o.Replicas {
		a, err := filepath.Abs(r)
		if err != nil {
			return nil, err
		}
		if seen[a] {
			return nil, fmt.Errorf("vault: replica %s is listed twice", a)
		}
		seen[a] = true
		reps[i] = a
	}
	o.Replicas = reps
	if o.WriteQuorum == 0 {
		o.WriteQuorum = n/2 + 1
	}
	if o.WriteQuorum < 1 || o.WriteQuorum > n || 2*o.WriteQuorum <= n {
		return nil, fmt.Errorf("vault: write quorum %d of %d replicas must be a majority", o.WriteQuorum, n)
	}
	if o.LockPath == "" {
		return nil, errors.New("vault: a lock path is required")
	}
	if o.SegmentBytes <= 0 {
		o.SegmentBytes = 64 << 20
	}
	if o.PartRows <= 0 {
		o.PartRows = 1000
	}
	if o.PartBytes <= 0 {
		o.PartBytes = 1 << 20
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(o.LockPath), 0o700); err != nil {
		return nil, err
	}
	v := &Vault{o: o}
	for _, r := range o.Replicas {
		_ = v.prepare(r) // a replica that is down now is caught up when it is back
	}
	v.shared = sharedDevices(o.Replicas)
	if o.RequireIndependent && len(v.shared) > 0 {
		return nil, fmt.Errorf("vault: replicas %v are on the same device and would be lost together", v.shared)
	}
	return v, nil
}

// sharedDevices groups replicas that live on the same device.
func sharedDevices(reps []string) [][]string {
	by := map[uint64][]string{}
	var order []uint64
	for _, r := range reps {
		var st syscall.Stat_t
		if syscall.Stat(r, &st) != nil {
			continue
		}
		d := uint64(st.Dev)
		if by[d] == nil {
			order = append(order, d)
		}
		by[d] = append(by[d], r)
	}
	var out [][]string
	for _, d := range order {
		if len(by[d]) > 1 {
			out = append(out, by[d])
		}
	}
	return out
}

// Replicas returns the replica directories.
func (v *Vault) Replicas() []string { return append([]string{}, v.o.Replicas...) }

// Quorum returns the write quorum.
func (v *Vault) Quorum() int { return v.o.WriteQuorum }

// Keys returns the keyring (nil when content is stored in the clear).
func (v *Vault) Keys() *Keyring { return v.o.Keys }

// SharedDevices lists groups of replicas that are on the same device.
func (v *Vault) SharedDevices() [][]string { return v.shared }

func segDir(r string) string    { return filepath.Join(r, "seg") }
func orphanDir(r string) string { return filepath.Join(r, "orphans") }

// prepare creates a replica's directories and finishes a repair a crash interrupted.
func (v *Vault) prepare(r string) error {
	for _, d := range []string{r, orphanDir(r)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	seg, next, old := segDir(r), segDir(r)+".new", segDir(r)+".old"
	_, errSeg := os.Stat(seg)
	_, errNext := os.Stat(next)
	if os.IsNotExist(errSeg) && errNext == nil { // crashed between the two renames of a repair
		if err := os.Rename(next, seg); err != nil {
			return err
		}
		_ = os.RemoveAll(idxDir(r))
	} else if errNext == nil { // crashed while writing the new segments: the old ones stand
		if err := os.RemoveAll(next); err != nil {
			return err
		}
	}
	if _, err := os.Stat(old); err == nil {
		// everything in it was written to the new segments or to orphans before the swap
		if err := os.RemoveAll(old); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(seg, 0o700); err != nil {
		return err
	}
	return syncDir(r)
}

func syncDir(d string) error {
	f, err := os.Open(d)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func (v *Vault) fault(r, op string) error {
	if v.hook != nil {
		return v.hook(r, op)
	}
	return nil
}

// lock serialises appends, index rebuilds and repairs: in this process, and across processes.
func (v *Vault) lock() (func(), error) {
	v.mu.Lock()
	fd, err := syscall.Open(v.o.LockPath, syscall.O_RDWR|syscall.O_CREAT, 0o600)
	if err != nil {
		v.mu.Unlock()
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = syscall.Close(fd)
		v.mu.Unlock()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
		v.mu.Unlock()
	}, nil
}

// segments lists a replica's segment files, oldest first.
func segments(r string) ([]string, error) {
	es, err := os.ReadDir(segDir(r))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			out = append(out, filepath.Join(segDir(r), e.Name()))
		}
	}
	sort.Strings(out) // names are zero-padded first sequence numbers
	return out, nil
}

func segName(r string, first uint64) string {
	return filepath.Join(segDir(r), fmt.Sprintf("%020d.log", first))
}

// moveAside keeps bytes that are being removed from a segment, so nothing is ever lost.
func (v *Vault) moveAside(r, why string, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	p := filepath.Join(orphanDir(r), fmt.Sprintf("%s-%d-%s.bin", why, v.o.Now().UnixNano(), rnd()))
	if err := writeFileSync(p, b); err != nil {
		return err
	}
	return syncDir(orphanDir(r))
}

func writeFileSync(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func rnd() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type tail struct {
	seq   uint64
	sum   string
	seg   string // last segment ("" if none)
	size  int64
	empty bool
}

// readTail finds a replica's last valid record. A torn or corrupt end is moved aside and
// cut off (only the end of the last segment can be torn: appends hold the lock).
func (v *Vault) readTail(r string) (tail, error) {
	if err := v.prepare(r); err != nil {
		return tail{}, err
	}
	segs, err := segments(r)
	if err != nil {
		return tail{}, err
	}
	for len(segs) > 0 {
		p := segs[len(segs)-1]
		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			return tail{}, err
		}
		t, err := v.fileTail(r, f)
		f.Close()
		if err != nil {
			return tail{}, err
		}
		if !t.empty {
			t.seg = p
			return t, nil
		}
		// the whole segment was torn: it is kept in orphans; drop the empty file
		if err := os.Remove(p); err != nil {
			return tail{}, err
		}
		_ = syncDir(segDir(r))
		segs = segs[:len(segs)-1]
	}
	return tail{empty: true}, nil
}

func (v *Vault) fileTail(r string, f *os.File) (tail, error) {
	for {
		end, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return tail{}, err
		}
		if end == 0 {
			return tail{empty: true}, nil
		}
		last, start, err := lastLine(f, end)
		if err != nil {
			return tail{}, err
		}
		complete := start+int64(len(last)) < end // followed by its newline
		if complete {
			if rec, err := decode(last); err == nil {
				return tail{seq: rec.Seq, sum: rec.sum, size: end}, nil
			}
		}
		why := "torn"
		if complete {
			why = "corrupt"
		}
		if err := v.moveAside(r, why, append([]byte{}, last...)); err != nil {
			return tail{}, err
		}
		if err := f.Truncate(start); err != nil {
			return tail{}, err
		}
		if err := f.Sync(); err != nil {
			return tail{}, err
		}
	}
}

// lastLine returns the last line of f (without its newline) and where it starts.
func lastLine(f *os.File, end int64) ([]byte, int64, error) {
	stop := end
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, end-1); err != nil {
		return nil, 0, err
	}
	if buf[0] == '\n' {
		stop = end - 1
	}
	size := int64(64 << 10)
	for {
		start := stop - size
		if start < 0 {
			start = 0
		}
		chunk := make([]byte, stop-start)
		if _, err := f.ReadAt(chunk, start); err != nil && err != io.EOF {
			return nil, 0, err
		}
		if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 {
			return chunk[i+1:], start + int64(i) + 1, nil
		}
		if start == 0 {
			return chunk, 0, nil
		}
		size *= 4
	}
}

var errBad = errors.New("bad line")

// scanLines calls fn with each complete line of p (without its newline) and its offset.
// fn returns errBad to count a line as invalid. An unterminated end counts as invalid.
func scanLines(p string, fn func(off int64, l []byte) error) (bad int, err error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	var off int64
	for {
		l, err := br.ReadBytes('\n')
		if len(l) > 0 {
			if l[len(l)-1] != '\n' {
				bad++
			} else if e := fn(off, l[:len(l)-1]); e == errBad {
				bad++
			} else if e != nil {
				return bad, e
			}
			off += int64(len(l))
		}
		if err == io.EOF {
			return bad, nil
		}
		if err != nil {
			return bad, err
		}
	}
}

// each streams a replica's valid records with seq > after, in order.
func each(r string, after uint64, fn func(rec *Record, seg string, off int64) error) (bad int, err error) {
	segs, err := segments(r)
	if err != nil {
		return 0, err
	}
	start := 0
	for i := range segs {
		var first uint64
		if _, err := fmt.Sscanf(filepath.Base(segs[i]), "%020d.log", &first); err == nil && first <= after+1 {
			start = i
		}
	}
	for _, p := range segs[start:] {
		b, err := scanLines(p, func(off int64, l []byte) error {
			rec, err := decode(l)
			if err != nil {
				return errBad
			}
			if rec.Seq <= after {
				return nil
			}
			return fn(rec, p, off)
		})
		bad += b
		if err != nil {
			return bad, err
		}
	}
	return bad, nil
}

var errStop = errors.New("stop")

// indexEvery: how many records between durable index checkpoints (a var for tests).
var indexEvery uint64 = 1024

// recordAt returns a replica's record with the given seq, or nil.
func recordAt(r string, seq uint64) (*Record, error) {
	if seq == 0 {
		return nil, nil
	}
	var out *Record
	_, err := each(r, seq-1, func(rec *Record, _ string, _ int64) error {
		if rec.Seq == seq {
			out = rec
		}
		return errStop
	})
	if err != nil && err != errStop {
		return nil, err
	}
	return out, nil
}

// split turns an entry into records (without seq, prev or sum), each bounded in rows and
// bytes, and seals their content when there is a keyring.
func (v *Vault) split(e Entry, batch string, ts float64) ([]*Record, error) {
	var rowParts [][]Row
	var cur []Row
	size := 0
	for _, r := range e.Rows {
		b, _ := json.Marshal(r)
		if len(cur) > 0 && (len(cur) >= v.o.PartRows || size+len(b) > v.o.PartBytes) {
			rowParts, cur, size = append(rowParts, cur), nil, 0
		}
		cur, size = append(cur, r), size+len(b)
	}
	if len(cur) > 0 {
		rowParts = append(rowParts, cur)
	}
	var undoParts [][]byte
	for i := 0; i < len(e.Undo); i += v.o.PartBytes {
		undoParts = append(undoParts, e.Undo[i:min(i+v.o.PartBytes, len(e.Undo))])
	}
	n := max(len(rowParts), len(undoParts), 1)
	out := make([]*Record, n)
	for i := range out {
		r := &Record{TS: ts, Batch: batch, Part: i, Parts: n, Tx: e.Tx, Task: e.Task, Requester: e.Requester,
			Connector: e.Connector, Phase: e.Phase, Ref: e.Ref}
		var body sealedBody
		if i < len(rowParts) {
			body.Rows = rowParts[i]
		}
		if i < len(undoParts) {
			body.Undo = undoParts[i]
		}
		if v.o.Keys != nil && (body.Rows != nil || body.Undo != nil) {
			plain, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			id, sealed, err := v.o.Keys.seal(aad(r), plain)
			if err != nil {
				return nil, err
			}
			r.Key, r.Sealed = id, sealed
		} else {
			r.Rows, r.Undo = body.Rows, body.Undo
		}
		out[i] = r
	}
	return out, nil
}

// Receipt says where an entry was stored.
type Receipt struct {
	Batch    string `json:"batch"`
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
	LastSum  string `json:"last_sum"`
	Copies   int    `json:"copies"`
	Replicas int    `json:"replicas"`
}

// AppendLater stores an entry without waiting: it goes into the next batch that is written
// (or, if none comes, within lazyEvery). Used for records nothing waits on (how a change
// that is already in the vault ended); Flush writes what is pending.
func (v *Vault) AppendLater(e Entry) {
	batch := rnd() + rnd()
	recs, err := v.split(e, batch, float64(v.o.Now().UnixNano())/1e9)
	if err != nil {
		return
	}
	v.qmu.Lock()
	v.lazy = append(v.lazy, &waiter{recs: recs, done: make(chan struct{})})
	start := !v.lazyTimer
	v.lazyTimer = true
	v.qmu.Unlock()
	if start {
		time.AfterFunc(lazyEvery, func() { _ = v.Flush() })
	}
}

// lazyEvery: the longest an AppendLater entry waits for a batch to ride in.
var lazyEvery = 200 * time.Millisecond

// Flush writes every entry AppendLater queued.
func (v *Vault) Flush() error {
	v.qmu.Lock()
	v.lazyTimer = false
	if len(v.lazy) == 0 {
		v.qmu.Unlock()
		return nil
	}
	last := v.lazy[len(v.lazy)-1]
	v.qmu.Unlock()
	v.lead()
	<-last.done
	return last.err
}

// Append stores an entry on at least WriteQuorum replicas, or returns an error wrapping
// ErrNoQuorum (some replicas may then hold it: such records are harmless and are kept).
//
// Group commit: entries appended at the same time (from any goroutine of this process)
// are written together, one write and one sync per replica for the whole batch, and each
// returns once the batch is on a quorum. The first caller to arrive writes; the others
// wait for it, and whoever arrives while a batch is being written goes in the next one.
func (v *Vault) Append(e Entry) (*Receipt, error) {
	if e.Tx == "" || e.Connector == "" || e.Phase == "" {
		return nil, errors.New("vault: an entry needs tx, connector and phase")
	}
	batch := rnd() + rnd()
	recs, err := v.split(e, batch, float64(v.o.Now().UnixNano())/1e9)
	if err != nil {
		return nil, err
	}
	w := &waiter{recs: recs, done: make(chan struct{})}
	v.qmu.Lock()
	v.queue = append(v.queue, w)
	v.qmu.Unlock()
	v.lead()
	<-w.done
	return w.rc, w.err
}

// lead writes queued entries, batch after batch, unless another caller already is (then
// that one writes them).
func (v *Vault) lead() {
	v.qmu.Lock()
	if v.leading {
		v.qmu.Unlock()
		return
	}
	v.leading = true
	v.qmu.Unlock()
	for {
		v.qmu.Lock()
		group := append(v.lazy, v.queue...) // queued later entries ride along
		v.lazy, v.queue = nil, nil
		if len(group) == 0 {
			v.leading = false
			v.qmu.Unlock()
			return
		}
		v.qmu.Unlock()
		v.appendGroup(group)
		for _, g := range group {
			close(g.done)
		}
	}
}

type waiter struct {
	recs []*Record
	rc   *Receipt
	err  error
	done chan struct{}
}

// appendGroup writes a group of entries as one batch.
func (v *Vault) appendGroup(group []*waiter) {
	fail := func(err error) {
		for _, g := range group {
			g.err = err
		}
	}
	unlock, err := v.lock()
	if err != nil {
		fail(err)
		return
	}
	defer unlock()

	tails, ok, problems := v.tails()
	if reach := count(ok); reach < v.o.WriteQuorum {
		fail(fmt.Errorf("%w: %d of %d replicas reachable, %d needed (%s)", ErrNoQuorum, reach,
			len(v.o.Replicas), v.o.WriteQuorum, strings.Join(problems, "; ")))
		return
	}
	// Fast path: every reachable replica ends at the same record. Otherwise some missed
	// writes or hold records that lost a quorum race: reconcile them first.
	if !sameTails(tails, ok) {
		if err := v.reconcileLocked(ok, false); err != nil {
			problems = append(problems, err.Error())
		}
		var more []string
		tails, ok, more = v.tails(ok...)
		problems = append(problems, more...)
		ref := -1
		for i := range tails {
			if ok[i] && (ref < 0 || tails[i].seq > tails[ref].seq) {
				ref = i
			}
		}
		for i := range tails {
			if ok[i] && (tails[i].seq != tails[ref].seq || tails[i].sum != tails[ref].sum) {
				ok[i] = false
				problems = append(problems, v.o.Replicas[i]+": could not be reconciled")
			}
		}
		if reach := count(ok); reach < v.o.WriteQuorum {
			fail(fmt.Errorf("%w: %d of %d replicas agree, %d needed (%s)", ErrNoQuorum, reach,
				len(v.o.Replicas), v.o.WriteQuorum, strings.Join(problems, "; ")))
			return
		}
	}
	var head tail
	for i := range tails {
		if ok[i] {
			head = tails[i]
			break
		}
	}
	seq, prev := head.seq, head.sum
	var all []*Record
	for _, g := range group {
		for _, r := range g.recs {
			seq++
			r.Seq, r.Prev = seq, prev
			if _, err := encode(r); err != nil {
				fail(err)
				return
			}
			prev = r.sum
			all = append(all, r)
		}
	}
	var wg sync.WaitGroup
	var pmu sync.Mutex
	copies := 0
	for i, r := range v.o.Replicas {
		if !ok[i] {
			continue
		}
		wg.Add(1)
		go func(i int, r string) {
			defer wg.Done()
			err := v.writeReplica(r, tails[i], all)
			pmu.Lock()
			defer pmu.Unlock()
			if err != nil {
				problems = append(problems, r+": "+err.Error())
				return
			}
			copies++
		}(i, r)
	}
	wg.Wait()
	if copies < v.o.WriteQuorum {
		fail(fmt.Errorf("%w: %d of %d replicas stored it, %d needed (%s)", ErrNoQuorum, copies,
			len(v.o.Replicas), v.o.WriteQuorum, strings.Join(problems, "; ")))
		return
	}
	for _, g := range group {
		last := g.recs[len(g.recs)-1]
		g.rc = &Receipt{Batch: g.recs[0].Batch, FirstSeq: g.recs[0].Seq, LastSeq: last.Seq, LastSum: last.sum,
			Copies: copies, Replicas: len(v.o.Replicas)}
	}
}

// tails reads every replica's tail (only those marked in only, if given).
func (v *Vault) tails(only ...bool) ([]tail, []bool, []string) {
	tails := make([]tail, len(v.o.Replicas))
	ok := make([]bool, len(v.o.Replicas))
	var problems []string
	for i, r := range v.o.Replicas {
		if len(only) > 0 && !only[i] {
			continue
		}
		if err := v.fault(r, "tail"); err != nil {
			problems = append(problems, r+": "+err.Error())
			continue
		}
		t, err := v.readTail(r)
		if err != nil {
			problems = append(problems, r+": "+err.Error())
			continue
		}
		tails[i], ok[i] = t, true
	}
	return tails, ok, problems
}

func count(ok []bool) int {
	n := 0
	for _, b := range ok {
		if b {
			n++
		}
	}
	return n
}

func sameTails(ts []tail, ok []bool) bool {
	ref := -1
	for i, t := range ts {
		if !ok[i] {
			continue
		}
		if ref < 0 {
			ref = i
			continue
		}
		if t.empty != ts[ref].empty || t.seq != ts[ref].seq || t.sum != ts[ref].sum {
			return false
		}
	}
	return true
}

// writeReplica appends records (exactly as first written), syncs them to disk, then
// indexes them. The index is a hint: failing to write it never fails the append.
func (v *Vault) writeReplica(r string, t tail, recs []*Record) error {
	if len(recs) == 0 {
		return nil
	}
	var buf []byte
	lens := make([]int64, len(recs))
	for i, rec := range recs {
		l := rawLine(rec)
		lens[i] = int64(len(l))
		buf = append(buf, l...)
	}
	p := t.seg
	created := false
	if p == "" || t.size >= v.o.SegmentBytes {
		p, created = segName(r, recs[0].Seq), true
	}
	if err := v.fault(r, "write"); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	base := fi.Size()
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return err
	}
	if err := v.fault(r, "sync"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if created {
		if err := syncDir(segDir(r)); err != nil {
			return err
		}
	}
	_ = base
	// the index is not written per append: every indexEvery records, and before a lookup,
	// what is past its mark is indexed from the segments (in one pass, durably)
	if recs[len(recs)-1].Seq/indexEvery != (recs[0].Seq-1)/indexEvery {
		// every 1024 records: index everything past the mark again from the segments (lines
		// a crash lost come back), sync, and move the mark
		_ = v.catchUpIndex(r)
	}
	return nil
}
