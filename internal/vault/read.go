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
)

// ReplicaState is what one replica holds.
type ReplicaState struct {
	Dir       string `json:"dir"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
	Records   int    `json:"records"`
	Orphans   int    `json:"orphans"`
	BadLines  int    `json:"bad_lines"`
	LastSeq   uint64 `json:"last_seq"`
	// Missing: records of the agreed chain this replica does not hold in its segments.
	Missing int `json:"missing"`
	// Extra: records in its segments that are not part of the agreed chain.
	Extra int `json:"extra"`
}

// Report is the state of the whole vault.
type Report struct {
	Replicas []ReplicaState `json:"replicas"`
	Records  int            `json:"records"` // distinct valid records anywhere
	Chain    int            `json:"chain"`   // records in the agreed chain
	// Breaks: places where the agreed chain stops short of records that exist (a record
	// whose predecessor is missing everywhere).
	Breaks []uint64 `json:"breaks,omitempty"`
	// UnderReplicated: records of the chain held by fewer than WriteQuorum replicas.
	UnderReplicated int `json:"under_replicated"`
	// SharedDevices: replicas on the same device (they would be lost together).
	SharedDevices [][]string `json:"shared_devices,omitempty"`
	Encrypted     bool       `json:"encrypted"`
	Healthy       bool       `json:"healthy"`
}

// loc is where one copy of a record is.
type loc struct {
	rep  int
	path string
	off  int64
	n    int64
}

// meta is what is kept of a record while reading the whole vault: not its content.
type meta struct {
	seq  uint64
	prev string
	sum  string
	locs []loc
}

type gathered struct {
	all    map[string]*meta
	held   map[string]map[int]bool // sum -> replicas holding it in segments
	bySeq  map[uint64][]string
	order  [][]string // per replica: sums in segment order
	states []ReplicaState
}

// gather reads every replica (segments and orphans), keeping only each record's identity
// and where its copies are, so memory grows with the number of records, not their size.
func (v *Vault) gather() *gathered {
	g := &gathered{all: map[string]*meta{}, held: map[string]map[int]bool{}, bySeq: map[uint64][]string{}}
	for i, r := range v.o.Replicas {
		st := ReplicaState{Dir: r}
		var order []string
		add := func(rec *Record, l loc) {
			m := g.all[rec.sum]
			if m == nil {
				m = &meta{seq: rec.Seq, prev: rec.Prev, sum: rec.sum}
				g.all[rec.sum] = m
				g.bySeq[rec.Seq] = append(g.bySeq[rec.Seq], rec.sum)
			}
			m.locs = append(m.locs, l)
		}
		err := v.fault(r, "read")
		if err == nil {
			if _, e := os.Stat(segDir(r)); e != nil {
				err = e
			}
		}
		if err == nil {
			st.BadLines, err = each(r, 0, func(rec *Record, seg string, off int64) error {
				add(rec, loc{i, seg, off, int64(len(rawLine(rec)) - 1)})
				order = append(order, rec.sum)
				if g.held[rec.sum] == nil {
					g.held[rec.sum] = map[int]bool{}
				}
				g.held[rec.sum][i] = true
				st.Records++
				st.LastSeq = max(st.LastSeq, rec.Seq)
				return nil
			})
		}
		if err == nil {
			err = eachOrphan(r, func(rec *Record, p string, off int64) {
				add(rec, loc{i, p, off, int64(len(rawLine(rec)) - 1)})
				st.Orphans++
			})
		}
		if err != nil {
			st.Error = err.Error()
		} else {
			st.Reachable = true
		}
		g.order = append(g.order, order)
		g.states = append(g.states, st)
	}
	return g
}

func eachOrphan(r string, fn func(rec *Record, p string, off int64)) error {
	es, err := os.ReadDir(orphanDir(r))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range es {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		p := filepath.Join(orphanDir(r), e.Name())
		if _, err := scanLines(p, func(off int64, l []byte) error {
			rec, err := decode(l)
			if err != nil {
				return errBad
			}
			fn(rec, p, off)
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// fetch reads a record from the first of its copies that is intact.
func (g *gathered) fetch(m *meta) (*Record, error) {
	var last error
	for _, l := range m.locs {
		rec, err := readAt(l.path, l.off, l.n)
		if err == nil && rec.sum == m.sum {
			return rec, nil
		}
		last = err
	}
	return nil, fmt.Errorf("record %d (%s) unreadable everywhere: %v", m.seq, m.sum[:12], last)
}

// chain picks the agreed chain from the records held in segments: starting from sequence
// 1, each next record is one whose prev is the record chosen before it, and among those the
// one held by the most replicas (then the smaller sum). Records not chosen are kept and
// still read; they are only out of the chain.
func (g *gathered) chain() []*meta {
	var out []*meta
	prev := ""
	for s := uint64(1); ; s++ {
		var best string
		for _, sum := range g.bySeq[s] {
			if len(g.held[sum]) == 0 || g.all[sum].prev != prev {
				continue
			}
			if best == "" || len(g.held[sum]) > len(g.held[best]) || (len(g.held[sum]) == len(g.held[best]) && sum < best) {
				best = sum
			}
		}
		if best == "" {
			return out
		}
		out = append(out, g.all[best])
		prev = best
	}
}

// Check reports what every replica holds, without changing anything.
func (v *Vault) Check() *Report {
	g := v.gather()
	ch := g.chain()
	rep := &Report{Records: len(g.all), Chain: len(ch), SharedDevices: v.shared, Encrypted: v.o.Keys != nil}
	inChain := map[string]bool{}
	for _, m := range ch {
		inChain[m.sum] = true
		if len(g.held[m.sum]) < v.o.WriteQuorum {
			rep.UnderReplicated++
		}
	}
	top := uint64(len(ch))
	for s, sums := range g.bySeq {
		for _, sum := range sums {
			if s > top+1 && len(g.held[sum]) > 0 && !inChain[sum] {
				rep.Breaks = append(rep.Breaks, s)
			}
		}
	}
	sort.Slice(rep.Breaks, func(i, j int) bool { return rep.Breaks[i] < rep.Breaks[j] })
	for i := range g.states {
		st := &g.states[i]
		if !st.Reachable {
			continue
		}
		mine := map[string]bool{}
		for _, s := range g.order[i] {
			mine[s] = true
			if !inChain[s] {
				st.Extra++
			}
		}
		for _, m := range ch {
			if !mine[m.sum] {
				st.Missing++
			}
		}
	}
	rep.Replicas = g.states
	rep.Healthy = len(rep.Breaks) == 0 && rep.UnderReplicated == 0
	for _, st := range g.states {
		rep.Healthy = rep.Healthy && st.Reachable && st.Missing == 0 && st.Extra == 0 && st.BadLines == 0
	}
	return rep
}

// Repair brings every reachable replica in line with the agreed chain: a replica that only
// missed records gets them appended; one that holds anything else is rewritten. Records
// that are not part of the chain, and lines that are no longer valid, are kept in the
// replica's orphans directory first: repair removes nothing.
func (v *Vault) Repair() (*Report, error) {
	unlock, err := v.lock()
	if err != nil {
		return nil, err
	}
	_, ok, _ := v.tails()
	err = v.reconcileLocked(ok, true)
	unlock()
	return v.Check(), err
}

var catchUpBatch = 2000 // records per catch-up write (a var for tests)

// reconcileLocked brings the replicas marked ok in line. Without force it first tries the
// cheap case: every replica's chain is a prefix of the longest one, so the ones behind
// are streamed what they miss. Otherwise (or with force, which also repairs damage in the
// middle of segments) it reads the whole vault's identities and rewrites what differs.
func (v *Vault) reconcileLocked(ok []bool, force bool) error {
	if !force && v.catchUpPrefix(ok) == nil {
		return nil
	}
	g := v.gather()
	ch := g.chain()
	inChain := map[string]bool{}
	for _, m := range ch {
		inChain[m.sum] = true
	}
	var problems []string
	for i, r := range v.o.Replicas {
		if !ok[i] || !g.states[i].Reachable {
			continue
		}
		have := g.order[i]
		prefix := g.states[i].BadLines == 0 && len(have) <= len(ch)
		for k := 0; prefix && k < len(have); k++ {
			prefix = have[k] == ch[k].sum
		}
		var err error
		switch {
		case prefix && len(have) == len(ch):
			continue
		case prefix:
			err = v.appendFrom(r, g, ch[len(have):])
		default:
			err = v.rewrite(r, g, ch, inChain)
		}
		if err != nil {
			problems = append(problems, r+": "+err.Error())
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("vault repair: %v", problems)
	}
	return nil
}

var errNotPrefix = errors.New("replicas diverged")

// catchUpPrefix: when every reachable replica's last record is the longest replica's
// record at that sequence number, stream the missing records to the ones behind, in
// batches (memory stays bounded however far behind they are).
func (v *Vault) catchUpPrefix(ok []bool) error {
	tails, ok2, _ := v.tails(ok...)
	src := -1
	for i := range tails {
		if ok2[i] && (src < 0 || tails[i].seq > tails[src].seq) {
			src = i
		}
	}
	if src < 0 {
		return nil
	}
	for i, t := range tails {
		if !ok2[i] || i == src || t.empty {
			continue
		}
		at, err := recordAt(v.o.Replicas[src], t.seq)
		if err != nil || at == nil || at.sum != t.sum {
			return errNotPrefix
		}
	}
	for i, t := range tails {
		if !ok2[i] || i == src || (t.seq == tails[src].seq && !t.empty) {
			continue
		}
		r := v.o.Replicas[i]
		var batch []*Record
		size := 0
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			cur, err := v.readTail(r)
			if err != nil {
				return err
			}
			err = v.writeReplica(r, cur, batch)
			batch, size = nil, 0
			return err
		}
		if _, err := each(v.o.Replicas[src], t.seq, func(rec *Record, _ string, _ int64) error {
			batch = append(batch, rec)
			size += len(rec.raw)
			if len(batch) >= catchUpBatch || size >= 16<<20 {
				return flush()
			}
			return nil
		}); err != nil {
			return err
		}
		if err := flush(); err != nil {
			return err
		}
	}
	return nil
}

// appendFrom streams chain records to a replica that holds a prefix of the chain.
func (v *Vault) appendFrom(r string, g *gathered, ms []*meta) error {
	for i := 0; i < len(ms); i += catchUpBatch {
		var batch []*Record
		for _, m := range ms[i:min(i+catchUpBatch, len(ms))] {
			rec, err := g.fetch(m)
			if err != nil {
				return err
			}
			batch = append(batch, rec)
		}
		cur, err := v.readTail(r)
		if err != nil {
			return err
		}
		if err := v.writeReplica(r, cur, batch); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) rewrite(r string, g *gathered, ch []*meta, inChain map[string]bool) error {
	if err := v.fault(r, "write"); err != nil {
		return err
	}
	// 1. keep what is not in the agreed chain, and every invalid line, in orphans
	segs, err := segments(r)
	if err != nil {
		return err
	}
	var keep []byte
	for _, p := range segs {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var bad []byte
		for _, l := range bytes.SplitAfter(b, []byte("\n")) {
			if len(l) == 0 {
				continue
			}
			if l[len(l)-1] != '\n' {
				bad = append(bad, l...)
				continue
			}
			rec, err := decode(l[:len(l)-1])
			switch {
			case err != nil:
				bad = append(bad, l...)
			case !inChain[rec.sum]:
				keep = append(keep, l...)
			}
		}
		if err := v.moveAside(r, "invalid", bad); err != nil {
			return err
		}
	}
	if len(keep) > 0 {
		p := filepath.Join(orphanDir(r), fmt.Sprintf("diverged-%d-%s.log", v.o.Now().UnixNano(), rnd()))
		if err := writeFileSync(p, keep); err != nil {
			return err
		}
		if err := syncDir(orphanDir(r)); err != nil {
			return err
		}
	}
	// 2. write the agreed chain into new segments, one record at a time
	next := segDir(r) + ".new"
	if err := os.RemoveAll(next); err != nil {
		return err
	}
	if err := os.MkdirAll(next, 0o700); err != nil {
		return err
	}
	var cur *os.File
	var size int64
	closeCur := func() error {
		if cur == nil {
			return nil
		}
		if err := cur.Sync(); err != nil {
			cur.Close()
			return err
		}
		err := cur.Close()
		cur = nil
		return err
	}
	for _, m := range ch {
		rec, err := g.fetch(m)
		if err != nil {
			if cur != nil {
				cur.Close()
			}
			return err
		}
		if cur == nil || size >= v.o.SegmentBytes {
			if err := closeCur(); err != nil {
				return err
			}
			f, err := os.OpenFile(filepath.Join(next, fmt.Sprintf("%020d.log", rec.Seq)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			cur, size = f, 0
		}
		l := rawLine(rec)
		if _, err := cur.Write(l); err != nil {
			cur.Close()
			return err
		}
		size += int64(len(l))
	}
	if err := closeCur(); err != nil {
		return err
	}
	if err := syncDir(next); err != nil {
		return err
	}
	// 3. swap: seg -> seg.old, seg.new -> seg (prepare finishes this after a crash); the
	// index pointed into the old segments, so it is rebuilt
	old := segDir(r) + ".old"
	if err := os.RemoveAll(old); err != nil {
		return err
	}
	if err := os.Rename(segDir(r), old); err != nil {
		return err
	}
	if err := os.Rename(next, segDir(r)); err != nil {
		return err
	}
	if err := os.RemoveAll(idxDir(r)); err != nil {
		return err
	}
	if err := syncDir(r); err != nil {
		return err
	}
	return os.RemoveAll(old)
}

// Scan calls fn for every distinct valid record in the vault, in sequence order: the
// agreed chain and every orphan, from every reachable replica.
func (v *Vault) Scan(fn func(*Record) error) (*Report, error) {
	g := v.gather()
	ms := make([]*meta, 0, len(g.all))
	for _, m := range g.all {
		ms = append(ms, m)
	}
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].seq != ms[j].seq {
			return ms[i].seq < ms[j].seq
		}
		return ms[i].sum < ms[j].sum
	})
	reachable := 0
	for _, st := range g.states {
		if st.Reachable {
			reachable++
		}
	}
	rep := &Report{Records: len(g.all), Replicas: g.states, SharedDevices: v.shared, Encrypted: v.o.Keys != nil}
	if reachable == 0 {
		return rep, fmt.Errorf("vault: no replica is readable")
	}
	for _, m := range ms {
		rec, err := g.fetch(m)
		if err != nil {
			continue // changed on disk since it was read: the next check reports it
		}
		if err := fn(rec); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

// Batch is one entry as read back.
type Batch struct {
	Batch     string  `json:"batch"`
	Tx        string  `json:"tx"`
	Task      string  `json:"task,omitempty"`
	Requester string  `json:"requester,omitempty"`
	Connector string  `json:"connector"`
	Phase     string  `json:"phase"`
	Ref       string  `json:"ref,omitempty"`
	TS        float64 `json:"ts"`
	FirstSeq  uint64  `json:"first_seq"`
	Rows      []Row   `json:"rows"`
	Undo      []byte  `json:"-"`
	// Complete: every part was found.
	Complete bool `json:"complete"`
	// Shredded: its key was destroyed on purpose; the content is gone everywhere.
	Shredded bool `json:"shredded,omitempty"`
	// Error: the content could not be opened (a missing key, a tampered record).
	Error string `json:"error,omitempty"`
	parts map[int]*Record
}

// Batches returns the entries that match (nil matches all), in the order they were stored,
// reading the whole vault.
func (v *Vault) Batches(match func(*Record) bool) ([]*Batch, *Report, error) {
	var recs []*Record
	rep, err := v.Scan(func(r *Record) error {
		if match == nil || match(r) {
			recs = append(recs, r)
		}
		return nil
	})
	if err != nil {
		return nil, rep, err
	}
	return v.assemble(recs), rep, nil
}

// ForTx returns one task's entries through each replica's index (falling back to its
// segments where the index cannot answer), plus any kept in orphans.
func (v *Vault) ForTx(tx string) ([]*Batch, error) {
	seen := map[string]bool{}
	var recs []*Record
	add := func(r *Record) {
		if r.Tx == tx && !seen[r.sum] {
			seen[r.sum] = true
			recs = append(recs, r)
		}
	}
	readable := 0
	for _, r := range v.o.Replicas {
		if v.fault(r, "read") != nil {
			continue
		}
		if _, err := os.Stat(segDir(r)); err != nil {
			continue
		}
		readable++
		if found, ok := v.lookup(r, tx); ok {
			for _, rec := range found {
				add(rec)
			}
		} else if _, err := each(r, 0, func(rec *Record, _ string, _ int64) error { add(rec); return nil }); err != nil {
			continue
		}
		_ = eachOrphan(r, func(rec *Record, _ string, _ int64) { add(rec) })
	}
	if readable == 0 {
		return nil, fmt.Errorf("vault: no replica is readable")
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Seq < recs[j].Seq })
	return v.assemble(recs), nil
}

// assemble groups records into entries, opening sealed content.
func (v *Vault) assemble(recs []*Record) []*Batch {
	byID := map[string]*Batch{}
	var order []*Batch
	for _, r := range recs {
		b := byID[r.Batch]
		if b == nil {
			b = &Batch{Batch: r.Batch, Tx: r.Tx, Task: r.Task, Requester: r.Requester, Connector: r.Connector,
				Phase: r.Phase, Ref: r.Ref, TS: r.TS, FirstSeq: r.Seq, parts: map[int]*Record{}}
			byID[r.Batch] = b
			order = append(order, b)
		}
		if b.parts[r.Part] == nil || r.Seq < b.parts[r.Part].Seq {
			b.parts[r.Part] = r
		}
		b.FirstSeq = min(b.FirstSeq, r.Seq)
	}
	for _, b := range order {
		n := 0
		for _, p := range b.parts {
			n = p.Parts
			break
		}
		b.Complete = len(b.parts) == n
		b.Rows = []Row{}
		if b.Complete {
			for i := 0; i < n; i++ {
				p := b.parts[i]
				rows, undo := p.Rows, p.Undo
				if p.Sealed != nil {
					body, err := v.unseal(p)
					if err != nil {
						b.Shredded = errors.Is(err, ErrShredded)
						b.Error = err.Error()
						b.Rows, b.Undo = []Row{}, nil
						break
					}
					rows, undo = body.Rows, body.Undo
					if body.Task != "" {
						b.Task = body.Task
					}
				}
				b.Rows = append(b.Rows, rows...)
				b.Undo = append(b.Undo, undo...)
			}
		}
		b.parts = nil
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].FirstSeq < order[j].FirstSeq })
	return order
}

func (v *Vault) unseal(r *Record) (*sealedBody, error) {
	if v.o.Keys == nil {
		return nil, fmt.Errorf("vault: record %d is sealed and no keyring is configured", r.Seq)
	}
	plain, err := v.o.Keys.open(r.Key, aad(r), r.Sealed)
	if err != nil {
		if errors.Is(err, ErrShredded) {
			return nil, err
		}
		return nil, fmt.Errorf("vault: record %d cannot be opened: %v", r.Seq, err)
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.UseNumber()
	var body sealedBody
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}
	return &body, nil
}
