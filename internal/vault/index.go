package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The index: per replica, which records belong to which task, so reading one task's
// entries reads a 256th of the index and then only that task's records. Entries are
// appended after the data is on disk and point at (segment, offset, length); every record
// read through the index is verified by its sum, and anything the index gets wrong falls
// back to reading the segments. Appends write index lines without syncing them (an index
// must not slow every change down); idx/hwm marks how far the index is known to be
// complete and durable. Before a lookup, everything past the mark is indexed again and the
// mark moved, durably; appends do the same every 1024 records. The mark never moves past a
// record without that record having been indexed again from the segments.

type idxLine struct {
	Tx  string `json:"tx"`
	Seq uint64 `json:"seq"`
	Seg string `json:"seg"`
	Off int64  `json:"off"`
	Len int64  `json:"len"`
}

func idxDir(r string) string { return filepath.Join(r, "idx") }

func shardOf(tx string) string {
	h := sha256.Sum256([]byte(tx))
	return hex.EncodeToString(h[:1])
}

func readHWM(r string) uint64 {
	b, err := os.ReadFile(filepath.Join(idxDir(r), "hwm"))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// writeIndex appends index lines. Without durable it does not sync and does not move the
// high-water mark (lines written that way may be lost in a crash; catchUpIndex re-adds
// everything past the mark). With durable it syncs every shard, then raises the mark.
func writeIndex(r string, ix []idxLine, durable bool) error {
	if len(ix) == 0 {
		return nil
	}
	if err := os.MkdirAll(idxDir(r), 0o700); err != nil {
		return err
	}
	by := map[string][]byte{}
	var top uint64
	for _, l := range ix {
		b, _ := json.Marshal(l)
		s := shardOf(l.Tx)
		by[s] = append(by[s], append(b, '\n')...)
		top = max(top, l.Seq)
	}
	for s, b := range by {
		f, err := os.OpenFile(filepath.Join(idxDir(r), s+".log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		// a line a crash cut short must not swallow the next one
		if fi, err := f.Stat(); err == nil && fi.Size() > 0 {
			last := make([]byte, 1)
			if _, err := f.ReadAt(last, fi.Size()-1); err == nil && last[0] != '\n' {
				b = append([]byte{'\n'}, b...)
			}
		}
		_, err = f.Write(b)
		f.Close()
		if err != nil {
			return err
		}
	}
	if !durable || top <= readHWM(r) {
		return nil
	}
	return checkpoint(r, top)
}

// checkpoint syncs every index shard, then records that everything up to top is indexed.
func checkpoint(r string, top uint64) error {
	es, err := os.ReadDir(idxDir(r))
	if err != nil {
		return err
	}
	for _, e := range es {
		if !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		f, err := os.OpenFile(filepath.Join(idxDir(r), e.Name()), os.O_RDWR, 0)
		if err != nil {
			return err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return err
		}
	}
	tmp := filepath.Join(idxDir(r), "hwm.tmp-"+rnd())
	if err := writeFileSync(tmp, []byte(strconv.FormatUint(top, 10))); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(idxDir(r), "hwm")); err != nil {
		return err
	}
	return syncDir(idxDir(r))
}

// catchUpIndex indexes a replica's records past its high-water mark, durably (under the lock).
func (v *Vault) catchUpIndex(r string) error {
	hwm := readHWM(r)
	var ix []idxLine
	var top uint64
	_, err := each(r, hwm, func(rec *Record, seg string, off int64) error {
		ix = append(ix, idxLine{Tx: rec.Tx, Seq: rec.Seq, Seg: filepath.Base(seg), Off: off, Len: int64(len(rawLine(rec)) - 1)})
		top = max(top, rec.Seq)
		if len(ix) >= 5000 {
			err := writeIndex(r, ix, false)
			ix = ix[:0]
			return err
		}
		return nil
	})
	if err == nil {
		err = writeIndex(r, ix, false)
	}
	if err != nil || top == 0 {
		return err
	}
	return checkpoint(r, top)
}

// lookup returns one replica's records of a task through its index. ok=false means the
// index could not answer (the caller reads the segments instead).
func (v *Vault) lookup(r, tx string) (recs []*Record, ok bool) {
	t, err := v.readTail(r)
	if err != nil {
		return nil, false
	}
	if !t.empty && readHWM(r) < t.seq {
		unlock, err := v.lock()
		if err != nil {
			return nil, false
		}
		err = v.catchUpIndex(r)
		unlock()
		if err != nil {
			return nil, false
		}
	}
	b, err := os.ReadFile(filepath.Join(idxDir(r), shardOf(tx)+".log"))
	if os.IsNotExist(err) {
		return nil, true
	}
	if err != nil {
		return nil, false
	}
	seen := map[uint64]bool{}
	for _, ln := range strings.Split(string(b), "\n") {
		var l idxLine
		if ln == "" {
			continue
		}
		if json.Unmarshal([]byte(ln), &l) != nil {
			continue // cut short by a crash; catchUpIndex re-added its record before the mark moved
		}
		if l.Tx != tx || seen[l.Seq] {
			continue
		}
		rec, err := readAt(filepath.Join(segDir(r), l.Seg), l.Off, l.Len)
		if err != nil || rec.Seq != l.Seq || rec.Tx != tx {
			return nil, false // stale index (a repair moved things): read the segments
		}
		seen[l.Seq] = true
		recs = append(recs, rec)
	}
	return recs, true
}

func readAt(p string, off, n int64) (*Record, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		return nil, err
	}
	rec, err := decode(b)
	if err != nil {
		return nil, fmt.Errorf("%s@%d: %v", p, off, err)
	}
	return rec, nil
}
