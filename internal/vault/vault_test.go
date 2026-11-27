package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func open3(t *testing.T, mod func(*Options)) (*Vault, []string) {
	t.Helper()
	d := t.TempDir()
	reps := []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")}
	o := Options{Replicas: append([]string{}, reps...), LockPath: filepath.Join(d, "vault.lock")}
	if mod != nil {
		mod(&o)
	}
	v, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	return v, v.Replicas()
}

func entry(tx string, n int) Entry {
	rows := make([]Row, n)
	for i := range rows {
		rows[i] = Row{Table: "customers", Op: "delete", Key: map[string]any{"id": i},
			Before: map[string]any{"id": i, "name": fmt.Sprintf("customer %d", i), "balance": 10.5 + float64(i), "note": "<&>"}}
	}
	undo, _ := json.Marshal(map[string]any{"tx": tx, "rows": n})
	return Entry{Tx: tx, Task: "clean up", Requester: "agent", Connector: "sql", Phase: "intent", Rows: rows, Undo: undo}
}

// down makes the named replicas fail every operation while the returned func is not called.
func down(v *Vault, dirs ...string) func() {
	set := map[string]bool{}
	for _, d := range dirs {
		set[d] = true
	}
	v.hook = func(r, op string) error {
		if set[r] {
			return errors.New("replica unavailable")
		}
		return nil
	}
	return func() { v.hook = nil }
}

func segBytes(t *testing.T, r string) []byte {
	t.Helper()
	segs, err := segments(r)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for _, p := range segs {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
	}
	return out
}

func mustHealthy(t *testing.T, v *Vault) *Report {
	t.Helper()
	rep := v.Check()
	if !rep.Healthy {
		b, _ := json.MarshalIndent(rep, "", " ")
		t.Fatalf("vault not healthy:\n%s", b)
	}
	return rep
}

func txRows(t *testing.T, v *Vault, tx string) []Row {
	t.Helper()
	bs, _, err := v.Batches(func(r *Record) bool { return r.Tx == tx })
	if err != nil {
		t.Fatal(err)
	}
	var out []Row
	for _, b := range bs {
		if !b.Complete {
			t.Fatalf("batch %s incomplete", b.Batch)
		}
		out = append(out, b.Rows...)
	}
	return out
}

func TestAppendReachesEveryReplicaByteForByte(t *testing.T) {
	v, reps := open3(t, nil)
	for i := 0; i < 5; i++ {
		rc, err := v.Append(entry(fmt.Sprint("tx", i), 3))
		if err != nil {
			t.Fatal(err)
		}
		if rc.Copies != 3 {
			t.Fatalf("copies %d", rc.Copies)
		}
	}
	a := segBytes(t, reps[0])
	for _, r := range reps[1:] {
		if !bytes.Equal(a, segBytes(t, r)) {
			t.Fatal("replicas differ")
		}
	}
	rep := mustHealthy(t, v)
	if rep.Chain != 5 {
		t.Fatalf("chain %d", rep.Chain)
	}
	rows := txRows(t, v, "tx3")
	if len(rows) != 3 || rows[2].Before["name"] != "customer 2" || rows[2].Before["note"] != "<&>" {
		t.Fatalf("rows %+v", rows)
	}
	if n, _ := rows[2].Before["balance"].(json.Number); n.String() != "12.5" {
		t.Fatalf("number not exact: %#v", rows[2].Before["balance"])
	}
}

func TestLargeEntriesAreSplitAndReassembled(t *testing.T) {
	v, _ := open3(t, func(o *Options) { o.PartRows, o.PartBytes, o.SegmentBytes = 7, 50, 2000 })
	e := entry("big", 100)
	e.Undo = bytes.Repeat([]byte(`{"x":"abcdefghij"}`), 40)
	if _, err := v.Append(e); err != nil {
		t.Fatal(err)
	}
	bs, _, err := v.Batches(func(r *Record) bool { return r.Tx == "big" })
	if err != nil || len(bs) != 1 {
		t.Fatalf("%v %d", err, len(bs))
	}
	if !bs[0].Complete || len(bs[0].Rows) != 100 || !bytes.Equal(bs[0].Undo, e.Undo) {
		t.Fatalf("complete=%v rows=%d undo equal=%v", bs[0].Complete, len(bs[0].Rows), bytes.Equal(bs[0].Undo, e.Undo))
	}
	for i, r := range bs[0].Rows {
		if fmt.Sprint(r.Key["id"]) != fmt.Sprint(i) {
			t.Fatalf("row %d out of order: %v", i, r.Key)
		}
	}
	for i := 0; i < 3; i++ { // a segment rolls between appends, never inside one
		if _, err := v.Append(entry(fmt.Sprint("more", i), 20)); err != nil {
			t.Fatal(err)
		}
	}
	if segs, _ := segments(v.Replicas()[0]); len(segs) < 3 {
		t.Fatalf("segments did not roll: %d", len(segs))
	}
	mustHealthy(t, v)
}

func TestOneReplicaDownThenCaughtUp(t *testing.T) {
	v, reps := open3(t, nil)
	if _, err := v.Append(entry("t1", 1)); err != nil {
		t.Fatal(err)
	}
	up := down(v, reps[2])
	for i := 0; i < 3; i++ {
		rc, err := v.Append(entry(fmt.Sprint("d", i), 2))
		if err != nil {
			t.Fatal(err)
		}
		if rc.Copies != 2 {
			t.Fatalf("copies %d", rc.Copies)
		}
	}
	up()
	if rep := v.Check(); rep.Healthy || rep.Replicas[2].Missing != 3 {
		t.Fatalf("expected replica c to miss 3 records: %+v", rep.Replicas[2])
	}
	if _, err := v.Append(entry("t2", 1)); err != nil { // catches c up first
		t.Fatal(err)
	}
	mustHealthy(t, v)
	if !bytes.Equal(segBytes(t, reps[0]), segBytes(t, reps[2])) {
		t.Fatal("caught-up replica differs")
	}
}

func TestNoQuorumMeansNoAcknowledgement(t *testing.T) {
	v, reps := open3(t, nil)
	up := down(v, reps[1], reps[2])
	_, err := v.Append(entry("lost", 1))
	if !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("want ErrNoQuorum, got %v", err)
	}
	up()
	// a write that reaches one replica only (two fail at write time) is not acknowledged
	v.hook = func(r, op string) error {
		if op == "write" && r != reps[0] {
			return errors.New("disk full")
		}
		return nil
	}
	if _, err := v.Append(entry("half", 1)); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("want ErrNoQuorum, got %v", err)
	}
	v.hook = nil
	// the unacknowledged record is harmless: it is kept and readable, and the vault heals
	if _, err := v.Append(entry("next", 1)); err != nil {
		t.Fatal(err)
	}
	mustHealthy(t, v)
	if len(txRows(t, v, "next")) != 1 || len(txRows(t, v, "half")) != 1 {
		t.Fatal("records missing")
	}
}

func TestTornTailIsKeptAsideAndHealed(t *testing.T) {
	v, reps := open3(t, nil)
	if _, err := v.Append(entry("t1", 2)); err != nil {
		t.Fatal(err)
	}
	segs, _ := segments(reps[1])
	f, _ := os.OpenFile(segs[len(segs)-1], os.O_WRONLY|os.O_APPEND, 0)
	_, _ = f.Write([]byte(`{"sum":"abc","rec":{"seq":2,"tx":"tor`)) // crash mid-write
	f.Close()
	if _, err := v.Append(entry("t2", 2)); err != nil {
		t.Fatal(err)
	}
	mustHealthy(t, v)
	es, _ := os.ReadDir(orphanDir(reps[1]))
	found := false
	for _, e := range es {
		b, _ := os.ReadFile(filepath.Join(orphanDir(reps[1]), e.Name()))
		found = found || strings.HasPrefix(e.Name(), "torn-") && bytes.Contains(b, []byte(`"tx":"tor`))
	}
	if !found {
		t.Fatal("torn bytes were not kept")
	}
}

func TestBitRotIsDetectedAndRepairedWithoutLoss(t *testing.T) {
	v, reps := open3(t, nil)
	for i := 0; i < 4; i++ {
		if _, err := v.Append(entry(fmt.Sprint("r", i), 2)); err != nil {
			t.Fatal(err)
		}
	}
	segs, _ := segments(reps[0])
	b, _ := os.ReadFile(segs[0])
	i := bytes.Index(b, []byte("customer 1"))
	b[i] = 'X' // one flipped byte inside the first record
	_ = os.WriteFile(segs[0], b, 0o600)
	rep := v.Check()
	if rep.Healthy || rep.Replicas[0].BadLines != 1 {
		t.Fatalf("rot not detected: %+v", rep.Replicas[0])
	}
	if len(txRows(t, v, "r0")) != 2 { // still readable from the other replicas
		t.Fatal("record unreadable")
	}
	if _, err := v.Repair(); err != nil {
		t.Fatal(err)
	}
	mustHealthy(t, v)
	if !bytes.Equal(segBytes(t, reps[0]), segBytes(t, reps[1])) {
		t.Fatal("repaired replica differs")
	}
}

func TestDivergedReplicaIsRewrittenAndItsRecordsKept(t *testing.T) {
	v, reps := open3(t, nil)
	if _, err := v.Append(entry("base", 1)); err != nil {
		t.Fatal(err)
	}
	// x = replica a gets a record nobody else does (the writer then lost its quorum)
	v.hook = func(r, op string) error {
		if op == "write" && r != reps[0] {
			return errors.New("network partition")
		}
		return nil
	}
	if _, err := v.Append(entry("unacked", 1)); !errors.Is(err, ErrNoQuorum) {
		t.Fatal(err)
	}
	// a goes away; b and c accept a different record at the same sequence number
	up := down(v, reps[0])
	if _, err := v.Append(entry("acked", 1)); err != nil {
		t.Fatal(err)
	}
	up()
	// a is back: the next write reconciles it with the majority chain first
	if _, err := v.Append(entry("after", 1)); err != nil {
		t.Fatal(err)
	}
	rep := mustHealthy(t, v)
	if rep.Chain != 3 {
		t.Fatalf("chain %d", rep.Chain)
	}
	for _, tx := range []string{"base", "unacked", "acked", "after"} {
		if len(txRows(t, v, tx)) != 1 {
			t.Fatalf("%s lost", tx)
		}
	}
	if rep.Replicas[0].Orphans != 1 {
		t.Fatalf("diverged record not kept in orphans: %+v", rep.Replicas[0])
	}
}

func TestConcurrentWritersInSeveralProcessesKeepOneChain(t *testing.T) {
	v, reps := open3(t, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for w := 0; w < 6; w++ {
		// each writer opens its own vault, as a separate process would
		vw, err := Open(Options{Replicas: append([]string{}, reps...), LockPath: v.o.LockPath})
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(w int, vw *Vault) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if _, err := vw.Append(entry(fmt.Sprintf("w%d-%d", w, i), 1)); err != nil {
					errs <- err
				}
			}
		}(w, vw)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	rep := mustHealthy(t, v)
	if rep.Chain != 150 || rep.Records != 150 {
		t.Fatalf("chain %d records %d", rep.Chain, rep.Records)
	}
}

func TestCrashDuringRepairSwapIsFinishedOnOpen(t *testing.T) {
	v, reps := open3(t, nil)
	if _, err := v.Append(entry("t", 1)); err != nil {
		t.Fatal(err)
	}
	r := reps[0]
	want := segBytes(t, r)
	// crash after seg -> seg.old, before seg.new -> seg
	if err := os.Rename(segDir(r), segDir(r)+".new"); err != nil {
		t.Fatal(err)
	}
	v2, err := Open(Options{Replicas: append([]string{}, reps...), LockPath: v.o.LockPath})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(segBytes(t, r), want) {
		t.Fatal("swap not finished")
	}
	mustHealthy(t, v2)
}

func TestQuorumMustBeAMajority(t *testing.T) {
	d := t.TempDir()
	for _, c := range []struct {
		n, w int
		ok   bool
	}{{3, 1, false}, {3, 2, true}, {3, 3, true}, {4, 2, false}, {4, 3, true}, {1, 1, true}, {2, 1, false}} {
		var reps []string
		for i := 0; i < c.n; i++ {
			reps = append(reps, filepath.Join(d, fmt.Sprint(c.n, c.w, i)))
		}
		_, err := Open(Options{Replicas: reps, WriteQuorum: c.w, LockPath: filepath.Join(d, "l")})
		if (err == nil) != c.ok {
			t.Fatalf("n=%d w=%d: %v", c.n, c.w, err)
		}
	}
	if _, err := Open(Options{Replicas: []string{d, d}, LockPath: filepath.Join(d, "l")}); err == nil {
		t.Fatal("accepted the same replica twice")
	}
}

func TestEveryReplicaGoneMeansNoAppend(t *testing.T) {
	v, reps := open3(t, nil)
	up := down(v, reps...)
	defer up()
	if _, err := v.Append(entry("x", 1)); !errors.Is(err, ErrNoQuorum) {
		t.Fatal(err)
	}
	if _, err := v.Scan(func(*Record) error { return nil }); err == nil {
		t.Fatal("scan with no readable replica should fail")
	}
}
