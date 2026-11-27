package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openKeyed(t *testing.T) (*Vault, []string, string) {
	t.Helper()
	kp := filepath.Join(t.TempDir(), "keys", "vault.keys")
	k, err := OpenKeyring(kp)
	if err != nil {
		t.Fatal(err)
	}
	v, reps := open3(t, func(o *Options) { o.Keys = k })
	return v, reps, kp
}

// Content is sealed on disk, opened on read, and gone everywhere once its key is shredded;
// the replicas stay checkable and repairable without the key.
func TestSealedContentAndCryptoShredding(t *testing.T) {
	v, reps, kp := openKeyed(t)
	if _, err := v.Append(entry("old", 3)); err != nil {
		t.Fatal(err)
	}
	for _, r := range reps {
		if bytes.Contains(segBytes(t, r), []byte("customer 1")) {
			t.Fatal("content stored in the clear")
		}
	}
	if rows := txRows(t, v, "old"); len(rows) != 3 || rows[1].Before["name"] != "customer 1" {
		t.Fatalf("unsealed rows %+v", rows)
	}
	oldKey := v.Keys().Info().Active
	newKey, err := v.Keys().Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Append(entry("new", 2)); err != nil {
		t.Fatal(err)
	}
	if err := v.Keys().Shred(oldKey); err != nil {
		t.Fatal(err)
	}
	// a fresh process with the keyring file sees the shred too
	k2, err := OpenKeyring(kp)
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := Open(Options{Replicas: reps, LockPath: v.o.LockPath, Keys: k2})
	bs, err := v2.ForTx("old")
	if err != nil || len(bs) != 1 || !bs[0].Shredded || len(bs[0].Rows) != 0 {
		t.Fatalf("shredded entry: %v %+v", err, bs)
	}
	if bs, _ := v2.ForTx("new"); len(bs) != 1 || len(bs[0].Rows) != 2 || bs[0].Error != "" {
		t.Fatalf("entry under %s: %+v", newKey, bs)
	}
	mustHealthy(t, v2)                                        // checking needs no key
	if err := v2.Keys().Shred(k2.Info().Active); err != nil { // the active key: a new one replaces it
		t.Fatal(err)
	}
	if _, err := v2.Append(entry("after", 1)); err != nil {
		t.Fatal(err)
	}
}

// A sealed record moved under another task's name does not open.
func TestSealedContentIsBoundToItsRecord(t *testing.T) {
	v, _, _ := openKeyed(t)
	e := entry("a", 1)
	recs, err := v.split(e, "b1", 1)
	if err != nil {
		t.Fatal(err)
	}
	recs[0].Tx = "someone-else"
	if _, err := v.unseal(recs[0]); err == nil {
		t.Fatal("sealed content opened under another record's identity")
	}
}

// Reading one task goes through the index; a crash between data and index, a stale index
// after a repair, and a deleted index all still give the right answer.
func TestIndexFindsATaskAndRecoversFromEveryGap(t *testing.T) {
	v, reps := open3(t, nil)
	for i := 0; i < 50; i++ {
		if _, err := v.Append(entry(fmt.Sprint("t", i), 2)); err != nil {
			t.Fatal(err)
		}
	}
	check := func(why string) {
		t.Helper()
		for _, tx := range []string{"t0", "t17", "t49"} {
			bs, err := v.ForTx(tx)
			if err != nil || len(bs) != 1 || len(bs[0].Rows) != 2 || bs[0].Tx != tx {
				t.Fatalf("%s: %s: %v %+v", why, tx, err, bs)
			}
		}
		if bs, _ := v.ForTx("nope"); len(bs) != 0 {
			t.Fatalf("%s: found a task that does not exist", why)
		}
	}
	check("indexed")
	// lines written after the mark and lost in a crash come back at the next checkpoint
	oldEvery := indexEvery
	indexEvery = 16
	defer func() { indexEvery = oldEvery }()
	if _, err := v.Append(entry("lost-line", 1)); err != nil { // seq 51, past the mark (50)
		t.Fatal(err)
	}
	for _, r := range reps {
		p := filepath.Join(idxDir(r), shardOf("lost-line")+".log")
		b, _ := os.ReadFile(p)
		_ = os.WriteFile(p, bytes.ReplaceAll(b, []byte(`"tx":"lost-line"`), []byte(`"tx":"x`)), 0o600) // not on disk
	}
	for i := 50; i < 70; i++ { // crosses seq 64, a checkpoint
		if _, err := v.Append(entry(fmt.Sprint("t", i), 1)); err != nil {
			t.Fatal(err)
		}
	}
	if readHWM(reps[1]) < 64 {
		t.Fatalf("no checkpoint: %d", readHWM(reps[1]))
	}
	if bs, _ := v.ForTx("lost-line"); len(bs) != 1 {
		t.Fatal("a checkpoint moved the mark past lines a crash lost")
	}

	// crash between the data and its index: index lines past seq 10 never reached the disk
	for _, r := range reps {
		es, _ := os.ReadDir(idxDir(r))
		for _, e := range es {
			if !strings.HasSuffix(e.Name(), ".log") {
				continue
			}
			p := filepath.Join(idxDir(r), e.Name())
			b, _ := os.ReadFile(p)
			var keep []string
			for _, ln := range strings.Split(string(b), "\n") {
				var l idxLine
				if json.Unmarshal([]byte(ln), &l) == nil && l.Seq <= 10 {
					keep = append(keep, ln)
				}
			}
			_ = os.WriteFile(p, []byte(strings.Join(keep, "\n")+"\n"+`{"tx":"t4`), 0o600) // and a torn last line
		}
		_ = os.WriteFile(filepath.Join(idxDir(r), "hwm"), []byte("10"), 0o600)
	}
	check("index behind")
	// an index that points at the wrong place falls back to the segments
	for _, r := range reps {
		p := filepath.Join(idxDir(r), shardOf("t17")+".log")
		_ = os.WriteFile(p, []byte(`{"tx":"t17","seq":36,"seg":"00000000000000000001.log","off":3,"len":40}`+"\n"), 0o600)
	}
	check("index wrong")
	// no index at all
	for _, r := range reps {
		_ = os.RemoveAll(idxDir(r))
	}
	check("no index")
}

// A replica far behind is caught up in bounded batches, byte for byte.
func TestFarBehindReplicaIsStreamedBack(t *testing.T) {
	v, reps := open3(t, nil)
	old := catchUpBatch
	catchUpBatch = 7
	defer func() { catchUpBatch = old }()
	up := down(v, reps[2])
	for i := 0; i < 40; i++ {
		if _, err := v.Append(entry(fmt.Sprint("x", i), 1)); err != nil {
			t.Fatal(err)
		}
	}
	up()
	if _, err := v.Append(entry("last", 1)); err != nil {
		t.Fatal(err)
	}
	mustHealthy(t, v)
	if !bytes.Equal(segBytes(t, reps[0]), segBytes(t, reps[2])) {
		t.Fatal("caught-up replica differs")
	}
}

// Rows are split by bytes as well as by count, so one record stays small.
func TestRecordsAreBoundedInBytes(t *testing.T) {
	v, _ := open3(t, func(o *Options) { o.PartBytes = 4096 })
	e := entry("wide", 40)
	for i := range e.Rows {
		e.Rows[i].Before["blob"] = string(bytes.Repeat([]byte("z"), 1000))
	}
	recs, err := v.split(e, "b", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) < 10 {
		t.Fatalf("parts %d", len(recs))
	}
	if _, err := v.Append(e); err != nil {
		t.Fatal(err)
	}
	if rows := txRows(t, v, "wide"); len(rows) != 40 {
		t.Fatalf("rows %d", len(rows))
	}
}

// Replicas on one disk are reported, and refused when independence is required.
func TestReplicasOnOneDeviceAreReported(t *testing.T) {
	v, _ := open3(t, nil)
	if len(v.SharedDevices()) != 1 || len(v.SharedDevices()[0]) != 3 || len(v.Check().SharedDevices) != 1 {
		t.Fatalf("shared devices: %v", v.SharedDevices())
	}
	d := t.TempDir()
	_, err := Open(Options{Replicas: []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")},
		LockPath: filepath.Join(d, "l"), RequireIndependent: true})
	if err == nil {
		t.Fatal("replicas on one device accepted")
	}
}

// Shredding keeps nothing readable even through orphans, and a missing keyring is an error
// a reader sees, not silent empty data.
func TestSealedWithoutKeyringIsReported(t *testing.T) {
	v, reps, _ := openKeyed(t)
	if _, err := v.Append(entry("s", 1)); err != nil {
		t.Fatal(err)
	}
	plain, _ := Open(Options{Replicas: reps, LockPath: v.o.LockPath})
	bs, err := plain.ForTx("s")
	if err != nil || len(bs) != 1 || bs[0].Error == "" || bs[0].Shredded {
		t.Fatalf("%v %+v", err, bs)
	}
	_ = errors.New
}
