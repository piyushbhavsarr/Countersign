package vault

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// UNDOLAYER_TEST_S3=http://csadmin:cs-secret-123@127.0.0.1:59000 (MinIO, or any S3 store)
func testS3(t *testing.T) *S3 {
	raw := os.Getenv("UNDOLAYER_TEST_S3")
	if raw == "" {
		t.Skip("set UNDOLAYER_TEST_S3 to run the archive tests")
	}
	var scheme, user, pass, host string
	fmt.Sscanf(raw, "%s", &raw)
	i := bytes.Index([]byte(raw), []byte("://"))
	scheme, rest := raw[:i], raw[i+3:]
	at := bytes.IndexByte([]byte(rest), '@')
	cred, host := rest[:at], rest[at+1:]
	colon := bytes.IndexByte([]byte(cred), ':')
	user, pass = cred[:colon], cred[colon+1:]
	c := &S3{Endpoint: scheme + "://" + host, Region: "us-east-1", Bucket: fmt.Sprintf("cs-%d", time.Now().UnixNano()),
		AccessKey: user, SecretKey: pass}
	if err := c.CreateBucket(); err != nil {
		t.Fatal(err)
	}
	return c
}

// Sealed segments go to the archive, verified and locked; a lost replica is rebuilt from it
// and caught up from the others.
func TestArchiveAndRestoreAReplica(t *testing.T) {
	s3 := testS3(t)
	v, reps := open3(t, func(o *Options) {
		o.SegmentBytes = 600
		o.Archive = &Archive{S3: s3, Prefix: "vault/", LockDays: 1}
	})
	for i := 0; i < 30; i++ {
		if _, err := v.Append(entry(fmt.Sprint("t", i), 1)); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := v.ArchiveSealed()
	if err != nil {
		t.Fatal(err)
	}
	segs, _ := segments(reps[0])
	if len(rep.Uploaded) != len(segs)-1 || rep.Pending != 0 {
		t.Fatalf("uploaded %d of %d sealed segments: %+v", len(rep.Uploaded), len(segs)-1, rep)
	}
	h, err := s3.Head(rep.Uploaded[0])
	if err != nil || h.Get("x-amz-object-lock-mode") != "COMPLIANCE" {
		t.Fatalf("not locked: %v %v", err, h)
	}
	// again: nothing new is uploaded
	if rep, _ := v.ArchiveSealed(); len(rep.Uploaded) != 0 {
		t.Fatalf("uploaded twice: %v", rep.Uploaded)
	}
	// a damaged sealed segment is never archived
	for i := 30; i < 40; i++ {
		_, _ = v.Append(entry(fmt.Sprint("t", i), 1))
	}
	segs, _ = segments(reps[0])
	b, _ := os.ReadFile(segs[len(segs)-2])
	b[len(b)/2] ^= 1
	_ = os.WriteFile(segs[len(segs)-2], b, 0o600)
	if rep, err := v.ArchiveSealed(); err != nil || len(rep.Uploaded) == 0 {
		t.Fatalf("should archive from the next replica: %v %+v", err, rep)
	}
	_, _ = v.Repair()
	// replica a is lost entirely
	_ = os.RemoveAll(reps[0])
	_ = os.MkdirAll(reps[0], 0o700)
	n, err := v.RestoreReplica(reps[0])
	if err != nil || n == 0 {
		t.Fatalf("restore: %d %v", n, err)
	}
	if _, err := v.Append(entry("after", 1)); err != nil { // catches it up with the rest
		t.Fatal(err)
	}
	mustHealthy(t, v)
	if !bytes.Equal(segBytes(t, reps[0]), segBytes(t, reps[1])) {
		// segment boundaries may differ; the records must not
		var a, b2 []string
		_, _ = each(reps[0], 0, func(r *Record, _ string, _ int64) error { a = append(a, r.sum); return nil })
		_, _ = each(reps[1], 0, func(r *Record, _ string, _ int64) error { b2 = append(b2, r.sum); return nil })
		if fmt.Sprint(a) != fmt.Sprint(b2) {
			t.Fatal("restored replica holds other records")
		}
	}
	_ = filepath.Join
}

// Segments close by age when an archive is configured.
func TestSegmentsCloseByAge(t *testing.T) {
	now := time.Now()
	v, reps := open3(t, func(o *Options) {
		o.MaxSegmentAge = time.Minute
		o.Now = func() time.Time { return now }
	})
	_, _ = v.Append(entry("a", 1))
	_, _ = v.Append(entry("b", 1))
	now = now.Add(2 * time.Minute)
	_, _ = v.Append(entry("c", 1))
	if segs, _ := segments(reps[0]); len(segs) != 2 {
		t.Fatalf("segments: %d", len(segs))
	}
	mustHealthy(t, v)
}
