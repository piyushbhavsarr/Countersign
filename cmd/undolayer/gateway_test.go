package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// From the shipped binary: undolayer gateway in front of PostgreSQL; an application writes
// through it; the operator lists, undoes and restores the gateway transaction.
func TestGatewayFromTheCLI(t *testing.T) {
	base := os.Getenv("UNDOLAYER_TEST_PG")
	if base == "" {
		t.Skip("set UNDOLAYER_TEST_PG")
	}
	f := newFixture(t, 1)
	dsn := pgOrders(t, base, 50)
	if out, err := exec.Command(f.bin, "pg", "install", "-c", pgConfig(t, f, dsn)).CombinedOutput(); err != nil {
		t.Fatalf("pg install: %v %s", err, out)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	b, _ := os.ReadFile(f.cfg)
	cfg := string(b) + fmt.Sprintf("\n[[pg_gateway]]\nname = \"main\"\nlisten = %q\nprimary = %q\ntrust = true\n", addr, dsn)
	_ = os.WriteFile(f.cfg, []byte(cfg), 0o644)
	gw := exec.Command(f.bin, "gateway", "-c", f.cfg)
	stderr, _ := gw.StderrPipe()
	if err := gw.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "countersign gateway main") {
				ready <- true
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("gateway did not start")
	}
	ctx := context.Background()
	db := dsn[strings.LastIndex(dsn, "/")+1:]
	c, err := pgx.Connect(ctx, fmt.Sprintf("postgres://app@%s/%s?sslmode=disable", addr, db))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, "DELETE FROM orders WHERE id IN (1, 2)"); err != nil {
		t.Fatal(err)
	}
	c.Close(ctx)
	_ = gw.Process.Signal(syscall.SIGTERM)
	_ = gw.Wait()
	// the gateway transaction, from the audit chain
	var txID string
	af, _ := os.ReadFile(filepath.Join(filepath.Dir(f.cfg), "state", "audit.jsonl"))
	for _, ln := range strings.Split(string(af), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(ln), &r) == nil && r["event"] == "gateway_commit" {
			txID = fmt.Sprint(r["tx"])
		}
	}
	if txID == "" {
		t.Fatalf("no gateway commit in the audit chain:\n%s", af)
	}
	ch := run(t, f.bin, "changes", txID, "-c", f.cfg)
	if !strings.Contains(ch, `"op": "delete"`) || strings.Count(ch, `"op": "delete"`) != 2 {
		t.Fatalf("changes:\n%s", ch)
	}
	if n := pgCount(t, dsn, 1) + pgCount(t, dsn, 2); n != 0 {
		t.Fatal("not deleted")
	}
	run(t, f.bin, "restore", txID, "--key", `{"id": 2}`, "--yes", "-c", f.cfg)
	if pgCount(t, dsn, 2) != 1 || pgCount(t, dsn, 1) != 0 {
		t.Fatal("restore of one row")
	}
	// undo of the whole gateway transaction refuses: row 2 was put back since (by the restore)
	if out, err := exec.Command(f.bin, "undo", txID, "-c", f.cfg).CombinedOutput(); err == nil && !strings.Contains(string(out), "conflict") && !strings.Contains(string(out), "changed") {
		t.Fatalf("undo over a newer change: %s", out)
	}
}
