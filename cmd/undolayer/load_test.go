package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Many agents at once: each worker is its own gateway process (as each agent would be),
// all on one database, one workspace and one payment service. Every task must end fully
// committed or cleanly refused, never half done, with no deadlock and an intact audit
// chain. UNDOLAYER_LOAD_AGENTS / UNDOLAYER_LOAD_TASKS set the size.
func TestManyAgentsAtOnce(t *testing.T) { manyAgents(t, "") }

// The same on PostgreSQL (UNDOLAYER_TEST_PG): it locks only the rows a task touches, so
// agents working on different rows never wait for each other.
func TestManyAgentsAtOnceOnPostgres(t *testing.T) {
	base := os.Getenv("UNDOLAYER_TEST_PG")
	if base == "" {
		t.Skip("set UNDOLAYER_TEST_PG to run the PostgreSQL load test")
	}
	manyAgents(t, base)
}

func manyAgents(t *testing.T, pgBase string) {
	agents, tasks := 12, 8
	if v := os.Getenv("UNDOLAYER_LOAD_AGENTS"); v != "" {
		fmt.Sscan(v, &agents)
	}
	if v := os.Getenv("UNDOLAYER_LOAD_TASKS"); v != "" {
		fmt.Sscan(v, &tasks)
	}
	f := newFixture(t, agents*tasks)
	count := func(k int) int { // is order k still there?
		db, _ := sql.Open("sqlite3", f.db)
		defer db.Close()
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM orders WHERE id = ?", k).Scan(&n)
		return n
	}
	if pgBase != "" {
		dsn := pgOrders(t, pgBase, agents*tasks)
		if out, err := exec.Command(f.bin, "pg", "install", "-c", pgConfig(t, f, dsn)).CombinedOutput(); err != nil {
			t.Fatalf("pg install: %v %s", err, out)
		}
		count = func(k int) int { return pgCount(t, dsn, k) }
	}
	type outcome struct {
		k         int
		committed bool
		err       string
		took      time.Duration
	}
	results := make(chan outcome, agents*tasks)
	start := time.Now()
	var wg sync.WaitGroup
	for a := 0; a < agents; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			cmd := exec.Command(f.bin, "serve", "-c", f.cfg)
			in, _ := cmd.StdinPipe()
			out, _ := cmd.StdoutPipe()
			cmd.Stderr = io.Discard
			if err := cmd.Start(); err != nil {
				t.Error(err)
				return
			}
			defer func() { in.Close(); _ = cmd.Wait() }()
			c := &mcpClient{in: in, out: bufio.NewReader(out)}
			c.send("initialize", map[string]any{"protocolVersion": "2025-06-18"})
			_, _ = c.recv()
			for j := 0; j < tasks; j++ {
				k := a*tasks + j + 1
				t0 := time.Now()
				o := outcome{k: k}
				err := func() error {
					if _, err := c.tool("undolayer_begin", map[string]any{"task": fmt.Sprintf("close order %d", k)}); err != nil {
						return err
					}
					if _, err := c.tool("sql_execute", map[string]any{"sql": fmt.Sprintf("DELETE FROM orders WHERE id = %d", k)}); err != nil {
						return err
					}
					if _, err := c.tool("fs_write", map[string]any{"path": fmt.Sprintf("closed/%d.txt", k), "content": "closed\n"}); err != nil {
						return err
					}
					if _, err := c.tool("pay_charge", map[string]any{"amount_cents": 1000 + k, "customer": fmt.Sprintf("cus_%d", k)}); err != nil {
						return err
					}
					_, err := c.tool("undolayer_commit", map[string]any{})
					return err
				}()
				o.took = time.Since(t0)
				if err != nil {
					o.err = err.Error()
					_, _ = c.tool("undolayer_rollback", map[string]any{"reason": "load test: refused"})
				} else {
					o.committed = true
				}
				results <- o
			}
		}(a)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Minute):
		t.Fatal("agents deadlocked: not finished after 10 minutes")
	}
	close(results)
	elapsed := time.Since(start)

	var committed, refused int
	var lat []time.Duration
	reasons := map[string]int{}
	for o := range results {
		n := count(o.k)
		_, ferr := os.Stat(filepath.Join(f.ws, "closed", fmt.Sprintf("%d.txt", o.k)))
		deleted, written, charged := n == 0, ferr == nil, f.pay.netFor(1000+o.k) > 0
		if !(deleted == written && written == charged) || deleted != o.committed {
			t.Errorf("task %d half done or misreported: committed=%v deleted=%v written=%v charged=%v (%s)",
				o.k, o.committed, deleted, written, charged, o.err)
		}
		if o.committed {
			committed++
			lat = append(lat, o.took)
		} else {
			refused++
			r := o.err
			if i := strings.Index(r, ":"); i > 0 && len(r) > 80 {
				r = r[:80]
			}
			reasons[r]++
		}
	}
	if out, err := exec.Command(f.bin, "audit", "-c", f.cfg).CombinedOutput(); err != nil || !strings.HasPrefix(string(out), "OK") {
		t.Fatalf("audit chain under load: %v %s", err, out)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p := func(q float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(q*float64(len(lat)-1))]
	}
	t.Logf("%d agents x %d tasks in %s: %d committed, %d refused cleanly; task latency p50 %s, p95 %s; %.1f tasks/s",
		agents, tasks, elapsed.Round(time.Millisecond), committed, refused, p(0.5).Round(time.Millisecond),
		p(0.95).Round(time.Millisecond), float64(committed)/elapsed.Seconds())
	for r, n := range reasons {
		t.Logf("  refused %dx: %s", n, r)
	}
	if committed == 0 {
		t.Fatal("no task committed under load")
	}
}
