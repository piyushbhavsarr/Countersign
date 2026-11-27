package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Crash testing with the shipped binary and no hooks in the product: drive a task over
// MCP (a database delete, a file write and a real charge), SIGKILL the gateway at a random
// moment (often during commit), run `undolayer recover`, and check that every task is
// either fully applied or fully undone. UNDOLAYER_CHAOS_RUNS sets the number of runs.

type payments struct {
	mu      sync.Mutex
	charges map[string]int // payment intent -> amount
	refunds map[string]bool
	byKey   map[string]string // idempotency key -> intent
	n       int
}

func (p *payments) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	switch r.URL.Path {
	case "/payment_intents":
		key := r.Header.Get("Idempotency-Key")
		if id, ok := p.byKey[key]; ok && key != "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "amount": p.charges[id]})
			return
		}
		p.n++
		id := fmt.Sprintf("pi_%d", p.n)
		amt := 0
		fmt.Sscan(fmt.Sprint(in["amount"]), &amt)
		p.charges[id] = amt
		if key != "" {
			p.byKey[key] = id
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "amount": amt})
	case "/refunds":
		id := fmt.Sprint(in["payment_intent"])
		if _, ok := p.charges[id]; !ok {
			w.WriteHeader(404)
			return
		}
		p.refunds[id] = true
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "re_" + id})
	case "/balance":
		_ = json.NewEncoder(w).Encode(map[string]any{"net": p.net()})
	default:
		w.WriteHeader(404)
	}
}

func (p *payments) net() int {
	n := 0
	for id, a := range p.charges {
		if !p.refunds[id] {
			n += a
		}
	}
	return n
}

// netFor: what customer cus_<k> was charged and not refunded.
func (p *payments) netFor(amount int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for id, a := range p.charges {
		if a == amount && !p.refunds[id] {
			n += a
		}
	}
	return n
}

type mcpClient struct {
	in  io.WriteCloser
	out *bufio.Reader
	n   int
}

func (c *mcpClient) send(method string, params any) {
	c.n++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.n, "method": method, "params": params})
	_, _ = c.in.Write(append(b, '\n'))
}

func (c *mcpClient) recv() (map[string]any, error) {
	line, err := c.out.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(line, &m)
}

func (c *mcpClient) tool(name string, args map[string]any) (map[string]any, error) {
	c.send("tools/call", map[string]any{"name": name, "arguments": args})
	r, err := c.recv()
	if err != nil {
		return nil, err
	}
	res, _ := r["result"].(map[string]any)
	if res["isError"] == true {
		return nil, fmt.Errorf("%s: %v", name, res["structuredContent"])
	}
	sc, _ := res["structuredContent"].(map[string]any)
	return sc, nil
}

func TestCrashesNeverLeaveATaskHalfDone(t *testing.T) {
	runs := 30
	if v := os.Getenv("UNDOLAYER_CHAOS_RUNS"); v != "" {
		fmt.Sscan(v, &runs)
	}
	f := newFixture(t, runs)
	bin, cfg, ws, dbPath, pay := f.bin, f.cfg, f.ws, f.db, f.pay
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	killedDuringCommit := 0
	for i := 1; i <= runs; i++ {
		cmd := exec.Command(bin, "serve", "-c", cfg)
		in, _ := cmd.StdinPipe()
		outp, _ := cmd.StdoutPipe()
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		c := &mcpClient{in: in, out: bufio.NewReader(outp)}
		c.send("initialize", map[string]any{"protocolVersion": "2025-06-18"})
		_, _ = c.recv()
		killAt := rng.Intn(4) // 0..3: during a step
		if rng.Intn(2) == 0 {
			killAt = 4 // half the runs: during commit
		}
		txID := ""
		steps := []func() error{
			func() error {
				r, err := c.tool("undolayer_begin", map[string]any{"task": fmt.Sprintf("close order %d", i)})
				txID = fmt.Sprint(r["tx"])
				return err
			},
			func() error {
				_, err := c.tool("sql_execute", map[string]any{"sql": fmt.Sprintf("DELETE FROM orders WHERE id = %d", i)})
				return err
			},
			func() error {
				_, err := c.tool("fs_write", map[string]any{"path": fmt.Sprintf("closed/%d.txt", i), "content": "closed\n"})
				return err
			},
			func() error {
				_, err := c.tool("pay_charge", map[string]any{"amount_cents": 1000 + i, "customer": fmt.Sprintf("cus_%d", i)})
				return err
			},
		}
		var stepErr error
		for k, step := range steps {
			if k == killAt {
				break
			}
			if stepErr = step(); stepErr != nil {
				break
			}
		}
		if stepErr != nil {
			t.Fatalf("run %d: %v", i, stepErr)
		}
		if killAt == 4 { // commit in flight, killed at a random moment
			c.send("tools/call", map[string]any{"name": "undolayer_commit", "arguments": map[string]any{}})
			time.Sleep(time.Duration(rng.Intn(25000)) * time.Microsecond)
			killedDuringCommit++
		}
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_ = cmd.Wait()

		if out, err := exec.Command(bin, "recover", "-c", cfg).CombinedOutput(); err != nil {
			t.Fatalf("run %d: recover: %v %s", i, err, out)
		}
		db, _ := sql.Open("sqlite3", dbPath)
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM orders WHERE id = ?", i).Scan(&n)
		db.Close()
		_, ferr := os.Stat(filepath.Join(ws, "closed", fmt.Sprintf("%d.txt", i)))
		deleted, written, charged := n == 0, ferr == nil, pay.netFor(1000+i) > 0
		if !(deleted == written && written == charged) {
			t.Fatalf("run %d (killed at step %d): half done: row deleted=%v, file written=%v, charged=%v",
				i, killAt, deleted, written, charged)
		}
		if killAt < 4 && (deleted || written || charged) {
			t.Fatalf("run %d: a task killed before commit left effects", i)
		}
		// the vault rule: a delete that happened has its row in the vault
		if deleted {
			out, err := exec.Command(bin, "changes", txID, "-c", cfg).Output()
			if err != nil {
				t.Fatalf("run %d: changes %s: %v", i, txID, err)
			}
			var doc struct {
				Changes []struct {
					Rows []struct {
						Op     string         `json:"op"`
						Before map[string]any `json:"before"`
					} `json:"rows"`
				} `json:"changes"`
			}
			_ = json.Unmarshal(out, &doc)
			found := false
			for _, ch := range doc.Changes {
				for _, r := range ch.Rows {
					found = found || (r.Op == "delete" && fmt.Sprint(r.Before["id"]) == fmt.Sprint(i) && r.Before["note"] == "x")
				}
			}
			if !found {
				t.Fatalf("run %d (killed at step %d): row %d was deleted but is not in the vault: %s", i, killAt, i, out)
			}
		}
	}
	if out, err := exec.Command(bin, "vault", "check", "-c", cfg).CombinedOutput(); err != nil {
		t.Fatalf("vault after crashes: %v %s", err, out)
	}
	out, err := exec.Command(bin, "audit", "-c", cfg).CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "OK") {
		t.Fatalf("audit chain after crashes: %v %s", err, out)
	}
	t.Logf("%d runs, %d killed during commit; every task all-or-nothing", runs, killedDuringCommit)
}

type fixture struct {
	bin, cfg, ws, db string
	pay              *payments
}

// newFixture: the built binary, a workspace, a SQLite database with `rows` orders, and a
// payment service whose registry entry has passed its round trip.
func newFixture(t *testing.T, rows int) *fixture {
	dir := t.TempDir()
	bin := filepath.Join(dir, "undolayer")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	pay := &payments{charges: map[string]int{}, refunds: map[string]bool{}, byKey: map[string]string{}}
	srv := httptest.NewServer(pay)
	t.Cleanup(srv.Close)

	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	_ = os.WriteFile(filepath.Join(ws, "README"), []byte("app\n"), 0o644)
	dbPath := filepath.Join(dir, "app.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec("CREATE TABLE orders(id INTEGER PRIMARY KEY, note TEXT)")
	for i := 1; i <= rows; i++ {
		_, _ = db.Exec("INSERT INTO orders(id, note) VALUES (?, 'x')", i)
	}
	db.Close()
	reg := filepath.Join(dir, "registry")
	_ = os.MkdirAll(reg, 0o755)
	_ = os.WriteFile(filepath.Join(reg, "pay.toml"), []byte(fmt.Sprintf(`
[tool]
name = "pay"
base_url = %q

[action.charge]
kind = "compensable"
description = "Charge a customer"
request = { method = "POST", path = "/payment_intents", body = { amount = "$args.amount_cents", customer = "$args.customer" } }
params = { amount_cents = { type = "integer" }, customer = { type = "string" } }
required = ["amount_cents", "customer"]
undo = { call = "refund", args = { payment_intent = "$response.id" } }
lookup = { replay = true }
test = { args = { amount_cents = 100000, customer = "cus_roundtrip" }, state = { call = "balance", args = {} } }

[action.refund]
kind = "irreversible"
description = "Refund a charge"
request = { method = "POST", path = "/refunds", body = { payment_intent = "$args.payment_intent" } }
params = { payment_intent = { type = "string" } }
required = ["payment_intent"]

[action.balance]
kind = "read"
description = "Net charged"
request = { method = "GET", path = "/balance" }
`, srv.URL)), 0o644)
	cfg := filepath.Join(dir, "undolayer.toml")
	_ = os.WriteFile(cfg, []byte(fmt.Sprintf(`state_dir = %q
[workspace]
root = "ws"
[sql]
dsn = "app.db"
[registry]
paths = [%q]
[vault]
replicas = [%q, %q, %q]
`, filepath.Join(dir, "state"), reg, filepath.Join(dir, "vault-a"), filepath.Join(dir, "vault-b"), filepath.Join(dir, "vault-c"))), 0o644)
	if out, err := exec.Command(bin, "registry", "test", reg, "-c", cfg).CombinedOutput(); err != nil {
		t.Fatalf("the payment tool did not pass its round trip: %v\n%s", err, out)
	}

	return &fixture{bin: bin, cfg: cfg, ws: ws, db: dbPath, pay: pay}
}
