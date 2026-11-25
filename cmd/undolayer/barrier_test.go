package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"undolayer/internal/sandbox"
)

// TestBarrier launches a hostile "agent" with `undolayer run` and checks that the
// gateway and the allow-listed proxy are its only ways to affect the world.
func TestBarrier(t *testing.T) {
	if sandbox.Backend() == "" {
		t.Skip("no OS sandbox on this machine")
	}
	bin := filepath.Join(t.TempDir(), "undolayer")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %s", out)
	}
	base, _ := filepath.EvalSymlinks(t.TempDir())
	home := filepath.Join(base, "home")
	ws := filepath.Join(base, "ws")
	for _, d := range []string{home, ws} {
		_ = os.MkdirAll(d, 0o755)
	}
	_ = os.WriteFile(filepath.Join(ws, "app.py"), []byte("print(1)\n"), 0o644)
	_ = os.WriteFile(filepath.Join(home, "id_rsa"), []byte("PRIVATE KEY\n"), 0o600)
	db := filepath.Join(base, "app.db")
	c, _ := sql.Open("sqlite3", db)
	if _, err := c.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY); INSERT INTO t VALUES (1),(2),(3),(4)"); err != nil {
		t.Fatal(err)
	}
	c.Close()

	var hits []string
	inet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Host+r.URL.Path)
		_, _ = io.WriteString(w, "ok")
	}))
	defer inet.Close()
	host := strings.TrimPrefix(inet.URL, "http://")
	cfg := filepath.Join(base, "undolayer.toml")
	_ = os.WriteFile(cfg, []byte(fmt.Sprintf(`state_dir = %q
[workspace]
root = "ws"
[sql]
dsn = "app.db"
[agent]
allow_hosts = ["model-api.test"]
`, filepath.Join(base, "state"))), 0o644)

	// Direct access to the "internet" must fail; going through the proxy to a host that is
	// not allow-listed must fail; the gateway must work.
	agent := filepath.Join(base, "agent.sh")
	script := fmt.Sprintf(`#!/bin/sh
try() { if sh -c "$2" >/dev/null 2>&1; then echo "$1=ok"; else echo "$1=blocked"; fi; }
try direct_http  "curl -s -f --noproxy '*' -m 3 http://%[1]s/direct"
try dns          "python3 -c \"import socket; socket.gethostbyname('exfil.example.com')\" || getent hosts exfil.example.com"
try proxy_denied "curl -s -f -m 5 -x \$HTTPS_PROXY http://%[1]s/via-proxy"
try write_ws     "echo owned > %[2]s/app.py"
try write_db     "echo x >> %[3]s"
try read_key     "cat %[4]s/approver.key"
try read_home    "cat %[5]s/id_rsa"
printf '%%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sql_execute","arguments":{"sql":"DELETE FROM t WHERE id = 1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"undolayer_commit","arguments":{}}}' \
  | %[6]s connect > "$TMPDIR/gw.out" 2>&1
grep -q '"committed"' "$TMPDIR/gw.out" && echo gateway=ok || { echo gateway=failed; cat "$TMPDIR/gw.out"; }
`, host, ws, db, filepath.Join(base, "state"), home, bin)
	_ = os.WriteFile(agent, []byte(script), 0o755)

	cmd := exec.Command(bin, "run", "-c", cfg, "--", agent)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, _ := cmd.CombinedOutput()
	got := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			got[k] = v
		}
	}
	want := map[string]string{"direct_http": "blocked", "dns": "blocked", "proxy_denied": "blocked", "write_ws": "blocked",
		"write_db": "blocked", "read_key": "blocked", "read_home": "blocked", "gateway": "ok"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	if t.Failed() {
		t.Logf("agent output:\n%s", out)
	}
	if len(hits) > 0 {
		t.Errorf("the internet was reached: %v", hits)
	}
	b, _ := os.ReadFile(filepath.Join(ws, "app.py"))
	c, _ = sql.Open("sqlite3", db)
	defer c.Close()
	var n int
	_ = c.QueryRow("SELECT COUNT(*) FROM t").Scan(&n)
	if string(b) != "print(1)\n" || n != 3 {
		t.Errorf("world after the run: app.py=%q rows=%d (want unchanged file, one row deleted via the gateway)", b, n)
	}
}
