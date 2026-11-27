// Command undolayer: the undo runtime for AI agents.
//
//	undolayer run      -c undolayer.toml -- <agent> [args]   confine the agent; gateway + egress proxy are its only way out
//	undolayer serve    -c ...                    MCP gateway on stdio
//	undolayer connect  [--socket PATH]           stdio <-> gateway socket (what a confined agent launches as its MCP server)
//	undolayer list | show <tx> | approve <tx> | rollback <tx> | undo <tx> [--step ID]
//	undolayer recover | worker [--once] | audit
//	undolayer registry test|list <path>
//	undolayer hook claude-code | setup claude-code
//	undolayer evidence <tx> [--out evidence.json]   everything about a task, as JSON
//	undolayer risk train [--data examples.jsonl] [--out risk-model.json] | risk explain <tx>
//	undolayer changes <tx> [--table T] [--op delete] [--format json|csv|sql] [--out file]
//	undolayer restore <tx> [--table T] [--key '{"id":42}'] [--on-conflict skip] [--dry-run] [--yes]
//	undolayer revert --requester NAME [--since 2h] [--until TIME] [--dry-run] [--yes]
//	undolayer vault check | repair | keys | rotate-key | shred-key <id>
//	undolayer bench [--json] [--suite core|heldout|all] [--policy none] [--no-sandbox]
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"undolayer/internal/bench"
	"undolayer/internal/connectors/cloud"
	"undolayer/internal/connectors/postgres"
	"undolayer/internal/creds"
	"undolayer/internal/egress"
	"undolayer/internal/harness"
	"undolayer/internal/integrations"
	"undolayer/internal/mcp"
	"undolayer/internal/registry"
	"undolayer/internal/review"
	"undolayer/internal/risk"
	rt "undolayer/internal/runtime"
	"undolayer/internal/sandbox"
	"undolayer/internal/tx"
)

const version = "0.3.0"

var jsonOut *bool

func die(err error) {
	fmt.Fprintln(os.Stderr, "undolayer:", err)
	os.Exit(1)
}

func out(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func load(cfgPath string) (*rt.Config, *tx.Manager) {
	c, err := rt.LoadConfig(cfgPath)
	if err != nil {
		die(err)
	}
	m, _, err := rt.Build(c)
	if err != nil {
		die(err)
	}
	return c, m
}

func main() {
	egress.MaybeNetinit()
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: undolayer <run|serve|connect|list|show|approve|rollback|undo|recover|worker|audit|registry|hook|setup|bench> ...")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("c", "undolayer.toml", "config file")
	jsonOut = fs.Bool("json", false, "machine-readable output")
	switch cmd {
	case "version", "--version":
		fmt.Println(version)
	case "bench":
		os.Exit(bench.Main(args))
	case "connect":
		sock := fs.String("socket", os.Getenv("UNDOLAYER_GATEWAY"), "gateway socket")
		parseArgs(fs, args)
		connect(*sock)
	case "hook":
		parseArgs(fs, args)
		var cfg map[string][]string
		if c, err := rt.LoadConfig(*cfgPath); err == nil {
			cfg = c.Integrations.ClaudeCode
		}
		if err := integrations.Hook(os.Stdin, os.Stdout, cfg); err != nil {
			die(err)
		}
	case "aws":
		parseArgs(fs, args)
		if fs.Arg(0) != "verify" || fs.Arg(1) == "" {
			die(errors.New("usage: undolayer aws verify <AWS::Type> --desired '<properties JSON>' --patch '<JSON Patch>' -c undolayer.toml\n" +
				"  Creates a resource of that type in your account, updates it, undoes the update, checks the properties\n" +
				"  are back, and deletes it. Use a sandbox account. On success the type's changes become undoable."))
		}
		var desired map[string]any
		var patch json.RawMessage
		rest := fs.Args()[2:]
		for i := 0; i+1 < len(rest); i++ {
			switch rest[i] {
			case "--desired":
				if err := json.Unmarshal([]byte(rest[i+1]), &desired); err != nil {
					die(fmt.Errorf("--desired: %v", err))
				}
			case "--patch":
				patch = json.RawMessage(rest[i+1])
			}
		}
		if desired == nil || len(patch) == 0 {
			die(errors.New("both --desired and --patch are required"))
		}
		_, m := load(*cfgPath)
		c, err := m.Connector("cloud")
		if err != nil {
			die(err)
		}
		cl := c.(*cloud.Connector)
		if cl.CC == nil {
			die(errors.New("[aws] read_profile and write_profile must be configured"))
		}
		if err := cl.Verify(fs.Arg(1), desired, patch); err != nil {
			die(fmt.Errorf("FAIL %s: %v", fs.Arg(1), err))
		}
		fmt.Printf("PASS %s: create, update, undo and delete round trip; its changes are now undoable\n", fs.Arg(1))
		return
	case "evidence":
		parseArgs(fs, args)
		if fs.Arg(0) == "" {
			die(errors.New("usage: undolayer evidence <tx> [--out evidence.json] -c undolayer.toml"))
		}
		_, m := load(*cfgPath)
		t, err := m.Get(fs.Arg(0))
		if err != nil {
			die(err)
		}
		rep, err := m.EvidenceReport(t)
		if err != nil {
			die(err)
		}
		rest := fs.Args()[1:]
		for i := 0; i+1 < len(rest); i++ {
			if rest[i] == "--out" {
				b, _ := json.MarshalIndent(rep, "", "  ")
				if err := os.WriteFile(rest[i+1], append(b, '\n'), 0o600); err != nil {
					die(err)
				}
				fmt.Printf("evidence for %s written to %s\n", t.ID, rest[i+1])
				return
			}
		}
		out(rep)
		return
	case "risk":
		parseArgs(fs, args)
		riskCmd(*cfgPath, fs.Args())
		return
	case "changes", "restore", "revert", "vault":
		parseArgs(fs, args)
		_, m := load(*cfgPath)
		map[string]func(*tx.Manager, []string){"changes": changesCmd, "restore": restoreCmd, "revert": revertCmd,
			"vault": vaultCmd}[cmd](m, fs.Args())
		return
	case "reviewer":
		parseArgs(fs, args)
		if fs.Arg(0) != "keygen" || fs.Arg(1) == "" {
			die(errors.New("usage: undolayer reviewer keygen <name> [--hardware] [--out ~/.ssh/undolayer_<name>]"))
		}
		name, out, hw := fs.Arg(1), "", false
		rest := fs.Args()[2:]
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--hardware":
				hw = true
			case "--out":
				if i+1 < len(rest) {
					out = rest[i+1]
					i++
				}
			}
		}
		if out == "" {
			home, _ := os.UserHomeDir()
			out = filepath.Join(home, ".ssh", "undolayer_"+name)
		}
		pub, err := review.Keygen(out, "undolayer reviewer "+name, hw)
		if err != nil {
			die(err)
		}
		fmt.Printf("\nPrivate key: %s (keep it; never put it where an agent can read it)\n", out)
		fmt.Printf("Add this to undolayer.toml:\n\n[reviewers.%s]\nkey = %q\nroles = []\n\n", name, pub)
		fmt.Printf("Approve with: undolayer approve <tx> --as %s --key %s\n", name, out)
		return
	case "setup":
		parseArgs(fs, args)
		abs, _ := filepath.Abs(*cfgPath)
		out(map[string]any{
			"note": "Simplest: put the .mcp.json below in your project; Claude Code then uses undolayer's tools (turn off its own " +
				"Bash/Edit/Write tools to route everything through it). Strongest: confine it with `undolayer run -c " + abs +
				" -- claude`; inside, the gateway is reached via `undolayer connect`. The sandbox hides the macOS keychain, so " +
				"run `claude setup-token` once and export CLAUDE_CODE_OAUTH_TOKEN, list the API host in [agent] " +
				"allow_hosts (api.anthropic.com), and set [agent] temp_env = [\"CLAUDE_CODE_TMPDIR\"] so its scratch " +
				"files go to its private temp directory.",
			".mcp.json": map[string]any{"mcpServers": map[string]any{"undolayer": map[string]any{"command": "undolayer", "args": []string{"connect"}}}},
			".claude/settings.json": map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{"matcher": "*",
				"hooks": []any{map[string]any{"type": "command", "command": "undolayer hook claude-code -c " + abs}}}}}},
		})
	case "pg":
		parseArgs(fs, args)
		if fs.Arg(0) != "install" {
			die(errors.New("usage: undolayer pg install -c undolayer.toml"))
		}
		c, err := rt.LoadConfig(*cfgPath)
		if err != nil || c.SQL == nil {
			die(errors.New("[sql] dsn must point at the PostgreSQL database"))
		}
		if err := postgres.Install(c.SQL.DSN); err != nil {
			die(err)
		}
		fmt.Println("capture installed")
	case "registry":
		parseArgs(fs, args)
		if fs.NArg() < 2 {
			die(errors.New("usage: undolayer registry test|list <path>"))
		}
		tools, err := registry.LoadDir(fs.Arg(1))
		if err != nil {
			die(err)
		}
		if fs.Arg(0) == "list" {
			for _, t := range tools {
				for _, n := range t.ActionNames() {
					a := t.Actions[n]
					st := "unverified"
					if t.IsVerified(a) {
						st = "verified"
					}
					fmt.Printf("%-34s %-13s %s\n", t.Name+"."+n, a.Kind, st)
				}
			}
			return
		}
		c, err := rt.LoadConfig(*cfgPath)
		if err != nil {
			die(err)
		}
		ok := true
		for _, t := range tools {
			for _, r := range harness.RoundTrip(t, creds.Store(c.Credentials), nil, true) {
				ok = ok && r.OK
				mark := "PASS"
				if !r.OK {
					mark = "FAIL"
				}
				fmt.Printf("%s  %s.%s  %s\n", mark, t.Name, r.Action, strings.Join(r.Errors, "; "))
			}
		}
		if !ok {
			os.Exit(1)
		}
	case "serve":
		parseArgs(fs, args)
		_, m := load(*cfgPath)
		if r := m.Recover(); len(r) > 0 {
			b, _ := json.Marshal(map[string]any{"recovered": r})
			fmt.Fprintln(os.Stderr, string(b))
		}
		stop := make(chan struct{})
		go mcp.Worker(m, 5*time.Second, stop)
		mcp.NewSession(m, version).Serve(os.Stdin, os.Stdout)
		close(stop)
	case "run":
		parseArgs(fs, args)
		runAgent(*cfgPath, fs.Args())
	default:
		parseArgs(fs, args)
		manage(cmd, *cfgPath, fs)
	}
}

// signedDecision: with reviewers configured, a decision is signed with the reviewer's key.
func signedDecision(m *tx.Manager, t *tx.Tx, rest []string) {
	as, key, action, decision, yes := os.Getenv("UNDOLAYER_REVIEWER"), os.Getenv("UNDOLAYER_REVIEWER_KEY"), "", "approve", false
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--as":
			if i+1 < len(rest) {
				as = rest[i+1]
				i++
			}
		case "--key":
			if i+1 < len(rest) {
				key = rest[i+1]
				i++
			}
		case "--action":
			if i+1 < len(rest) {
				action = rest[i+1]
				i++
			}
		case "--decline":
			decision = "decline"
		case "--yes":
			yes = true
		case "--exclude":
			die(errors.New("--exclude is applied from the agent session (undolayer_cancel)"))
		}
	}
	if as == "" || key == "" {
		die(errors.New("reviewers are configured: sign your decision with --as <your reviewer name> --key <your SSH key> " +
			"(or UNDOLAYER_REVIEWER / UNDOLAYER_REVIEWER_KEY)"))
	}
	if action == "" && decision == "approve" && !yes {
		pv := t.Preview()
		out(map[string]any{"tx": pv["tx"], "task": pv["task"], "changes": pv["changes"], "held_effects": pv["held_effects"],
			"totals": pv["totals"], "approval_reasons": pv["approval_reasons"]})
		fmt.Print("Approve exactly these changes? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			fmt.Println("not approved")
			os.Exit(1)
		}
	}
	o, err := m.SignDecision(t, action, decision, as, key)
	if err != nil {
		die(err)
	}
	subject := "the whole task"
	if action != "" {
		subject = action
	}
	switch {
	case o.DeclinedBy != "":
		fmt.Printf("declined %s in %s (signed by %s)\n", subject, t.ID, as)
	case o.Approved:
		fmt.Printf("approved %s in %s by %s\n", subject, t.ID, strings.Join(o.ApprovedBy, ", "))
	default:
		fmt.Printf("recorded %s's approval of %s in %s; still needed: %s\n", as, subject, t.ID, strings.Join(o.Missing, "; "))
	}
	for _, x := range o.Invalid {
		fmt.Println("  ignored:", x)
	}
}

func manage(cmd, cfgPath string, fs *flag.FlagSet) {
	_, m := load(cfgPath)
	switch cmd {
	case "pending":
		p := m.Pending()
		if *jsonOut {
			out(p)
			return
		}
		for _, x := range p {
			if x.Kind == "commit" {
				fmt.Printf("%s  commit  %v\n    %s\n    decide: undolayer approve %s [--decline]\n", x.Tx, x.Totals,
					strings.Join(x.Reasons, "; "), x.Tx)
				needs(x)
				continue
			}
			fmt.Printf("%s  %s  %s.%s %v\n    %s\n    decide: undolayer approve %s --action %s [--decline]\n", x.Tx, x.Action.ID,
				x.Action.Connector, x.Action.Operation, x.Action.Args, strings.Join(x.Reasons, "; "), x.Tx, x.Action.ID)
			needs(x)
		}
		return
	case "list":
		for _, t := range m.List() {
			fmt.Printf("%s  %-12s actions=%-4d %s\n", t.ID, t.State, t.Actions, t.Task)
		}
		return
	case "recover":
		out(m.Recover())
		return
	case "worker":
		once := false
		for _, a := range fs.Args() {
			once = once || a == "--once"
		}
		for {
			r := map[string]any{"recovered": m.Recover(), "released": m.FlushDue()}
			out(r)
			if once {
				return
			}
			time.Sleep(5 * time.Second)
		}
	case "audit":
		ok, msg := m.Audit.Verify()
		if ok {
			fmt.Println("OK: " + msg)
			return
		}
		fmt.Println("TAMPERED: " + msg)
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		die(fmt.Errorf("usage: undolayer %s <tx>", cmd))
	}
	t, err := m.Get(fs.Arg(0))
	if err != nil {
		die(err)
	}
	switch cmd {
	case "show":
		if t.State == "open" {
			out(t.Preview())
		} else {
			out(t)
		}
	case "approve":
		rest := fs.Args()[1:]
		if m.Review.Enabled() {
			signedDecision(m, t, rest)
			return
		}
		for i := 0; i < len(rest); i++ { // a decision on one pending action
			if rest[i] == "--action" && i+1 < len(rest) {
				decision := "approve"
				for _, r := range rest {
					if r == "--decline" {
						decision = "decline"
					}
				}
				u, _ := user.Current()
				if err := m.DecideAction(t, rest[i+1], u.Username, decision); err != nil {
					die(err)
				}
				fmt.Printf("%sd %s in %s\n", strings.TrimSuffix(decision, "e"), rest[i+1], t.ID)
				return
			}
		}
		for _, r := range rest { // refuse the whole preview
			if r == "--decline" {
				u, _ := user.Current()
				if err := m.DeclineCommit(t, u.Username); err != nil {
					die(err)
				}
				fmt.Printf("declined %s\n", t.ID)
				return
			}
		}
		var exclude []string
		for i := 0; i < len(rest); i++ {
			if rest[i] == "--exclude" && i+1 < len(rest) {
				exclude = append(exclude, strings.Split(rest[i+1], ",")...)
			}
		}
		if len(exclude) > 0 { // decline part of it: those actions never run
			if !m.TryOwn(t) && t.State == "open" {
				// the owner is the agent session; cancellation is recorded through the journal by the owner
				die(errors.New("--exclude must be applied from the agent session (undolayer_cancel) while it is running"))
			}
			if err := t.Cancel(exclude...); err != nil {
				die(err)
			}
		}
		pv := t.Preview()
		out(map[string]any{"tx": pv["tx"], "task": pv["task"], "changes": pv["changes"], "held_effects": pv["held_effects"],
			"totals": pv["totals"], "approval_reasons": pv["approval_reasons"]})
		yes := false
		for _, a := range fs.Args()[1:] {
			yes = yes || a == "--yes"
		}
		if !yes {
			fmt.Print("Approve exactly these changes? [y/N] ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimSpace(strings.ToLower(line)) != "y" {
				fmt.Println("not approved")
				os.Exit(1)
			}
		}
		u, _ := user.Current()
		h := pv["preview_hash"].(string)
		if err := t.Approve(u.Username, m.ApprovalToken(t.ID, h)); err != nil {
			die(err)
		}
		fmt.Printf("approved %s @ %s; the agent can now commit it\n", t.ID, h[:12])
	case "rollback":
		if !m.TryOwn(t) {
			die(fmt.Errorf("%s is owned by a running agent session; roll it back from there", t.ID))
		}
		r, err := t.Rollback("operator")
		if err != nil {
			die(err)
		}
		out(r)
	case "undo":
		step := ""
		rest := fs.Args()[1:]
		for i := 0; i < len(rest); i++ {
			if rest[i] == "--step" && i+1 < len(rest) {
				step = rest[i+1]
			}
		}
		r, err := t.Undo(step)
		if err != nil {
			die(err)
		}
		out(r)
	default:
		die(fmt.Errorf("unknown command %s", cmd))
	}
}

func orDot(s string) string {
	if s == "" {
		return "."
	}
	return s
}

// within reports whether p is w or inside it.
func within(p, w string) bool {
	rp, rw := p, w
	if r, err := filepath.EvalSymlinks(p); err == nil {
		rp = r
	}
	if r, err := filepath.EvalSymlinks(w); err == nil {
		rw = r
	}
	rel, err := filepath.Rel(rw, rp)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// connect bridges stdio to the gateway socket (what a confined agent runs as its MCP server).
func connect(sock string) {
	if sock == "" {
		die(errors.New("no gateway socket (set UNDOLAYER_GATEWAY or pass --socket); is the agent running under `undolayer run`?"))
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		die(err)
	}
	go func() { _, _ = io.Copy(c, os.Stdin); _ = c.(*net.UnixConn).CloseWrite() }()
	_, _ = io.Copy(os.Stdout, c)
}

func runChild(argv, env []string) int {
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin, c.Stdout, c.Stderr, c.Env = os.Stdin, os.Stdout, os.Stderr, env
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "undolayer:", err)
		return 127
	}
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sig {
			_ = c.Process.Signal(s)
		}
	}()
	_ = c.Wait()
	return c.ProcessState.ExitCode()
}

// runAgent confines an agent so that the gateway and the egress proxy are its only way out.
func runAgent(cfgPath string, argv []string) {
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		die(errors.New("usage: undolayer run -c undolayer.toml -- <agent> [args]"))
	}
	c, m := load(cfgPath)
	if sandbox.Backend() == "" {
		die(sandbox.ErrUnavailable)
	}
	_ = m.Recover()
	// Sockets live in a short private directory: Unix socket paths are limited to ~104 bytes.
	runDir, err := os.MkdirTemp("/tmp", "ul-")
	if err != nil {
		die(err)
	}
	if r, err := filepath.EvalSymlinks(runDir); err == nil {
		runDir = r
	}
	_ = os.Chmod(runDir, 0o700)
	defer os.RemoveAll(runDir)
	gw := filepath.Join(runDir, "gateway.sock")
	l, err := mcp.ListenUnix(m, gw, version)
	if err != nil {
		die(err)
	}
	defer l.Close()
	stop := make(chan struct{})
	go mcp.Worker(m, 5*time.Second, stop)
	defer close(stop)

	px := &egress.Proxy{Allow: c.Agent.AllowHosts, OnDecision: func(d egress.Decision) {
		_ = m.Audit.Record("egress", map[string]any{"host": d.Host, "allowed": d.Allowed, "method": d.Method})
	}}
	defer px.Close()
	spec := sandbox.Spec{Network: "proxy", UnixSockets: []string{gw}, ReadAllow: []string{runDir}}
	env := append(os.Environ(), "UNDOLAYER_GATEWAY="+gw)
	const nsPort = 18080
	if runtime.GOOS == "linux" {
		ps := filepath.Join(runDir, "egress.sock")
		pl, err := egress.ListenUnix(ps)
		if err != nil {
			die(err)
		}
		go px.Serve(pl)
		spec.UnixSockets = append(spec.UnixSockets, ps)
		self, _ := os.Executable()
		spec.LinuxInit = []string{self, "__netinit", "--proxy-sock", ps, "--port", strconv.Itoa(nsPort)}
		env = append(env, fmt.Sprintf("HTTPS_PROXY=http://127.0.0.1:%d", nsPort), fmt.Sprintf("HTTP_PROXY=http://127.0.0.1:%d", nsPort))
	} else {
		pl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			die(err)
		}
		go px.Serve(pl)
		port := pl.Addr().(*net.TCPAddr).Port
		spec.ProxyPort = port
		env = append(env, fmt.Sprintf("HTTPS_PROXY=http://127.0.0.1:%d", port), fmt.Sprintf("HTTP_PROXY=http://127.0.0.1:%d", port))
	}
	// A private temp dir, never the shared one: the workspace or database may live under it.
	agentTmp := filepath.Join(runDir, "tmp")
	_ = os.MkdirAll(agentTmp, 0o700)
	env = append(env, "TMPDIR="+agentTmp)
	for _, name := range c.Agent.TempEnv {
		if name == "" || strings.ContainsAny(name, "= \x00") {
			die(fmt.Errorf("[agent] temp_env: %q is not an environment variable name", name))
		}
		env = append(env, name+"="+agentTmp)
	}
	spec.Write = []string{agentTmp}
	for _, w := range c.Agent.Write {
		spec.Write = append(spec.Write, c.Abs(w))
	}
	protected := []string{c.StateDir}
	if c.Workspace != nil {
		protected = append(protected, c.Abs(orDot(c.Workspace.Root)))
	}
	if c.SQL != nil {
		protected = append(protected, c.Abs(c.SQL.DSN))
	}
	for _, w := range spec.Write {
		for _, p := range protected {
			if within(p, w) {
				die(fmt.Errorf("[agent] write includes %s, which contains %s: the agent could bypass the gateway", w, p))
			}
		}
	}
	// The agent may read the workspace and system files, but not $HOME (keys, cloud
	// credentials, other projects) except what the operator lists, nor the runtime state.
	home, _ := os.UserHomeDir()
	spec.Hide = []string{c.StateDir, home}
	spec.ReadAllow = append(spec.ReadAllow, runDir)
	for _, p := range c.Agent.Read {
		spec.ReadAllow = append(spec.ReadAllow, c.Abs(p))
	}
	if c.Workspace != nil {
		spec.ReadAllow = append(spec.ReadAllow, c.Abs(orDot(c.Workspace.Root)))
	}
	if wd, err := os.Getwd(); err == nil {
		spec.Workdir = wd
	}
	full, err := sandbox.Command(spec, argv)
	if err != nil {
		die(err)
	}
	os.Exit(runChild(full, env))
}

func needs(x tx.PendingAction) {
	if len(x.Needs) > 0 {
		fmt.Printf("    needs: %s\n", strings.Join(x.Needs, "; "))
	}
	if len(x.Missing) > 0 {
		fmt.Printf("    still missing: %s\n", strings.Join(x.Missing, "; "))
	}
}

// parseArgs parses the flags a command defines wherever they appear ("registry test FILE
// -c cfg" as well as "-c cfg registry test FILE"). Everything else stays in fs.Args() in
// order, including options a command reads itself (approve --action ID); nothing after
// "--" is touched, so an agent's own flags reach the agent.
func parseArgs(fs *flag.FlagSet, args []string) {
	var known, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		name := strings.TrimLeft(a, "-")
		value, hasValue := "", false
		if j := strings.IndexByte(name, '='); j >= 0 {
			name, value, hasValue = name[:j], name[j+1:], true
		}
		f := (*flag.Flag)(nil)
		if strings.HasPrefix(a, "-") && name != "" {
			f = fs.Lookup(name)
		}
		if f == nil {
			rest = append(rest, a)
			continue
		}
		if hasValue {
			known = append(known, "-"+name+"="+value)
			continue
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			known = append(known, "-"+name)
			continue
		}
		known = append(known, "-"+name)
		if i+1 < len(args) {
			known = append(known, args[i+1])
			i++
		}
	}
	_ = fs.Parse(append(known, append([]string{"--"}, rest...)...))
}

// riskCmd trains the risk model from reviewer decisions, or explains a task's scores.
func riskCmd(cfgPath string, args []string) {
	usage := errors.New("usage: undolayer risk train [--data examples.jsonl] [--out risk-model.json] [--epochs N] -c undolayer.toml\n" +
		"       undolayer risk explain <tx> [--model risk-model.json] -c undolayer.toml")
	if len(args) == 0 {
		die(usage)
	}
	opt := func(name string) string {
		for i := 1; i+1 < len(args); i++ {
			if args[i] == name {
				return args[i+1]
			}
		}
		return ""
	}
	c, m := load(cfgPath)
	switch args[0] {
	case "train":
		examples, err := m.ReviewedExamples()
		if err != nil {
			die(err)
		}
		fromAudit := len(examples)
		if f := opt("--data"); f != "" {
			more, err := readExamples(f)
			if err != nil {
				die(err)
			}
			examples = append(examples, more...)
		}
		epochs, _ := strconv.Atoi(opt("--epochs"))
		model, err := risk.Train(examples, risk.Options{Epochs: epochs})
		if err != nil {
			die(fmt.Errorf("%v (%d examples: %d from reviewer decisions in the audit log)", err, len(examples), fromAudit))
		}
		dest := opt("--out")
		if dest == "" {
			dest = c.Abs("risk-model.json")
		}
		if err := model.Save(dest); err != nil {
			die(err)
		}
		out(map[string]any{"model": dest, "examples": len(examples), "from_reviewer_decisions": fromAudit,
			"risky": model.Positives, "training_accuracy": model.Accuracy(examples, 0.5),
			"next": "set [risk] model = \"" + dest + "\" and add a rule on risk_score, e.g. when = { risk_score = { gt = 0.85 } }"})
	case "explain":
		if len(args) < 2 {
			die(usage)
		}
		rm := m.Policy.Risk
		if f := opt("--model"); f != "" {
			var err error
			if rm, err = risk.Load(f); err != nil {
				die(err)
			}
		}
		if rm == nil {
			die(errors.New("no model: set [risk] model in the config, or pass --model"))
		}
		t, err := m.Get(args[1])
		if err != nil {
			die(err)
		}
		rows := []map[string]any{}
		for _, a := range t.Actions {
			score, signals := rm.Score(a)
			rows = append(rows, map[string]any{"action": a.ID, "call": a.Connector + "." + a.Operation,
				"decision": a.Decision, "risk_score": score, "because": signals})
		}
		out(map[string]any{"tx": t.ID, "task": t.Task, "actions": rows})
	default:
		die(usage)
	}
}

// readExamples reads JSON lines of {"action": {...}, "label": 0|1}.
func readExamples(path string) ([]risk.Example, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []risk.Example
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e risk.Example
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, n, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
