package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"sort"
	"strings"
	"time"

	"undolayer/internal/connectors/mcpproxy"
	"undolayer/internal/model"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

// undolayer changes <tx> [--table T] [--op delete|update|insert|drop_table|drop_column]
//
//	[--format json|csv|sql] [--out file]
//
// What a task changed, row by row, with each row's content before and after: from the
// task's journal, or from the vault if the journal is gone. --format sql writes statements
// that put the rows back by hand (no conflict check; `undolayer restore` is the checked way).
func changesCmd(m *tx.Manager, args []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		die(errors.New("usage: undolayer changes <tx> [--table T] [--op delete] [--format json|csv|sql] [--out file] -c undolayer.toml"))
	}
	id := args[0]
	tables, ops := map[string]bool{}, map[string]bool{}
	format, outPath := "json", ""
	for i := 1; i < len(args); i++ {
		if i+1 >= len(args) {
			die(fmt.Errorf("%s needs a value", args[i]))
		}
		switch args[i] {
		case "--table":
			tables[args[i+1]] = true
		case "--op":
			ops[args[i+1]] = true
		case "--format":
			format = args[i+1]
		case "--out":
			outPath = args[i+1]
		default:
			die(fmt.Errorf("unknown option %s", args[i]))
		}
		i++
	}
	if format != "json" && format != "csv" && format != "sql" {
		die(errors.New("--format is json, csv or sql"))
	}
	crs, err := m.ChangedRows(id)
	if err != nil {
		die(err)
	}
	tableOK := func(t string) bool {
		return len(tables) == 0 || tables[t] || tables[strings.TrimPrefix(t, "public.")]
	}
	keep := func(r vault.Row) bool { return tableOK(r.Table) && (len(ops) == 0 || ops[r.Op]) }
	var w io.Writer = os.Stdout
	if outPath != "" {
		f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // it holds the deleted data
		if err != nil {
			die(err)
		}
		defer f.Close()
		w = f
	}
	n := 0
	switch format {
	case "json":
		type part struct {
			Connector string      `json:"connector"`
			State     string      `json:"state"`
			Source    string      `json:"source"`
			Undone    bool        `json:"undone"`
			Settled   string      `json:"settled,omitempty"`
			Rows      []vault.Row `json:"rows"`
		}
		doc := map[string]any{"tx": id, "exported_at": time.Now().UTC().Format(time.RFC3339)}
		parts := []part{}
		for _, cr := range crs {
			p := part{Connector: cr.Connector, State: string(cr.State), Source: cr.Source, Undone: cr.Undone, Settled: cr.Settled, Rows: []vault.Row{}}
			for _, r := range cr.Rows {
				if keep(r) {
					p.Rows = append(p.Rows, r)
				}
			}
			n += len(p.Rows)
			parts = append(parts, p)
		}
		doc["changes"], doc["rows"] = parts, n
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			die(err)
		}
	case "csv":
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"connector", "table", "op", "key", "before", "after"})
		for _, cr := range crs {
			for _, r := range cr.Rows {
				if !keep(r) {
					continue
				}
				k, _ := json.Marshal(r.Key)
				b, _ := json.Marshal(r.Before)
				a, _ := json.Marshal(r.After)
				if r.Before == nil {
					b = nil
				}
				if r.After == nil {
					a = nil
				}
				_ = cw.Write([]string{cr.Connector, r.Table, r.Op, string(k), string(b), string(a)})
				n++
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			die(err)
		}
	case "sql":
		fmt.Fprintf(w, "-- Puts back what %s changed, as it was before it ran.\n", id)
		fmt.Fprintln(w, "-- No conflict check: rows changed since are overwritten. `undolayer restore` checks each row first.")
		fmt.Fprintln(w, "-- Run it inside one transaction; if a foreign key refuses a row, restore its parent table first.")
		fmt.Fprintln(w, "BEGIN;")
		for _, cr := range crs {
			c, err := m.Connector(cr.Connector)
			if err != nil {
				die(err)
			}
			ex, ok := c.(interface {
				ExportSQL(json.RawMessage, func(string, map[string]any) bool) ([]string, error)
			})
			if !ok {
				fmt.Fprintf(w, "-- %s: no SQL form; use --format json\n", cr.Connector)
				continue
			}
			if len(ops) > 0 {
				die(errors.New("--op cannot be combined with --format sql (the statements put back whole rows)"))
			}
			stmts, err := ex.ExportSQL(cr.Record, func(t string, _ map[string]any) bool { return tableOK(t) })
			if err != nil {
				die(err)
			}
			for _, s := range stmts {
				fmt.Fprintln(w, s)
			}
			n += len(stmts)
		}
		fmt.Fprintln(w, "COMMIT;")
	}
	if outPath != "" {
		fmt.Fprintf(os.Stderr, "%d rows of %s written to %s\n", n, id, outPath)
	}
}

// undolayer restore <tx> [--table T]... [--key '{"id": 42}']... [--on-conflict fail|skip]
//
//	[--dry-run] [--yes]
//
// Puts chosen rows back as they were before <tx>, as a new task: each row is checked first
// (it must still be as <tx> left it), the restore is previewed, approved under policy like
// any change, and can itself be undone.
func restoreCmd(m *tx.Manager, args []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		die(errors.New("usage: undolayer restore <tx> [--table T] [--key '{\"id\": 42}'] [--path P] [--on-conflict skip] [--dry-run] [--yes] -c undolayer.toml"))
	}
	src := args[0]
	var tables, keys, paths []any
	onConflict, dry, yes := "fail", false, false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			dry = true
			continue
		case "--yes":
			yes = true
			continue
		}
		if i+1 >= len(args) {
			die(fmt.Errorf("%s needs a value", args[i]))
		}
		switch args[i] {
		case "--table":
			tables = append(tables, args[i+1])
		case "--key":
			var k map[string]any
			dec := json.NewDecoder(strings.NewReader(args[i+1]))
			dec.UseNumber()
			if err := dec.Decode(&k); err != nil || len(k) == 0 {
				die(fmt.Errorf("--key takes a JSON object, e.g. '{\"id\": 42}': %v", err))
			}
			keys = append(keys, k)
		case "--path":
			paths = append(paths, args[i+1])
		case "--on-conflict":
			onConflict = args[i+1]
		default:
			die(fmt.Errorf("unknown option %s", args[i]))
		}
		i++
	}
	crs, err := m.ChangedRows(src)
	if err != nil {
		die(err)
	}
	// rows go back through restore_rows, files through restore_files; --path picks files
	// only, --table/--key rows only
	type target struct{ name, op string }
	var targets []target
	seen := map[string]bool{}
	for _, cr := range crs {
		c, err := m.Connector(cr.Connector)
		if err != nil || seen[cr.Connector] {
			continue
		}
		ops := c.Operations()
		if _, ok := ops["restore_rows"]; ok && len(paths) == 0 {
			targets, seen[cr.Connector] = append(targets, target{cr.Connector, "restore_rows"}), true
		}
		if _, ok := ops["restore_files"]; ok && len(tables) == 0 && len(keys) == 0 {
			targets, seen[cr.Connector] = append(targets, target{cr.Connector, "restore_files"}), true
		}
	}
	if len(targets) == 0 {
		die(fmt.Errorf("%s has nothing that can be restored piece by piece here (undo it whole: undolayer undo %s)", src, src))
	}
	t := m.Begin("restore what " + src + " changed")
	results := map[string]any{}
	for _, tg := range targets {
		name := tg.name
		a := map[string]any{"source_tx": src, "on_conflict": onConflict}
		if len(tables) > 0 {
			a["tables"] = tables
		}
		if len(keys) > 0 {
			a["keys"] = keys
		}
		if len(paths) > 0 {
			a["paths"] = paths
		}
		r, err := t.Call(name, tg.op, a)
		if err != nil {
			_, _ = t.Rollback("restore failed")
			var cc *model.CommitConflict
			if errors.As(err, &cc) {
				die(fmt.Errorf("%v\n(nothing was changed)", err))
			}
			die(err)
		}
		results[name] = r
	}
	pv := t.Preview()
	out(map[string]any{"tx": t.ID, "restoring_from": src, "results": results, "changes": pv["changes"],
		"approval_reasons": pv["approval_reasons"]})
	if dry {
		_, _ = t.Rollback("dry run")
		fmt.Fprintln(os.Stderr, "dry run: nothing was changed")
		return
	}
	if !yes {
		fmt.Fprint(os.Stderr, "Restore exactly these changes? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			_, _ = t.Rollback("not confirmed")
			fmt.Fprintln(os.Stderr, "not restored")
			os.Exit(1)
		}
	}
	if pv["approval_required"] == true {
		if m.Review.Enabled() {
			if m.ApprovalWait == 0 {
				m.ApprovalWait = 15 * time.Minute
			}
			fmt.Fprintf(os.Stderr, "waiting for reviewers: undolayer approve %s --as <name> --key <key>\n", t.ID)
		} else {
			u, _ := user.Current()
			if err := t.Approve(u.Username, m.ApprovalToken(t.ID, pv["preview_hash"].(string))); err != nil {
				die(err)
			}
		}
	}
	res, err := t.Commit()
	if err != nil {
		die(err)
	}
	out(res)
	fmt.Fprintf(os.Stderr, "restored; to take it back: undolayer undo %s\n", t.ID)
}

// undolayer revert --requester NAME [--since TIME] [--until TIME] [--dry-run] [--yes]
// Undoes every committed task of one requester in a time window, newest first. It stops at
// the first task that cannot be undone cleanly (for example rows changed since by someone
// else), so it never leaves an older task undone under a newer one that still stands.
//
// undolayer revert --table T [--path P] [--since TIME] [--requester NAME] ...
// Puts one table (or file) back as it was at TIME: what every task committed since then
// changed in it is restored, newest task first, in one new task, which is checked row by
// row, previewed, approved under policy and undoable. Other tables those tasks changed are
// left as they are. A row changed since outside Countersign stops it (nothing is written).
// TIME is RFC 3339 (2026-11-27T14:00:00Z) or a duration ago (2h, 30m).
func revertCmd(m *tx.Manager, args []string) {
	var requester string
	var tables, paths []any
	var since, until float64
	dry, yes := false, false
	parseT := func(s string) float64 {
		if d, err := time.ParseDuration(s); err == nil {
			return float64(time.Now().Add(-d).UnixNano()) / 1e9
		}
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			die(fmt.Errorf("time %q: use RFC 3339 or a duration such as 2h", s))
		}
		return float64(tm.UnixNano()) / 1e9
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			dry = true
			continue
		case "--yes":
			yes = true
			continue
		}
		if i+1 >= len(args) {
			die(fmt.Errorf("%s needs a value", args[i]))
		}
		switch args[i] {
		case "--requester":
			requester = args[i+1]
		case "--table":
			tables = append(tables, args[i+1])
		case "--path":
			paths = append(paths, args[i+1])
		case "--since":
			since = parseT(args[i+1])
		case "--until":
			until = parseT(args[i+1])
		default:
			die(fmt.Errorf("unknown option %s", args[i]))
		}
		i++
	}
	if requester == "" && len(tables) == 0 && len(paths) == 0 {
		die(errors.New("usage: undolayer revert --requester NAME | --table T | --path P  [--since 2h] [--until TIME] [--dry-run] [--yes]"))
	}
	var picked []*tx.Tx
	for _, s := range m.List() {
		if s.State != string(model.Committed) || s.Created < since || (until > 0 && s.Created > until) {
			continue
		}
		t, err := m.Get(s.ID)
		if err != nil || (requester != "" && t.Requester != requester) {
			continue
		}
		picked = append(picked, t)
	}
	if len(tables) > 0 || len(paths) > 0 {
		sort.Slice(picked, func(i, j int) bool { return picked[i].Created > picked[j].Created })
		revertTo(m, picked, tables, paths, since, dry, yes)
		return
	}
	sort.Slice(picked, func(i, j int) bool { return picked[i].Created > picked[j].Created })
	list := []map[string]any{}
	for _, t := range picked {
		list = append(list, map[string]any{"tx": t.ID, "task": t.Task,
			"created": time.Unix(0, int64(t.Created*1e9)).UTC().Format(time.RFC3339), "actions": len(t.Actions)})
	}
	out(map[string]any{"requester": requester, "tasks": list})
	if len(picked) == 0 || dry {
		if dry {
			fmt.Fprintln(os.Stderr, "dry run: nothing was changed")
		}
		return
	}
	if !yes {
		fmt.Fprintf(os.Stderr, "Undo these %d tasks, newest first? [y/N] ", len(picked))
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			fmt.Fprintln(os.Stderr, "nothing undone")
			os.Exit(1)
		}
	}
	done := []string{}
	for _, t := range picked {
		rep, err := t.Undo("")
		if err != nil || !rep.Clean() {
			out(map[string]any{"undone": done, "stopped_at": t.ID, "error": fmt.Sprint(err), "report": rep,
				"not_attempted": len(picked) - len(done) - 1})
			die(fmt.Errorf("stopped at %s: it could not be undone cleanly; the %d older tasks were left as they are", t.ID,
				len(picked)-len(done)-1))
		}
		done = append(done, t.ID)
	}
	out(map[string]any{"undone": done})
}

// undolayer vault check | repair | keys | rotate-key | shred-key <id>
func vaultCmd(m *tx.Manager, args []string) {
	if m.Vault == nil {
		die(errors.New("the vault is disabled ([vault] disabled = true)"))
	}
	switch first(args) {
	case "check":
		rep := m.Vault.Check()
		out(rep)
		for _, g := range rep.SharedDevices {
			fmt.Fprintf(os.Stderr, "warning: replicas %v are on the same device; a disk failure would lose them together\n", g)
		}
		if !rep.Healthy {
			os.Exit(1)
		}
	case "repair":
		rep, err := m.Vault.Repair()
		out(rep)
		if err != nil {
			die(err)
		}
	case "keys":
		if m.Vault.Keys() == nil {
			die(errors.New("the vault stores content in the clear ([vault] encrypt = false)"))
		}
		out(m.Vault.Keys().Info())
	case "rotate-key":
		if m.Vault.Keys() == nil {
			die(errors.New("the vault stores content in the clear ([vault] encrypt = false)"))
		}
		id, err := m.Vault.Keys().Rotate()
		if err != nil {
			die(err)
		}
		fmt.Printf("new entries are sealed with %s; earlier ones keep their keys\n", id)
	case "shred-key":
		if m.Vault.Keys() == nil || len(args) < 2 {
			die(errors.New("usage: undolayer vault shred-key <key id> [--yes] (see: undolayer vault keys)"))
		}
		yes := len(args) > 2 && args[2] == "--yes"
		if !yes {
			fmt.Fprintf(os.Stderr, "Everything sealed with %s becomes unreadable on every replica, for good. Type the key id to confirm: ", args[1])
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimSpace(line) != args[1] {
				die(errors.New("not shredded"))
			}
		}
		if err := m.Vault.Keys().Shred(args[1]); err != nil {
			die(err)
		}
		_ = m.Audit.Record("vault_key_shredded", map[string]any{"key": args[1]})
		fmt.Printf("shredded %s\n", args[1])
	default:
		die(errors.New("usage: undolayer vault check|repair|keys|rotate-key|shred-key <id> -c undolayer.toml"))
	}
}

func first(a []string) string {
	if len(a) == 0 {
		return ""
	}
	return a[0]
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// revertTo restores the chosen tables and files from each task, newest first, in one task.
func revertTo(m *tx.Manager, picked []*tx.Tx, tables, paths []any, since float64, dry, yes bool) {
	if since == 0 {
		die(errors.New("--table and --path revert to a moment: give --since"))
	}
	t := m.Begin("revert to " + time.Unix(0, int64(since*1e9)).UTC().Format(time.RFC3339))
	used := []map[string]any{}
	for _, src := range picked {
		crs, err := m.ChangedRows(src.ID)
		if err != nil {
			continue
		}
		for _, cr := range crs {
			if cr.Undone {
				continue
			}
			c, err := m.Connector(cr.Connector)
			if err != nil {
				continue
			}
			ops := c.Operations()
			var op string
			a := map[string]any{"source_tx": src.ID, "on_conflict": "fail"}
			if _, ok := ops["restore_rows"]; ok && len(tables) > 0 && touches(cr, tables, "") {
				op, a["tables"] = "restore_rows", tables
			} else if _, ok := ops["restore_files"]; ok && len(paths) > 0 && touches(cr, paths, "files") {
				op, a["paths"] = "restore_files", paths
			}
			if op == "" {
				continue
			}
			r, err := t.Call(cr.Connector, op, a)
			if err != nil {
				_, _ = t.Rollback("revert failed")
				die(fmt.Errorf("%s: %v\n(nothing was changed)", src.ID, err))
			}
			used = append(used, map[string]any{"tx": src.ID, "task": src.Task, "connector": cr.Connector, "result": r})
		}
	}
	if len(used) == 0 {
		_, _ = t.Rollback("nothing to revert")
		out(map[string]any{"tasks": used})
		fmt.Fprintln(os.Stderr, "no committed task changed that since then")
		return
	}
	pv := t.Preview()
	out(map[string]any{"tx": t.ID, "tasks": used, "changes": pv["changes"], "approval_reasons": pv["approval_reasons"]})
	if dry {
		_, _ = t.Rollback("dry run")
		fmt.Fprintln(os.Stderr, "dry run: nothing was changed")
		return
	}
	if !yes {
		fmt.Fprint(os.Stderr, "Put these back? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			_, _ = t.Rollback("not confirmed")
			fmt.Fprintln(os.Stderr, "nothing changed")
			os.Exit(1)
		}
	}
	if pv["approval_required"] == true && !m.Review.Enabled() {
		u, _ := user.Current()
		if err := t.Approve(u.Username, m.ApprovalToken(t.ID, pv["preview_hash"].(string))); err != nil {
			die(err)
		}
	} else if pv["approval_required"] == true {
		if m.ApprovalWait == 0 {
			m.ApprovalWait = 15 * time.Minute
		}
		fmt.Fprintf(os.Stderr, "waiting for reviewers: undolayer approve %s --as <name> --key <key>\n", t.ID)
	}
	res, err := t.Commit()
	if err != nil {
		die(err)
	}
	out(res)
	fmt.Fprintf(os.Stderr, "reverted; to take it back: undolayer undo %s\n", t.ID)
}

// touches: the change set has a row in one of the tables (or, for files, one of the paths).
func touches(cr tx.ChangedRows, names []any, table string) bool {
	for _, r := range cr.Rows {
		for _, n := range names {
			ns := fmt.Sprint(n)
			if table == "files" {
				if r.Table == "files" && fmt.Sprint(r.Key["path"]) == ns {
					return true
				}
			} else if r.Table == ns || r.Table == "public."+ns {
				return true
			}
		}
	}
	return false
}

// undolayer freeze <requester> [--reason TEXT] | unfreeze <requester> | frozen
// Freezing stops a requester everywhere at once: every call on every connector, and every
// commit, on every gateway sharing the state store.
func freezeCmd(m *tx.Manager, cmd string, args []string) {
	by := "operator"
	if u, err := user.Current(); err == nil {
		by = u.Username
	}
	switch cmd {
	case "frozen":
		l, err := m.FrozenRequesters()
		if err != nil {
			die(err)
		}
		out(l)
	case "freeze":
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			die(errors.New("usage: undolayer freeze <requester> [--reason TEXT]"))
		}
		reason := "frozen by an operator"
		for i := 1; i+1 < len(args); i++ {
			if args[i] == "--reason" {
				reason = args[i+1]
			}
		}
		if err := m.Freeze(args[0], by, reason); err != nil {
			die(err)
		}
		fmt.Printf("%s is frozen: nothing it asks for runs or commits until: undolayer unfreeze %s\n", args[0], args[0])
	case "unfreeze":
		if len(args) == 0 {
			die(errors.New("usage: undolayer unfreeze <requester>"))
		}
		if err := m.Unfreeze(args[0], by); err != nil {
			die(err)
		}
		fmt.Printf("%s can act again\n", args[0])
	}
}

// undolayer mcp list | pin <server>
// pin accepts a server's current tool definitions after review; tools that changed since
// the last pin are listed.
func mcpCmd(m *tx.Manager, args []string) {
	switch first(args) {
	case "list":
		out := []map[string]any{}
		for name, c := range m.Connectors() {
			if pc, ok := c.(*mcpproxy.Connector); ok {
				ops := pc.Operations()
				tools := []string{}
				for t := range ops {
					tools = append(tools, t)
				}
				sort.Strings(tools)
				out = append(out, map[string]any{"server": name, "tools": tools})
			}
		}
		sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]["server"]) < fmt.Sprint(out[j]["server"]) })
		printJSON(out)
	case "pin":
		if len(args) < 2 {
			die(errors.New("usage: undolayer mcp pin <server>"))
		}
		c, err := m.Connector(args[1])
		pc, ok := c.(*mcpproxy.Connector)
		if err != nil || !ok {
			die(fmt.Errorf("no [[mcp_server]] named %s", args[1]))
		}
		changed, err := pc.Pin()
		if err != nil {
			die(err)
		}
		_ = m.Audit.Record("mcp_pin", map[string]any{"server": args[1], "changed": changed})
		fmt.Printf("pinned %s; tools whose definition changed: %v\n", args[1], changed)
		pc.Close()
	default:
		die(errors.New("usage: undolayer mcp list | pin <server> -c undolayer.toml"))
	}
}

func printJSON(v any) { out(v) }
