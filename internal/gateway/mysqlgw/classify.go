package mysqlgw

import (
	"sort"
	"strings"
	"sync"

	"undolayer/internal/sqlshape"
)

// A statement as the gateway reads it: MySQL's own lexical rules (backslash escapes, both
// quote characters for strings, backticks, # and "-- " comments, and /*! ... */, whose
// content MySQL runs), turned into what the decision needs.

type tok struct {
	k    byte // w word, s string, i quoted identifier, v variable, n number, p punctuation, c comment
	text string
}

func lex(sql string) []tok {
	var ts []tok
	i, n := 0, len(sql)
	exec := 0 // inside /*! ... */: its content is code
	for i < n {
		ch := sql[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' || ch == '\v':
			i++
		case exec > 0 && ch == '*' && i+1 < n && sql[i+1] == '/':
			exec--
			i += 2
		case ch == '#' || (ch == '-' && i+2 <= n && strings.HasPrefix(sql[i:], "--") && (i+2 == n || sql[i+2] <= ' ')):
			j := strings.IndexByte(sql[i:], '\n')
			if j < 0 {
				j = n - i
			}
			ts = append(ts, tok{'c', "--" + sql[i+1:i+j]})
			i += j
		case ch == '/' && i+1 < n && sql[i+1] == '*':
			if i+2 < n && sql[i+2] == '!' {
				i += 3
				for i < n && sql[i] >= '0' && sql[i] <= '9' {
					i++
				}
				exec++
				continue
			}
			j := strings.Index(sql[i+2:], "*/")
			end := n
			if j >= 0 {
				end = i + 2 + j + 2
			}
			ts = append(ts, tok{'c', sql[i:end]})
			i = end
		case ch == '\'' || ch == '"':
			j := i + 1
			var b strings.Builder
			for j < n {
				if sql[j] == '\\' && j+1 < n {
					b.WriteByte(sql[j+1])
					j += 2
					continue
				}
				if sql[j] == ch {
					if j+1 < n && sql[j+1] == ch {
						b.WriteByte(ch)
						j += 2
						continue
					}
					j++
					break
				}
				b.WriteByte(sql[j])
				j++
			}
			ts = append(ts, tok{'s', b.String()})
			i = j
		case ch == '`':
			j := i + 1
			var b strings.Builder
			for j < n {
				if sql[j] == '`' {
					if j+1 < n && sql[j+1] == '`' {
						b.WriteByte('`')
						j += 2
						continue
					}
					j++
					break
				}
				b.WriteByte(sql[j])
				j++
			}
			ts = append(ts, tok{'i', b.String()})
			i = j
		case ch == '@':
			j := i + 1
			for j < n && (isWord(sql[j]) || sql[j] == '@' || sql[j] == '.') {
				j++
			}
			if j < n && (sql[j] == '`' || sql[j] == '\'' || sql[j] == '"') { // @`name`
				q := sql[j]
				k := strings.IndexByte(sql[j+1:], q)
				if k < 0 {
					k = n - j - 1
				}
				j = j + 1 + k + 1
			}
			ts = append(ts, tok{'v', strings.ToLower(sql[i:min(j, n)])})
			i = min(j, n)
		case ch >= '0' && ch <= '9':
			j := i
			for j < n && (isWord(sql[j]) || sql[j] == '.') {
				j++
			}
			ts = append(ts, tok{'n', sql[i:j]})
			i = j
		case isWord(ch) || ch >= 0x80:
			j := i
			for j < n && (isWord(sql[j]) || sql[j] >= 0x80) {
				j++
			}
			ts = append(ts, tok{'w', strings.ToLower(sql[i:j])})
			i = j
		default:
			ts = append(ts, tok{'p', string(ch)})
			i++
		}
	}
	return ts
}

func isWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$'
}

// sqliteText renders the tokens in the dialect the shape reader knows.
func sqliteText(ts []tok) string {
	var b strings.Builder
	for _, t := range ts {
		switch t.k {
		case 's':
			b.WriteString("'" + strings.ReplaceAll(t.text, "'", "''") + "'")
		case 'i':
			b.WriteString(`"` + strings.ReplaceAll(t.text, `"`, `""`) + `"`)
		case 'c':
			if strings.HasPrefix(t.text, "--") {
				b.WriteString(t.text + "\n")
			} else {
				b.WriteString(t.text)
			}
		case 'v':
			b.WriteString("?")
		default:
			b.WriteString(t.text)
		}
		b.WriteByte(' ')
	}
	return b.String()
}

const (
	kRead       = "read"
	kWrite      = "write"
	kBegin      = "begin"
	kCommit     = "commit"
	kRollback   = "rollback"
	kImplicit   = "implicit_commit" // DDL and the rest that commit the open transaction first
	kAutocommit = "autocommit"
	kUse        = "use"
	kOther      = "other"
)

type stmtInfo struct {
	text      string
	kind      string
	chain     bool   // COMMIT AND CHAIN
	auto      int    // SET autocommit: 0, 1 (-1: not set)
	useDB     string // USE db
	ddlTables bool   // the statement changes tables' columns (the triggers follow)
	target    string // the table an INSERT/UPDATE/DELETE writes (unqualified)
	tempMade  string // CREATE TEMPORARY TABLE name
	facts     map[string]any
}

var adminWords = map[string]bool{"shutdown": true, "kill": true, "install": true, "uninstall": true, "reset": true,
	"purge": true, "change": true, "clone": true, "restart": true, "flush": true, "optimize": true, "repair": true,
	"cache": true, "binlog": true, "import": true}

func analyze(sql string) *stmtInfo {
	ts := lex(sql)
	var words []string // significant tokens at depth 0, lowercased (strings and identifiers excluded)
	var all []tok
	for _, t := range ts {
		if t.k != 'c' {
			all = append(all, t)
		}
	}
	depth := 0
	for _, t := range all {
		if t.k == 'p' && t.text == "(" {
			depth++
		}
		if t.k == 'p' && t.text == ")" {
			depth--
		}
		if depth == 0 && t.k == 'w' {
			words = append(words, t.text)
		}
	}
	si := &stmtInfo{text: sql, kind: kOther, auto: -1, facts: map[string]any{}}
	f := si.facts
	shape := sqlshape.Analyze(sqliteText(ts))
	sig := map[string]bool{}
	for _, s := range shape.Signals {
		sig[s] = true
	}
	f["query_shape"] = shape.Shape
	w := func(i int) string {
		if i < len(words) {
			return words[i]
		}
		return ""
	}
	has := func(x string) bool {
		for _, y := range words {
			if y == x {
				return true
			}
		}
		return false
	}
	// functions called, and words anywhere
	for i, t := range all {
		if t.k == 'w' && i+1 < len(all) && all[i+1].k == 'p' && all[i+1].text == "(" {
			switch t.text {
			case "sleep", "benchmark", "wait_for_executed_gtid_set", "source_pos_wait", "master_pos_wait":
				sig["time_delay"] = true
			case "load_file", "sys_exec", "sys_eval":
				sig["file_or_program"] = true
			}
		}
		if t.k == 'w' && (t.text == "outfile" || t.text == "dumpfile") {
			sig["file_or_program"] = true
		}
		if strings.Contains(strings.ToLower(t.text), "countersign") {
			f["capture_tamper"] = true
		}
	}
	switch w(0) {
	case "select", "show", "describe", "desc", "explain", "table", "values", "help", "do", "handler", "analyze", "check", "checksum":
		si.kind = kRead
	case "with":
		si.kind = kRead
		for i := 1; i < len(words); i++ {
			if (words[i] == "update" || words[i] == "delete" || words[i] == "insert" || words[i] == "replace") && words[i-1] != "for" && words[i-1] != "key" {
				si.kind = kWrite
			}
		}
	case "insert", "replace", "update", "delete":
		si.kind = kWrite
		si.target = writeTarget(all)
	case "call":
		si.kind = kWrite
	case "load":
		sig["file_or_program"] = true
		si.kind = kWrite
	case "begin":
		si.kind = kBegin
	case "start":
		if w(1) == "transaction" {
			si.kind = kBegin
		} else {
			f["admin_command"] = true
		}
	case "commit":
		si.kind = kCommit
		si.chain = has("chain") && !has("no")
	case "rollback":
		si.kind = kRollback
		if w(1) == "to" || w(2) == "to" {
			si.kind = kOther // to a savepoint: the transaction goes on
		}
		si.chain = has("chain") && !has("no")
	case "savepoint", "release":
		si.kind = kOther
	case "use":
		si.kind = kUse
		if len(all) > 1 {
			si.useDB = all[1].text
		}
	case "set":
		si.kind = kOther
		switch {
		case w(1) == "password":
			f["privilege_change"] = true
		case w(1) == "global" || w(1) == "persist" || w(1) == "persist_only":
			f["admin_command"] = true
		case w(1) == "default" && w(2) == "role":
			f["privilege_change"] = true
		}
		for i, t := range all {
			name := strings.TrimLeft(t.text, "@")
			name = strings.TrimPrefix(strings.TrimPrefix(name, "session."), "local.")
			if (t.k == 'w' || t.k == 'v') && name == "global.autocommit" {
				f["admin_command"] = true
			}
			if (t.k == 'w' || t.k == 'v') && name == "autocommit" && i+2 < len(all) && (all[i+1].text == "=" || all[i+1].text == ":") {
				j := i + 2
				if all[i+1].text == ":" && j < len(all) && all[j].text == "=" {
					j++
				}
				if j < len(all) {
					switch strings.ToLower(all[j].text) {
					case "0", "off", "false":
						si.auto = 0
					default:
						si.auto = 1
					}
					si.kind = kAutocommit
				}
			}
			if (t.k == 'w' || t.k == 'v') && (name == "sql_log_bin" || name == "session_track_transaction_info" || name == "pseudo_slave_mode" || name == "pseudo_replica_mode") {
				f["session_tamper"] = true
			}
		}
	case "create", "alter", "drop", "rename", "truncate", "lock", "unlock", "grant", "revoke":
		si.kind = kImplicit
		objs := map[string]bool{}
		for _, x := range words[1:min(len(words), 6)] {
			objs[x] = true
		}
		switch {
		case w(0) == "grant" || w(0) == "revoke" || objs["user"] || objs["role"]:
			f["privilege_change"] = true
		case objs["procedure"] || objs["function"] || objs["trigger"] || objs["event"]:
			f["routine_change"] = true
		case w(0) == "truncate":
			f["destroys_schema"] = true
		case w(0) == "drop" && (objs["table"] || objs["database"] || objs["schema"]) && !objs["temporary"]:
			f["destroys_schema"] = true
		case w(0) == "alter" && objs["table"] && has("drop") && !has("index") && !has("key") && !has("constraint") && !has("check") && !has("foreign") && !has("partition"):
			f["destroys_schema"] = true // dropping a column
		case w(0) == "alter" && objs["table"] && has("partition") && (has("drop") || has("truncate")):
			f["destroys_schema"] = true
		case w(0) == "rename" || (w(0) == "alter" && has("rename") && !has("index") && !has("key") && !has("column")):
			f["schema_unsupported"] = true // the vault keeps tables by name
		case w(0) == "alter" && (objs["database"] || objs["schema"] || objs["instance"] || objs["server"] || objs["tablespace"] || objs["logfile"]):
			f["admin_command"] = true
		}
		if w(0) == "create" && objs["temporary"] {
			si.kind = kOther // no implicit commit, no triggers: a session's scratch table
			for i := 0; i+1 < len(all); i++ {
				if all[i].text == "table" {
					j := i + 1
					for j < len(all) && (all[j].text == "if" || all[j].text == "not" || all[j].text == "exists") {
						j++
					}
					if j < len(all) {
						si.tempMade = lastName(all[j:])
					}
					break
				}
			}
		} else if (w(0) == "create" || w(0) == "alter") && objs["table"] {
			si.ddlTables = true
		}
		if w(0) == "drop" && objs["temporary"] {
			si.kind = kOther
		}
	case "prepare", "execute", "deallocate":
		f["dynamic_sql"] = true
	case "xa":
		f["two_phase"] = true
	default:
		if adminWords[w(0)] {
			f["admin_command"] = true
		}
	}
	if sig["stacked"] {
		f["multi_statement"] = true
	}
	f["is_write"] = si.kind == kWrite
	var signals []string
	for s := range sig {
		signals = append(signals, s)
	}
	sort.Strings(signals)
	f["sql_injection_signals"] = signals
	return si
}

// lastName: the table of a possibly qualified name at the start of ts (db.t -> t).
func lastName(ts []tok) string {
	if len(ts) == 0 {
		return ""
	}
	name := ts[0].text
	if len(ts) > 2 && ts[1].text == "." {
		name = ts[2].text
	}
	return strings.ToLower(name)
}

// writeTarget: the table an INSERT, REPLACE, UPDATE or single-table DELETE names first.
func writeTarget(ts []tok) string {
	skip := map[string]bool{"low_priority": true, "delayed": true, "high_priority": true, "ignore": true, "into": true, "quick": true, "from": true}
	i := 1
	for i < len(ts) && ts[i].k == 'w' && skip[ts[i].text] {
		i++
	}
	return lastName(ts[i:])
}

// a cache of analyses, by statement text
type analyzer struct {
	mu sync.Mutex
	m  map[string]*stmtInfo
}

func (a *analyzer) get(sql string) *stmtInfo {
	a.mu.Lock()
	si := a.m[sql]
	a.mu.Unlock()
	if si != nil {
		return si
	}
	si = analyze(sql)
	a.mu.Lock()
	if len(a.m) > 50_000 {
		a.m = map[string]*stmtInfo{}
	}
	a.m[sql] = si
	a.mu.Unlock()
	return si
}
