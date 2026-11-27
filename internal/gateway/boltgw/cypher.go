package boltgw

import (
	"sort"
	"strings"
	"sync"

	"undolayer/internal/sqlshape"
)

// A Cypher query as the gateway reads it: strings (either quote, backslash escapes),
// backtick names, // and /* */ comments, $parameters, and the procedures it calls.

type ctok struct {
	k    byte // w word, s string, i name, c comment, n number, $ parameter, p punctuation
	text string
}

func lexCypher(q string) []ctok {
	var ts []ctok
	i, n := 0, len(q)
	for i < n {
		ch := q[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
			i++
		case ch == '/' && i+1 < n && q[i+1] == '/':
			j := strings.IndexByte(q[i:], '\n')
			if j < 0 {
				j = n - i
			}
			ts = append(ts, ctok{'c', "--" + q[i+2:i+j]})
			i += j
		case ch == '/' && i+1 < n && q[i+1] == '*':
			j := strings.Index(q[i+2:], "*/")
			end := n
			if j >= 0 {
				end = i + 2 + j + 2
			}
			ts = append(ts, ctok{'c', q[i:end]})
			i = end
		case ch == '\'' || ch == '"':
			j := i + 1
			var b strings.Builder
			for j < n && q[j] != ch {
				if q[j] == '\\' && j+1 < n {
					j++
				}
				b.WriteByte(q[j])
				j++
			}
			ts = append(ts, ctok{'s', b.String()})
			i = min(j+1, n)
		case ch == '`':
			j := i + 1
			var b strings.Builder
			for j < n {
				if q[j] == '`' {
					if j+1 < n && q[j+1] == '`' {
						b.WriteByte('`')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(q[j])
				j++
			}
			ts = append(ts, ctok{'i', b.String()})
			i = min(j+1, n)
		case ch == '$':
			j := i + 1
			for j < n && isW(q[j]) {
				j++
			}
			ts = append(ts, ctok{'$', q[i:j]})
			i = j
		case ch >= '0' && ch <= '9':
			j := i
			for j < n && (isW(q[j]) || q[j] == '.') {
				j++
			}
			ts = append(ts, ctok{'n', q[i:j]})
			i = j
		case isW(ch) || ch >= 0x80:
			j := i
			for j < n && (isW(q[j]) || q[j] >= 0x80) {
				j++
			}
			ts = append(ts, ctok{'w', strings.ToLower(q[i:j])})
			i = j
		default:
			ts = append(ts, ctok{'p', string(ch)})
			i++
		}
	}
	return ts
}

func isW(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

type queryInfo struct {
	text  string
	norm  string // with its values taken out, as the audit log keeps it
	write bool
	facts map[string]any
}

var cypherClause = map[string]bool{"return": true, "with": true, "match": true, "optional": true, "create": true, "merge": true,
	"delete": true, "detach": true, "remove": true, "unwind": true, "call": true, "yield": true, "foreach": true, "skip": true}

var writeWords = map[string]bool{"create": true, "merge": true, "set": true, "delete": true, "remove": true, "detach": true, "foreach": true}

func analyzeCypher(q string) *queryInfo {
	ts := lexCypher(q)
	var code []ctok
	for _, t := range ts {
		if t.k != 'c' {
			code = append(code, t)
		}
	}
	qi := &queryInfo{text: q, facts: map[string]any{}}
	f := qi.facts
	sig := map[string]bool{}
	// the shape reader's view: strings as literals, names as quoted identifiers
	var b strings.Builder
	for _, t := range ts {
		switch t.k {
		case 's':
			b.WriteString("'" + strings.ReplaceAll(t.text, "'", "''") + "'")
		case 'i':
			b.WriteString(`"` + strings.ReplaceAll(t.text, `"`, `""`) + `"`)
		case 'c':
			b.WriteString(t.text + "\n")
		case '$':
			b.WriteString("?")
		case 'w':
			if cypherClause[t.text] {
				b.WriteString("group") // a Cypher clause ends a condition, as GROUP does in SQL
			} else {
				b.WriteString(t.text)
			}
		default:
			b.WriteString(t.text)
		}
		b.WriteByte(' ')
	}
	shape := sqlshape.Analyze(b.String())
	for _, s := range shape.Signals {
		sig[s] = true
	}
	f["query_shape"] = shape.Shape
	qi.norm = shape.Normalized
	if len(qi.norm) > 2000 {
		qi.norm = qi.norm[:2000] + "…"
	}
	word := func(i int) string {
		if i >= 0 && i < len(code) && code[i].k == 'w' {
			return code[i].text
		}
		return ""
	}
	for i, t := range code {
		if strings.Contains(strings.ToLower(t.text), "countersign") {
			f["capture_tamper"] = true
		}
		if t.k != 'w' {
			continue
		}
		if writeWords[t.text] {
			qi.write = true
		}
		switch {
		case t.text == "load" && word(i+1) == "csv":
			sig["file_or_program"] = true
			qi.write = true
		case t.text == "in" && word(i+1) == "transactions":
			f["separate_transactions"] = true
		case t.text == "periodic" && word(i+1) == "commit":
			f["separate_transactions"] = true
		}
		// a procedure or function name: a dotted chain of words
		if i+2 < len(code) && code[i+1].text == "." {
			j := i
			name := t.text
			for j+2 < len(code) && code[j+1].text == "." && (code[j+2].k == 'w' || code[j+2].k == 'i') {
				name += "." + strings.ToLower(code[j+2].text)
				j += 2
			}
			if i > 0 && code[i-1].text == "." {
				continue
			}
			procedure(name, qi, sig)
		}
	}
	first, second := word(0), word(1)
	switch {
	case first == "grant" || first == "deny" || first == "revoke":
		f["privilege_change"] = true
	case (first == "create" || first == "alter" || first == "drop" || first == "rename") &&
		(second == "user" || second == "role" || second == "current" || (second == "or" && (word(3) == "user" || word(3) == "role"))):
		f["privilege_change"] = true
	case first == "drop" && (second == "database" || second == "composite" || second == "alias"):
		f["destroys_schema"] = true
	case first == "create" && second == "or" && word(2) == "replace" && (word(3) == "database" || word(3) == "composite"):
		f["destroys_schema"] = true
	case (first == "create" || first == "alter" || first == "start" || first == "stop") &&
		(second == "database" || second == "composite" || second == "alias" || second == "server"),
		first == "enable" || first == "deallocate" || first == "reallocate" || first == "dryrun":
		f["admin_command"] = true
	case first == "use":
		f["database_switch"] = true
	case (first == "show" || first == "terminate") && (second == "transaction" || second == "transactions" || second == "queries" ||
		second == "connections"):
		f["other_sessions"] = true
	}
	if sig["stacked"] {
		f["multi_statement"] = true
	}
	var signals []string
	for s := range sig {
		signals = append(signals, s)
	}
	sort.Strings(signals)
	f["cypher_injection_signals"] = signals
	f["is_write"] = qi.write
	return qi
}

func procedure(name string, qi *queryInfo, sig map[string]bool) {
	f := qi.facts
	has := func(p string) bool { return name == p || strings.HasPrefix(name, p+".") }
	switch {
	case has("apoc.trigger"):
		f["capture_tamper"] = true
	case has("apoc.cypher"), has("apoc.do"), name == "apoc.when", name == "apoc.case":
		f["dynamic_cypher"] = true
	case has("apoc.periodic"):
		f["separate_transactions"] = true
	case has("apoc.load"), has("apoc.import"), has("apoc.export"), has("apoc.systemdb"), has("apoc.log"), has("apoc.static"):
		sig["file_or_program"] = true
	case name == "apoc.util.sleep":
		sig["time_delay"] = true
	case has("dbms") && name != "dbms.components" && !has("dbms.routing") && name != "dbms.info" && name != "dbms.queryjmx" && !has("dbms.client"):
		f["admin_command"] = true
	case has("apoc.create"), has("apoc.refactor"), has("apoc.merge"), has("apoc.nodes.delete"), has("apoc.nodes.link"),
		has("apoc.lock"), has("db.create"), has("apoc.graph"):
		qi.write = true
	}
	if has("apoc") || has("db") || has("dbms") || has("gds") {
		procs, _ := f["procedures"].([]string)
		f["procedures"] = append(procs, name)
	}
}

type qcache struct {
	mu sync.Mutex
	m  map[string]*queryInfo
}

func (c *qcache) get(q string) *queryInfo {
	c.mu.Lock()
	qi := c.m[q]
	c.mu.Unlock()
	if qi != nil {
		return qi
	}
	qi = analyzeCypher(q)
	c.mu.Lock()
	if len(c.m) > 50_000 {
		c.m = map[string]*queryInfo{}
	}
	c.m[q] = qi
	c.mu.Unlock()
	return qi
}
