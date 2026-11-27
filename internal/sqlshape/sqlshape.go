// Package sqlshape reads a SQL statement as tokens, following SQLite's tokenizer rules, to
// give it a shape (its structure with every literal value taken out) and the structural
// signs of SQL injection. It never decides what a statement does to data: that comes from
// the database itself (the authorizer, the row capture). It answers two other questions:
// is this the same query as before with different values, and does its structure look
// like a query someone else's input rewrote.
//
// Injection changes a query's structure, not only its values. A value pasted into the text
// of  WHERE name = '<input>'  as  x' OR 'a'='a  turns one comparison into an always-true
// disjunction; as  x' --  it cuts the rest of the statement off; as  x' UNION SELECT ...
// it appends a second query. A parameterized query cannot change shape, whatever the value.
package sqlshape

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

type kind int

const (
	kWord   kind = iota // keyword or bare identifier
	kQuoted             // "identifier", `identifier`, [identifier]
	kString             // 'text'
	kNumber
	kBlob  // x'..'
	kParam // ?, ?1, :name, @name, $name
	kOp
	kComment
	kSemi
)

type token struct {
	k    kind
	text string
	// trailing: a comment that runs to the end of the statement (nothing after it)
}

func isIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '$' || c >= 0x80
}

// tokens splits sql into tokens. An unterminated string, identifier or comment runs to the
// end, as SQLite reads it (and then rejects the statement, if it is not complete).
func tokens(sql string) []token {
	var out []token
	s := sql
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				j = len(s) - i
			}
			out = append(out, token{kComment, s[i : i+j]})
			i += j
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			j := strings.Index(s[i+2:], "*/")
			end := len(s)
			if j >= 0 {
				end = i + 2 + j + 2
			}
			out = append(out, token{kComment, s[i:end]})
			i = end
		case c == '\'':
			j := i + 1
			for j < len(s) {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			out = append(out, token{kString, s[i:j]})
			i = j
		case (c == 'x' || c == 'X') && i+1 < len(s) && s[i+1] == '\'':
			j := strings.IndexByte(s[i+2:], '\'')
			end := len(s)
			if j >= 0 {
				end = i + 2 + j + 1
			}
			out = append(out, token{kBlob, s[i:end]})
			i = end
		case c == '"' || c == '`':
			j := i + 1
			for j < len(s) {
				if s[j] == c {
					if j+1 < len(s) && s[j+1] == c {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			out = append(out, token{kQuoted, s[i:j]})
			i = j
		case c == '[':
			j := strings.IndexByte(s[i:], ']')
			end := len(s)
			if j >= 0 {
				end = i + j + 1
			}
			out = append(out, token{kQuoted, s[i:end]})
			i = end
		case c >= '0' && c <= '9' || c == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			j := i
			if c == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') {
				j += 2
				for j < len(s) && isIdent(s[j]) {
					j++
				}
			} else {
				for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.' || s[j] == '_') {
					j++
				}
				if j < len(s) && (s[j] == 'e' || s[j] == 'E') {
					k := j + 1
					if k < len(s) && (s[k] == '+' || s[k] == '-') {
						k++
					}
					if k < len(s) && s[k] >= '0' && s[k] <= '9' {
						j = k
						for j < len(s) && s[j] >= '0' && s[j] <= '9' {
							j++
						}
					}
				}
			}
			out = append(out, token{kNumber, s[i:j]})
			i = j
		case c == '?':
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			out = append(out, token{kParam, "?"})
			i = j
		case (c == ':' || c == '@' || c == '$') && i+1 < len(s) && isIdent(s[i+1]):
			j := i + 1
			for j < len(s) && isIdent(s[j]) {
				j++
			}
			out = append(out, token{kParam, "?"})
			i = j
		case isIdent(c):
			j := i
			for j < len(s) && isIdent(s[j]) {
				j++
			}
			out = append(out, token{kWord, strings.ToLower(s[i:j])})
			i = j
		case c == ';':
			out = append(out, token{kSemi, ";"})
			i++
		default:
			// two-character operators first
			if i+1 < len(s) {
				two := s[i : i+2]
				switch two {
				case "<=", ">=", "<>", "!=", "==", "||", "<<", ">>", "->":
					if two == "->" && i+2 < len(s) && s[i+2] == '>' {
						out = append(out, token{kOp, "->>"})
						i += 3
						continue
					}
					out = append(out, token{kOp, two})
					i += 2
					continue
				}
			}
			out = append(out, token{kOp, string(c)})
			i++
		}
	}
	return out
}

func literal(t token) bool {
	switch t.k {
	case kString, kNumber, kBlob:
		return true
	case kWord:
		return t.text == "true" || t.text == "false" || t.text == "null"
	}
	return false
}

var cmpOps = map[string]bool{"=": true, "==": true, "<>": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true}

// clause words that end a condition
var clauseEnd = map[string]bool{"group": true, "order": true, "limit": true, "union": true, "intersect": true,
	"except": true, "returning": true, "window": true, "select": true, "set": true, "values": true, "do": true}

// Result is a statement's shape and its injection signs.
type Result struct {
	// Shape identifies the statement's structure: the same query with other values (or
	// another number of values in an IN list) has the same shape.
	Shape string
	// Normalized is the text the shape is taken from (literals replaced by ?).
	Normalized string
	// Signals, sorted: or_tautology (an always-true operand of OR: OR 1=1, OR 'a'='a',
	// OR true), trailing_comment (the statement ends in a -- comment: what cuts off the
	// rest of a query), comment, union, stacked (more than one statement).
	Signals []string
}

// Analyze returns the shape and injection signs of sql.
func Analyze(sql string) Result {
	ts := tokens(sql)
	sig := map[string]bool{}
	var norm []string
	statements := 0
	inStmt := false
	inCond := false
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		switch t.k {
		case kComment:
			sig["comment"] = true
			rest := ts[i+1:]
			trailing := strings.HasPrefix(t.text, "--")
			for _, r := range rest {
				if r.k != kComment && r.k != kSemi {
					trailing = false
				}
			}
			if trailing && i > 0 {
				sig["trailing_comment"] = true
			}
			continue
		case kSemi:
			if inStmt {
				statements++
			}
			inStmt, inCond = false, false
			norm = append(norm, ";")
			continue
		}
		inStmt = true
		// a sign in front of a number is part of the value: n > -1 and n > 2 are one shape
		if t.k == kOp && (t.text == "-" || t.text == "+") && i+1 < len(ts) && ts[i+1].k == kNumber && !afterValue(ts[:i]) {
			continue
		}
		if t.k == kWord {
			switch {
			case t.text == "where" || t.text == "having" || t.text == "on" || t.text == "when":
				inCond = true
			case clauseEnd[t.text]:
				inCond = false
			}
			if t.text == "union" {
				sig["union"] = true
			}
			if t.text == "or" && inCond && orTautology(ts[i+1:]) {
				sig["or_tautology"] = true
			}
		}
		switch {
		case literal(t) && !(t.k == kWord && t.text == "null"), t.k == kParam:
			// a list of values is one value: IN (1, 2, 3) and IN (?) have the same shape
			if len(norm) >= 2 && norm[len(norm)-1] == "," && norm[len(norm)-2] == "?" {
				norm = norm[:len(norm)-1]
				continue
			}
			norm = append(norm, "?")
		case t.k == kQuoted:
			norm = append(norm, strings.ToLower(t.text[1:max(1, len(t.text)-1)]))
		default:
			norm = append(norm, t.text)
		}
	}
	if inStmt {
		statements++
	}
	if statements > 1 {
		sig["stacked"] = true
	}
	n := strings.Join(norm, " ")
	h := sha256.Sum256([]byte(n))
	r := Result{Shape: hex.EncodeToString(h[:8]), Normalized: n, Signals: []string{}}
	for s := range sig {
		r.Signals = append(r.Signals, s)
	}
	sort.Strings(r.Signals)
	return r
}

// orTautology: the operand right after OR is always true by its own text: a literal
// compared with an equal literal, a column compared with itself, or a bare true literal
// (true, a non-zero number, a non-empty string), up to the next AND/OR or the end.
func orTautology(rest []token) bool {
	var op []token
	depth := 0
	for _, t := range rest {
		if t.k == kComment {
			continue
		}
		if t.k == kOp && t.text == "(" {
			depth++
			if depth == 1 && len(op) == 0 {
				continue
			}
		}
		if t.k == kOp && t.text == ")" {
			if depth == 0 {
				break
			}
			depth--
			if depth == 0 {
				continue
			}
		}
		if depth == 0 && (t.k == kSemi || t.k == kWord && (t.text == "and" || t.text == "or" || clauseEnd[t.text])) {
			break
		}
		op = append(op, t)
	}
	switch len(op) {
	case 1:
		t := op[0]
		switch t.k {
		case kNumber:
			return strings.Trim(t.text, "0.") != ""
		case kString:
			return len(t.text) > 2
		case kWord:
			return t.text == "true"
		}
	case 3:
		a, o, b := op[0], op[1], op[2]
		if !cmpOps[o.text] || o.k != kOp {
			return false
		}
		same := a.k == b.k && a.text == b.text
		if literal(a) && literal(b) {
			switch o.text {
			case "=", "==", "<=", ">=":
				return same
			case "<>", "!=":
				return !same && a.k == b.k
			}
			return false
		}
		if (a.k == kWord || a.k == kQuoted) && same && !literal(a) {
			return o.text == "=" || o.text == "==" || o.text == "<=" || o.text == ">="
		}
	case 4: // NOT false
		return false
	}
	return false
}

// afterValue: the last significant token ends a value (so a following - is binary).
func afterValue(before []token) bool {
	for i := len(before) - 1; i >= 0; i-- {
		t := before[i]
		if t.k == kComment {
			continue
		}
		switch t.k {
		case kString, kNumber, kBlob, kParam, kQuoted:
			return true
		case kWord:
			switch t.text {
			case "select", "where", "and", "or", "not", "on", "having", "when", "then", "else", "case", "set",
				"values", "in", "is", "like", "between", "by", "limit", "offset", "return", "returning":
				return false
			}
			return true
		case kOp:
			return t.text == ")"
		}
		return false
	}
	return false
}
