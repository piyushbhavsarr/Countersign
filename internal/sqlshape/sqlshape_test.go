package sqlshape

import (
	"strings"
	"testing"
)

func has(r Result, s string) bool {
	for _, x := range r.Signals {
		if x == s {
			return true
		}
	}
	return false
}

func TestSameQueryOtherValuesSameShape(t *testing.T) {
	same := [][2]string{
		{"SELECT * FROM users WHERE id = 42", "select *  from USERS where ID = 7"},
		{"SELECT * FROM t WHERE name = 'bob' AND n > 3.5", "SELECT * FROM t WHERE name = 'it''s' AND n > -0"},
		{"SELECT * FROM t WHERE id IN (1, 2, 3)", "SELECT * FROM t WHERE id IN (?)"},
		{"UPDATE t SET a = :a WHERE id = $1", "UPDATE t SET a = 'x' WHERE id = 99"},
		{`SELECT "Name" FROM [t]`, "SELECT name FROM t"},
		{"DELETE FROM t WHERE b = x'00ff'", "DELETE FROM t WHERE b = ?"},
	}
	for _, p := range same {
		if a, b := Analyze(p[0]), Analyze(p[1]); a.Shape != b.Shape {
			t.Errorf("%q and %q differ:\n %s\n %s", p[0], p[1], a.Normalized, b.Normalized)
		}
	}
	diff := [][2]string{
		{"SELECT * FROM users WHERE id = 1", "SELECT * FROM users WHERE id = 1 OR 1 = 1"},
		{"SELECT * FROM users WHERE id = 1", "SELECT * FROM users WHERE id = 1 UNION SELECT * FROM secrets"},
		{"SELECT a FROM t", "SELECT b FROM t"},
	}
	for _, p := range diff {
		if Analyze(p[0]).Shape == Analyze(p[1]).Shape {
			t.Errorf("%q and %q should differ", p[0], p[1])
		}
	}
}

func TestInjectionSigns(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
		not  []string
	}{
		{"SELECT * FROM users WHERE name = 'x' OR 'a'='a'", []string{"or_tautology"}, nil},
		{"SELECT * FROM users WHERE id = 5 OR 1=1", []string{"or_tautology"}, nil},
		{"SELECT * FROM users WHERE id = 5 OR (1 = 1)", []string{"or_tautology"}, nil},
		{"DELETE FROM users WHERE id = 5 OR TRUE", []string{"or_tautology"}, nil},
		{"SELECT * FROM users WHERE id = 5 OR 1", []string{"or_tautology"}, nil},
		{"SELECT * FROM users WHERE id = 5 OR id = id", []string{"or_tautology"}, nil},
		{"SELECT * FROM users WHERE id = 5 OR 2 > 1", nil, []string{"or_tautology"}}, // not decided textually
		{"SELECT * FROM users WHERE 1=1 AND id = 5", nil, []string{"or_tautology"}},  // a common query-builder idiom
		{"SELECT * FROM users WHERE a = 1 OR b = 2", nil, []string{"or_tautology"}},
		{"SELECT * FROM users WHERE id = 5 OR 0", nil, []string{"or_tautology"}},
		{"SELECT * FROM users WHERE note = 'a OR 1=1 -- UNION'", nil, []string{"or_tautology", "comment", "union"}},
		{"SELECT * FROM users WHERE name = 'admin' --' AND pw = 'x'", []string{"trailing_comment", "comment"}, nil},
		{"SELECT * FROM users /* hi */ WHERE id = 1", []string{"comment"}, []string{"trailing_comment"}},
		{"SELECT name FROM users WHERE id = 1 UNION SELECT password FROM admins", []string{"union"}, nil},
		{"SELECT 1; DROP TABLE users", []string{"stacked"}, nil},
		{"SELECT 1;", nil, []string{"stacked"}},
		{"SELECT a, b FROM t ORDER BY a OR 1", nil, []string{"or_tautology"}}, // not a condition
	}
	for _, c := range cases {
		r := Analyze(c.sql)
		for _, w := range c.want {
			if !has(r, w) {
				t.Errorf("%q: want %s, got %v", c.sql, w, r.Signals)
			}
		}
		for _, n := range c.not {
			if has(r, n) {
				t.Errorf("%q: did not want %s, got %v", c.sql, n, r.Signals)
			}
		}
	}
}

func FuzzAnalyze(f *testing.F) {
	for _, s := range []string{"SELECT 'unterminated", "x'", "[a", "\"a", "/* open", "-- c", "?1 :a @b $c", "0x", "1e", ".5e+", "->>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r := Analyze(s)
		if len(r.Shape) != 16 {
			t.Fatal("shape")
		}
		// a value never changes the shape when it is passed as a parameter
		q := "SELECT * FROM t WHERE a = ?"
		if Analyze(q).Shape != Analyze(strings.Replace(q, "?", "'"+strings.ReplaceAll(s, "'", "''")+"'", 1)).Shape {
			t.Fatalf("a quoted value changed the shape: %q", s)
		}
	})
}
