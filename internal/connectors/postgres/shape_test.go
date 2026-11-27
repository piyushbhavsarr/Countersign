package postgres

import (
	"fmt"
	"testing"
)

func signals(t *testing.T, sql string) []string {
	t.Helper()
	f, err := Analyze(sql)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	s, _ := f["sql_injection_signals"].([]string)
	return s
}

func hasSig(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Injection signs from PostgreSQL's own parse tree (no server needed).
func TestPGInjectionSignsFromTheParseTree(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
		not  []string
	}{
		{"SELECT * FROM u WHERE email = 'x' OR 'a' = 'a'", []string{"or_tautology"}, nil},
		{"SELECT * FROM u WHERE id = 5 OR 1 = 1", []string{"or_tautology"}, nil},
		{"DELETE FROM u WHERE id = 5 OR true", []string{"or_tautology"}, nil},
		{"SELECT * FROM u WHERE id = 5 OR 'yes'::boolean", []string{"or_tautology"}, nil},
		{"SELECT * FROM u WHERE id = 5 OR id = id", []string{"or_tautology"}, nil},
		{"SELECT * FROM u WHERE 1 = 1 AND id = 5", nil, []string{"or_tautology"}},
		{"SELECT * FROM u WHERE a = 1 OR b = 1", nil, []string{"or_tautology"}},
		{"SELECT * FROM u WHERE note = 'x OR 1=1 -- union'", nil, []string{"or_tautology", "comment", "union"}},
		{"SELECT * FROM u WHERE email = 'a' -- ' AND pw = 'x'", []string{"comment", "trailing_comment"}, nil},
		{"SELECT email FROM u UNION SELECT passwd FROM pg_shadow", []string{"union", "system_catalog"}, nil},
		{"SELECT * FROM information_schema.tables", []string{"system_catalog"}, nil},
		{"SELECT pg_sleep(10)", []string{"time_delay"}, nil},
		{"SELECT pg_catalog.pg_read_file('/etc/passwd')", []string{"file_or_program"}, nil},
		{"COPY u TO PROGRAM 'curl evil'", []string{"file_or_program"}, nil},
		{"SELECT 1; DROP TABLE u", []string{"stacked"}, nil},
		{"DO $$ BEGIN PERFORM 1; -- not a comment of the statement\nEND $$", nil, []string{"comment"}},
	}
	for _, c := range cases {
		s := signals(t, c.sql)
		for _, w := range c.want {
			if !hasSig(s, w) {
				t.Errorf("%q: want %s, got %v", c.sql, w, s)
			}
		}
		for _, n := range c.not {
			if hasSig(s, n) {
				t.Errorf("%q: did not want %s, got %v", c.sql, n, s)
			}
		}
	}
	a, _ := Analyze("SELECT * FROM u WHERE id = 1")
	b, _ := Analyze("SELECT * FROM u WHERE id = 99")
	c, _ := Analyze("SELECT * FROM u WHERE id = 1 OR 1 = 1")
	if a["query_shape"] != b["query_shape"] || a["query_shape"] == c["query_shape"] || a["query_shape"] == nil {
		t.Fatalf("shapes: %v %v %v", a["query_shape"], b["query_shape"], c["query_shape"])
	}
}

// The cache hands out copies: what a caller adds is not seen by the next caller.
func TestPGAnalyzeCacheIsolation(t *testing.T) {
	q := "UPDATE u SET plan = 'x' WHERE id = 3"
	a, _ := Analyze(q)
	a["env"] = "mutated"
	a["tables_written"].([]string)[0] = "mutated"
	b, _ := Analyze(q)
	if b["env"] != nil || fmt.Sprint(b["tables_written"]) != "[u]" {
		t.Fatalf("cache leaked a caller's change: %v", b)
	}
}
