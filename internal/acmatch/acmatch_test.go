package acmatch

import (
	"math/rand"
	"sort"
	"strings"
	"testing"
)

func naive(pats []string, text string) []int {
	var out []int
	for i, p := range pats {
		if strings.Contains(text, p) {
			out = append(out, i)
		}
	}
	return out
}

func got(m *Matcher, text string) []int {
	var out []int
	m.Find(text, func(id int) { out = append(out, id) })
	sort.Ints(out)
	return out
}

// The same answers as strings.Contains for every pattern, across rebuilds.
func TestMatchesContainsExactly(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	alpha := "abcab\"{}:,"
	word := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[r.Intn(len(alpha))]
		}
		return string(b)
	}
	m := &Matcher{}
	var pats []string
	for round := 0; round < 2000; round++ {
		p := word(1 + r.Intn(6))
		pats = append(pats, p)
		m.Add(p)
		text := word(r.Intn(40))
		want, have := naive(pats, text), got(m, text)
		if len(want) != len(have) {
			t.Fatalf("round %d text %q: want %v got %v", round, text, want, have)
		}
		for i := range want {
			if want[i] != have[i] {
				t.Fatalf("round %d text %q: want %v got %v", round, text, want, have)
			}
		}
	}
}

func FuzzMatcher(f *testing.F) {
	f.Add("abc", "xxabcxx", "bc")
	f.Fuzz(func(t *testing.T, a, text, b string) {
		pats := []string{a, b, a + b, text}
		m := &Matcher{}
		for _, p := range pats {
			m.Add(p)
		}
		m.build()
		want, have := naive(pats, text), got(m, text)
		if len(want) != len(have) {
			t.Fatalf("want %v got %v", want, have)
		}
	})
}

func BenchmarkFind10k(b *testing.B) {
	m := &Matcher{}
	for i := 0; i < 10000; i++ {
		m.Add("value-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + "-" + string(rune('0'+i%10)))
	}
	text := `{"sql":"SELECT * FROM t WHERE id = ?","params":["value-xxa-3"]}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Find(text, func(int) {})
	}
}
