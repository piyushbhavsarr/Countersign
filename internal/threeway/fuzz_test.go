package threeway

import (
	"encoding/json"
	"testing"
)

// Properties that must hold for every input, not just the ones we thought of:
//  1. Revert(before, after, after) == before          (undo of an untouched change restores it)
//  2. Revert never touches a field the change did not touch
//  3. Revert(b, a, n) either conflicts or yields a document where every changed path is back
func FuzzRevert(f *testing.F) {
	seeds := [][3]string{
		{`{"a":1}`, `{"a":2}`, `{"a":2,"b":3}`},
		{`{"s":{"r":1,"i":"v1"}}`, `{"s":{"r":1,"i":"v2"}}`, `{"s":{"r":5,"i":"v2"}}`},
		{`{"l":[1,2,3]}`, `{"l":[1,9,3]}`, `{"l":[1,9,3,4]}`},
		{`{"x":null}`, `{}`, `{"y":1}`},
		{`[]`, `[1]`, `[1]`},
		{`1`, `2`, `3`},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, bs, as, ns string) {
		var b, a, n any
		if json.Unmarshal([]byte(bs), &b) != nil || json.Unmarshal([]byte(as), &a) != nil || json.Unmarshal([]byte(ns), &n) != nil {
			return
		}
		// 1
		got, cs, err := Revert(b, a, a)
		if err == nil && len(cs) == 0 && !equal(got, b) {
			t.Fatalf("undo of an untouched change did not restore: before %s after %s got %s", bs, as, js(got))
		}
		// 2 and 3
		got, cs, err = Revert(b, a, n)
		if err != nil || len(cs) > 0 {
			return
		}
		changed := map[string]bool{}
		for _, p := range Changes(b, a) {
			changed[p.String()] = true
			if !equal(value(got, p), value(b, p)) {
				t.Fatalf("path %s not restored: before %s after %s now %s got %s", p, bs, as, ns, js(got))
			}
		}
		for _, p := range Changes(n, got) {
			inside := false
			for c := range changed {
				if under(p.String(), c) {
					inside = true
				}
			}
			if !inside {
				t.Fatalf("revert touched %s, which the change never did: before %s after %s now %s got %s", p, bs, as, ns, js(got))
			}
		}
	})
}

// under: p is c or inside it (or c inside p, when a whole subtree was restored).
func under(p, c string) bool {
	if p == c || c == "(root)" || p == "(root)" {
		return true
	}
	return len(p) > len(c) && p[:len(c)] == c && (p[len(c)] == '.' || p[len(c)] == '[') ||
		len(c) > len(p) && c[:len(p)] == p && (c[len(p)] == '.' || c[len(p)] == '[')
}
