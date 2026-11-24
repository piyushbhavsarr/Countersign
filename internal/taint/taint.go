// Package taint tracks sensitive data by provenance, plus scanner-flagged values.
//
// A value is sensitive when it is a token of a sensitive source (delegated credential
// secrets, VCS-ignored files, operator-declared paths) and not a token of the ordinary
// corpus (tracked files). Tokens come from splitting on whitespace and syntactic
// delimiters, never from recognisers. Sensitive values are redacted from every tool
// result and refused on egress. Scanner hits (gitleaks) are a second tier: they send
// egress to approval and are never redacted.
package taint

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
)

const delimiters = " \t\r\n\f\v=:\"'`,;@/\\()[]{}<>|&!?*"

func Tokens(text string, minLen int) map[string]struct{} {
	out := map[string]struct{}{}
	for _, f := range strings.FieldsFunc(text, func(r rune) bool { return strings.ContainsRune(delimiters, r) }) {
		if len(f) >= minLen {
			out[f] = struct{}{}
		}
	}
	return out
}

type Index struct {
	mu      sync.RWMutex
	MinLen  int
	values  map[string]string
	public  map[string]struct{}
	flagged map[string]string
	Scanner string
}

func New(minLen int) *Index {
	return &Index{MinLen: minLen, values: map[string]string{}, public: map[string]struct{}{},
		flagged: map[string]string{}, Scanner: "not run"}
}

func (x *Index) AddPublic(text string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for t := range Tokens(text, x.MinLen) {
		x.public[t] = struct{}{}
		delete(x.values, t)
	}
}

func (x *Index) AddSource(text, label string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for t := range Tokens(text, x.MinLen) {
		if _, pub := x.public[t]; !pub {
			if _, ok := x.values[t]; !ok {
				x.values[t] = label
			}
		}
	}
}

// AddValue: an exact secret (delegated credential), sensitive even if short.
func (x *Index) AddValue(v, label string) {
	if v == "" {
		return
	}
	x.mu.Lock()
	x.values[v] = label
	x.mu.Unlock()
}

func (x *Index) AddFlagged(v, label string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if _, ok := x.values[v]; v != "" && !ok {
		if _, ok := x.flagged[v]; !ok {
			x.flagged[v] = label
		}
	}
}

// FragmentLen is the shortest piece of a secret that counts as leaking it: a third of
// the value, but never shorter than 12 characters (or the whole value, if shorter).
func FragmentLen(v string) int {
	k := (len(v) + 2) / 3
	if k < 12 {
		k = 12
	}
	if k > len(v) {
		k = len(v)
	}
	return k
}

// containsFragment reports whether blob holds any FragmentLen-long piece of v.
func containsFragment(blob, v string) bool {
	k := FragmentLen(v)
	for i := 0; i+k <= len(v); i++ {
		if strings.Contains(blob, v[i:i+k]) {
			return true
		}
	}
	return false
}

func labelsIn(m map[string]string, blob string) []string {
	set := map[string]bool{}
	for v, l := range m {
		if containsFragment(blob, v) {
			set[l] = true
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Sources lists the files (labels) that contributed sensitive values, and their values.
func (x *Index) Values() map[string]string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := make(map[string]string, len(x.values))
	for k, v := range x.values {
		out[k] = v
	}
	return out
}

func (x *Index) LabelsIn(blob string) []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return labelsIn(x.values, blob)
}

func (x *Index) FlaggedIn(blob string) []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return labelsIn(x.flagged, blob)
}

func (x *Index) sortedValues() []string {
	vs := make([]string, 0, len(x.values))
	for v := range x.values {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return len(vs[i]) > len(vs[j]) })
	return vs
}

// Redact returns a copy of obj with every sensitive value replaced, and the count.
func (x *Index) Redact(obj any) (any, int) {
	x.mu.RLock()
	vs := x.sortedValues()
	x.mu.RUnlock()
	var walk func(any) (any, int)
	walk = func(o any) (any, int) {
		switch v := o.(type) {
		case string:
			n := 0
			for _, s := range vs {
				if c := strings.Count(v, s); c > 0 {
					n += c
					v = strings.ReplaceAll(v, s, "[REDACTED:"+x.values[s]+"]")
				}
			}
			return v, n
		case map[string]any:
			out, total := make(map[string]any, len(v)), 0
			for k, e := range v {
				r, n := walk(e)
				out[k], total = r, total+n
			}
			return out, total
		case []any:
			out, total := make([]any, len(v)), 0
			for i, e := range v {
				r, n := walk(e)
				out[i], total = r, total+n
			}
			return out, total
		case []map[string]any:
			out, total := make([]any, len(v)), 0
			for i, e := range v {
				r, n := walk(e)
				out[i], total = r, total+n
			}
			return out, total
		}
		return o, 0
	}
	return walk(obj)
}

func (x *Index) Fingerprints() []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := []string{}
	for v := range x.values {
		h := sha256.Sum256([]byte(v))
		out = append(out, hex.EncodeToString(h[:8]))
	}
	sort.Strings(out)
	return out
}

func (x *Index) Len() int { x.mu.RLock(); defer x.mu.RUnlock(); return len(x.values) }
