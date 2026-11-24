// Package threeway reverts one change to a JSON document while keeping everyone else's.
//
// Given the document before a change, right after it, and now, Revert puts back exactly
// the fields the change touched, and leaves fields changed since by anyone else alone. A
// field the change touched that someone changed again since is a conflict: there is no
// right answer without a person, so nothing is written. This is git revert, for JSON.
//
// Objects are compared key by key. Arrays are compared element by element when the
// change did not alter their length and nobody has since; otherwise an array is one
// value (an insertion shifts every index, so per-index paths would mean nothing).
package threeway

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Path is a list of object keys (string) and array indexes (int).
type Path []any

func (p Path) String() string {
	var b strings.Builder
	for _, e := range p {
		switch x := e.(type) {
		case int:
			b.WriteString("[" + strconv.Itoa(x) + "]")
		default:
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(fmt.Sprint(x))
		}
	}
	if b.Len() == 0 {
		return "(root)"
	}
	return b.String()
}

// absent marks a field that does not exist.
type absentT struct{}

var absent = absentT{}

// Changes lists the leaf paths where before and after differ.
func Changes(before, after any) []Path {
	var out []Path
	walk(before, after, nil, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func walk(a, b any, p Path, out *[]Path) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		for k := range keys {
			av, ain := am[k]
			bv, bin := bm[k]
			if !ain {
				av = absent
			}
			if !bin {
				bv = absent
			}
			walk(av, bv, append(append(Path{}, p...), k), out)
		}
		return
	}
	al, aok := a.([]any)
	bl, bok := b.([]any)
	if aok && bok && len(al) == len(bl) {
		for i := range al {
			walk(al[i], bl[i], append(append(Path{}, p...), i), out)
		}
		return
	}
	if !equal(a, b) {
		*out = append(*out, p)
	}
}

// Get returns the value at p, and whether it exists.
func Get(v any, p Path) (any, bool) {
	cur := v
	for _, e := range p {
		switch k := e.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			if cur, ok = m[k]; !ok {
				return nil, false
			}
		case int:
			l, ok := cur.([]any)
			if !ok || k >= len(l) {
				return nil, false
			}
			cur = l[k]
		}
	}
	return cur, true
}

func value(v any, p Path) any {
	if x, ok := Get(v, p); ok {
		return x
	}
	return absent
}

// set writes (or, for absent, removes) the value at p inside a deep copy's structure.
func set(doc any, p Path, val any) (any, error) {
	if len(p) == 0 {
		if val == absent {
			return nil, nil
		}
		return val, nil
	}
	switch k := p[0].(type) {
	case string:
		m, ok := doc.(map[string]any)
		if !ok {
			if val == absent {
				return doc, nil
			}
			m = map[string]any{}
		}
		child, exists := m[k]
		if !exists && len(p) > 1 {
			if val == absent {
				return m, nil
			}
			if _, isIdx := p[1].(int); isIdx {
				return nil, fmt.Errorf("cannot restore %s: its array no longer exists", p)
			}
			child = map[string]any{}
		}
		nv, err := set(child, p[1:], val)
		if err != nil {
			return nil, err
		}
		if nv == nil && val == absent && len(p) == 1 {
			delete(m, k)
		} else {
			m[k] = nv
		}
		return m, nil
	case int:
		l, ok := doc.([]any)
		if !ok || k >= len(l) {
			return nil, fmt.Errorf("cannot restore %s: the array changed shape", p)
		}
		nv, err := set(l[k], p[1:], val)
		if err != nil {
			return nil, err
		}
		l[k] = nv
		return l, nil
	}
	return nil, fmt.Errorf("bad path %s", p)
}

// Conflict is a field the change touched that someone changed again since.
type Conflict struct {
	Path   string `json:"path"`
	Before any    `json:"before"`
	After  any    `json:"after"`
	Now    any    `json:"now"`
}

// Revert returns now with the change before -> after reverted, or the conflicts.
// Fields the change touched that already hold their before value are left as they are.
func Revert(before, after, now any) (any, []Conflict, error) {
	result := deepCopy(now)
	var conflicts []Conflict
	for _, p := range Changes(before, after) {
		if q, ok := reshaped(after, now, p); ok { // an array on the way changed length since
			conflicts = append(conflicts, Conflict{Path: q.String(), Before: show(value(before, q)),
				After: show(value(after, q)), Now: show(value(now, q))})
			continue
		}
		b, a, n := value(before, p), value(after, p), value(now, p)
		switch {
		case equal(n, a):
			var err error
			if result, err = set(result, p, b); err != nil {
				return nil, nil, err
			}
		case equal(n, b):
			// already back to how it was
		default:
			conflicts = append(conflicts, Conflict{Path: p.String(), Before: show(b), After: show(a), Now: show(n)})
		}
	}
	if len(conflicts) > 0 {
		return nil, conflicts, nil
	}
	return result, nil, nil
}

// reshaped: the first array along p whose length differs between after and now, if any.
func reshaped(after, now any, p Path) (Path, bool) {
	for i, e := range p {
		if _, isIdx := e.(int); !isIdx {
			continue
		}
		q := p[:i]
		al, _ := value(after, q).([]any)
		nl, nok := value(now, q).([]any)
		if !nok || len(al) != len(nl) {
			return append(Path{}, q...), true
		}
	}
	return nil, false
}

// Touched reports the fields of a change that someone has changed since before: the
// check before applying a staged change to a document others may have edited.
func Touched(before, after, now any) []Conflict {
	var out []Conflict
	for _, p := range Changes(before, after) {
		if b, n := value(before, p), value(now, p); !equal(b, n) {
			out = append(out, Conflict{Path: p.String(), Before: show(b), After: show(value(after, p)), Now: show(n)})
		}
	}
	return out
}

func show(v any) any {
	if v == absent {
		return "(absent)"
	}
	return v
}

func equal(a, b any) bool {
	if a == absent || b == absent {
		return a == b
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func deepCopy(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}
