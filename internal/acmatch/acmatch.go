// Package acmatch finds which of many strings occur in a text, in one pass over the text
// (Aho-Corasick), however many strings there are. Patterns are added at any time: the
// automaton is rebuilt when the patterns added since the last build reach a quarter of it,
// and those few are checked directly until then, so adding stays cheap and every lookup
// gives exactly the answer of checking each pattern with strings.Contains.
package acmatch

import "strings"

type node struct {
	next map[byte]int32
	fail int32
	out  []int32 // pattern ids ending here (including through fail links)
}

// Matcher holds the patterns.
type Matcher struct {
	pats    []string
	built   int // patterns in the automaton
	nodes   []node
	pending []int32
}

// Add adds a pattern and returns its id (ids are 0, 1, 2, ... in the order added).
func (m *Matcher) Add(p string) int {
	id := len(m.pats)
	m.pats = append(m.pats, p)
	m.pending = append(m.pending, int32(id))
	if len(m.pending) > 64 && len(m.pending)*8 > m.built {
		m.build()
	}
	return id
}

// Len is the number of patterns.
func (m *Matcher) Len() int { return len(m.pats) }

func (m *Matcher) build() {
	m.nodes = []node{{next: map[byte]int32{}}}
	for id, p := range m.pats {
		if p == "" {
			continue
		}
		cur := int32(0)
		for i := 0; i < len(p); i++ {
			nx, ok := m.nodes[cur].next[p[i]]
			if !ok {
				m.nodes = append(m.nodes, node{next: map[byte]int32{}})
				nx = int32(len(m.nodes) - 1)
				m.nodes[cur].next[p[i]] = nx
			}
			cur = nx
		}
		m.nodes[cur].out = append(m.nodes[cur].out, int32(id))
	}
	// breadth-first: fail links and inherited outputs
	queue := []int32{}
	for _, nx := range m.nodes[0].next {
		m.nodes[nx].fail = 0
		queue = append(queue, nx)
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for c, v := range m.nodes[u].next {
			f := m.nodes[u].fail
			for {
				if nx, ok := m.nodes[f].next[c]; ok && nx != v {
					m.nodes[v].fail = nx
					break
				}
				if f == 0 {
					m.nodes[v].fail = 0
					break
				}
				f = m.nodes[f].fail
			}
			m.nodes[v].out = append(m.nodes[v].out, m.nodes[m.nodes[v].fail].out...)
			queue = append(queue, v)
		}
	}
	m.built = len(m.pats)
	m.pending = m.pending[:0]
}

// Find calls fn once for each id whose pattern occurs in text (an empty pattern occurs in
// every text).
func (m *Matcher) Find(text string, fn func(id int)) {
	seen := map[int32]bool{}
	if m.nodes != nil {
		cur := int32(0)
		for i := 0; i < len(text); i++ {
			c := text[i]
			for {
				if nx, ok := m.nodes[cur].next[c]; ok {
					cur = nx
					break
				}
				if cur == 0 {
					break
				}
				cur = m.nodes[cur].fail
			}
			for _, id := range m.nodes[cur].out {
				if !seen[id] {
					seen[id] = true
					fn(int(id))
				}
			}
		}
	}
	for id, p := range m.pats[:m.built] {
		if p == "" && !seen[int32(id)] {
			seen[int32(id)] = true
			fn(id)
		}
	}
	for _, id := range m.pending {
		if !seen[id] && strings.Contains(text, m.pats[id]) {
			seen[id] = true
			fn(int(id))
		}
	}
}
