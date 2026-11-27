package tx

import (
	"encoding/json"
	"fmt"
	"sort"

	"undolayer/internal/model"
)

// Freezing a requester stops it everywhere at once: every call it makes, on every
// connector (databases, files, APIs, MCP tools, cloud), and every commit of a task it
// already started, are refused until it is unfrozen. The list lives in the state store,
// so every gateway node that shares the store sees it on the next call.

const frozenDoc = "frozen.json"

// Frozen is one frozen requester.
type Frozen struct {
	Requester string  `json:"requester"`
	By        string  `json:"by"`
	Reason    string  `json:"reason"`
	At        float64 `json:"at"`
}

func (m *Manager) frozenList() (map[string]Frozen, error) {
	b, err := m.Store.Get(frozenDoc)
	if err != nil || len(b) == 0 {
		return map[string]Frozen{}, err
	}
	out := map[string]Frozen{}
	return out, json.Unmarshal(b, &out)
}

// Freeze stops a requester everywhere.
func (m *Manager) Freeze(requester, by, reason string) error {
	l, err := m.frozenList()
	if err != nil {
		return err
	}
	l[requester] = Frozen{Requester: requester, By: by, Reason: reason, At: model.Now()}
	b, _ := json.Marshal(l)
	if err := m.Store.Put(frozenDoc, b); err != nil {
		return err
	}
	m.audit("freeze", map[string]any{"requester": requester, "by": by, "reason": reason})
	return nil
}

// Unfreeze lets a requester act again.
func (m *Manager) Unfreeze(requester, by string) error {
	l, err := m.frozenList()
	if err != nil {
		return err
	}
	if _, ok := l[requester]; !ok {
		return fmt.Errorf("%s is not frozen", requester)
	}
	delete(l, requester)
	b, _ := json.Marshal(l)
	if err := m.Store.Put(frozenDoc, b); err != nil {
		return err
	}
	m.audit("unfreeze", map[string]any{"requester": requester, "by": by})
	return nil
}

// FrozenRequesters lists who is frozen.
func (m *Manager) FrozenRequesters() ([]Frozen, error) {
	l, err := m.frozenList()
	out := []Frozen{}
	for _, f := range l {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requester < out[j].Requester })
	return out, err
}

// frozen returns why the task's requester is frozen, or "". A store that cannot be read
// counts as frozen: the switch must not fail open.
func (t *Tx) frozen() string {
	l, err := t.Mgr.frozenList()
	if err != nil {
		return "the freeze list cannot be read (" + err.Error() + "), so nothing runs"
	}
	if f, ok := l[t.Requester]; ok {
		return fmt.Sprintf("%s is frozen by %s: %s", f.Requester, f.By, f.Reason)
	}
	return ""
}
