package tx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"undolayer/internal/model"
	"undolayer/internal/vault"
)

// The vault keeps, before a change runs, what the change will destroy or replace: row
// images, dropped tables and columns, the connector's own undo record. The rule is
// enforced here, at commit: a connector's change runs only after its before state is on
// a write quorum of vault replicas. If the vault cannot take it, nothing is applied.

// RowDescriber lists, from one of its undo records, the net change the task made to each
// row: what it was before and what it became.
type RowDescriber interface {
	DescribeRows(record json.RawMessage) ([]vault.Row, error)
}

// vaultEntry builds the vault entry for one connector's undo record.
func (t *Tx) vaultEntry(name, phase, ref string, raw json.RawMessage) (vault.Entry, error) {
	e := vault.Entry{Tx: t.ID, Task: t.Task, Requester: t.Requester, Connector: name, Phase: phase, Ref: ref, Undo: raw}
	if raw == nil {
		return e, nil
	}
	c, err := t.Mgr.Connector(name)
	if err != nil {
		return e, err
	}
	if d, ok := c.(RowDescriber); ok {
		rows, err := d.DescribeRows(raw)
		if err != nil {
			return e, fmt.Errorf("describing the change for the vault: %v", err)
		}
		e.Rows = rows
	}
	return e, nil
}

// vaultAppend stores an entry and anchors where it went in the audit chain.
func (t *Tx) vaultAppend(e vault.Entry) (*vault.Receipt, error) {
	if t.Mgr.Vault == nil {
		return nil, nil
	}
	rc, err := t.Mgr.Vault.Append(e)
	if err != nil {
		t.Mgr.audit("vault_append_failed", map[string]any{"tx": t.ID, "connector": e.Connector, "phase": e.Phase,
			"error": err.Error()})
		return nil, err
	}
	t.Mgr.audit("vault_append", map[string]any{"tx": t.ID, "connector": e.Connector, "phase": e.Phase,
		"batch": rc.Batch, "first_seq": rc.FirstSeq, "last_seq": rc.LastSeq, "last_sum": rc.LastSum,
		"copies": rc.Copies, "replicas": rc.Replicas, "rows": len(e.Rows)})
	return rc, nil
}

// vaultSettle records, after a connector committed or failed to, how its intent ended. The
// change has already happened (or not), so a failure here cannot stop anything: it is
// audited and reported, and the intent (which holds the complete record) stands.
func (t *Tx) vaultSettle(name, phase, ref string, intent, final json.RawMessage) {
	if t.Mgr.Vault == nil {
		return
	}
	var e vault.Entry
	var err error
	if phase == "committed" && final != nil && (intent == nil || !bytes.Equal(intent, final)) {
		e, err = t.vaultEntry(name, phase, ref, final)
	} else {
		e = vault.Entry{Tx: t.ID, Task: t.Task, Requester: t.Requester, Connector: name, Phase: phase, Ref: ref}
	}
	if err == nil {
		_, err = t.vaultAppend(e)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "undolayer: vault: recording that %s %s for %s: %v\n", name, phase, t.ID, err)
	}
}

// ChangedRows is what a task changed in one connector, as kept by the journal or vault.
type ChangedRows struct {
	Tx        string        `json:"tx"`
	Connector string        `json:"connector"`
	State     model.TxState `json:"state"`
	Source    string        `json:"source"` // journal | vault
	Undone    bool          `json:"undone"` // already put back by undo
	// Settled (vault only): how the commit of this intent ended: committed, failed, or ""
	// when the vault holds no settlement (then State, from the journal, tells).
	Settled string `json:"settled,omitempty"`
	// Shredded: the vault key that sealed it was destroyed on purpose; Error: it could not
	// be opened for another reason.
	Shredded bool            `json:"shredded,omitempty"`
	Error    string          `json:"error,omitempty"`
	Rows     []vault.Row     `json:"rows"`
	Record   json.RawMessage `json:"-"`
}

// ChangedRows returns, for a task, every connector's net change, with the undo record that
// can put it back. It reads the journal first; if the task's journal is gone or holds no
// record, it reads the vault.
func (m *Manager) ChangedRows(id string) ([]ChangedRows, error) {
	var out []ChangedRows
	t, err := m.Get(id)
	if err == nil {
		add := func(r *UndoRecord, undone bool) error {
			cr := ChangedRows{Tx: id, Connector: r.Connector, State: t.State, Source: "journal", Undone: undone, Record: r.Record}
			if c, err := m.Connector(r.Connector); err == nil {
				if d, ok := c.(RowDescriber); ok {
					rows, err := d.DescribeRows(r.Record)
					if err != nil {
						return err
					}
					cr.Rows = rows
				}
			}
			out = append(out, cr)
			return nil
		}
		for _, r := range t.UndoRecords {
			if err := add(r, false); err != nil {
				return nil, err
			}
		}
		for _, r := range t.AppliedUndo {
			if err := add(r, true); err != nil {
				return nil, err
			}
		}
		if len(out) > 0 || m.Vault == nil {
			return out, nil
		}
	}
	if m.Vault == nil {
		return nil, err
	}
	bs, verr := m.Vault.ForTx(id)
	if verr != nil {
		return nil, verr
	}
	// per connector: the committed record if one was written, else the intent. An intent
	// settled as failed most likely changed nothing; it is still listed, with its state.
	byBatch := map[string]*vault.Batch{}
	for _, b := range bs {
		byBatch[b.Batch] = b
	}
	settled := map[string]string{}
	for _, b := range bs {
		if b.Ref != "" {
			settled[b.Ref] = b.Phase
		}
	}
	state := model.TxState("unknown")
	if t != nil {
		state = t.State
	}
	for _, b := range bs {
		if b.Phase != "intent" || !b.Complete {
			continue
		}
		cr := ChangedRows{Tx: id, Connector: b.Connector, State: state, Source: "vault", Rows: b.Rows, Record: b.Undo,
			Shredded: b.Shredded, Error: b.Error}
		cr.Settled = settled[b.Batch]
		switch settled[b.Batch] {
		case "committed":
			for _, c := range bs {
				if c.Ref == b.Batch && c.Phase == "committed" && c.Complete && len(c.Undo) > 0 && c.Error == "" {
					cr.Rows, cr.Record = c.Rows, c.Undo
				}
			}
		}
		out = append(out, cr)
	}
	if len(out) == 0 {
		if err != nil {
			return nil, fmt.Errorf("%s: no journal and nothing in the vault", id)
		}
		return nil, nil
	}
	return out, nil
}
