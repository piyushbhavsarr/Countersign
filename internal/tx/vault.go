package tx

import (
	"bytes"
	"encoding/json"
	"errors"
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
	t.Mgr.note("vault_append", map[string]any{"tx": t.ID, "connector": e.Connector, "phase": e.Phase,
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
	if err != nil {
		fmt.Fprintf(os.Stderr, "undolayer: vault: recording that %s %s for %s: %v\n", name, phase, t.ID, err)
		return
	}
	t.Mgr.vaultLater(func() {
		if _, err := t.vaultAppend(e); err != nil {
			fmt.Fprintf(os.Stderr, "undolayer: vault: recording that %s %s for %s: %v\n", name, phase, t.ID, err)
		}
	})
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
	Batch    string          `json:"-"` // the vault intent it comes from
	Rows     []vault.Row     `json:"rows"`
	Record   json.RawMessage `json:"-"`
}

// ChangedRows returns, for a task, every connector's net change, with the undo record that
// can put it back. It reads the journal first; if the task's journal is gone or holds no
// record, it reads the vault.
func (m *Manager) ChangedRows(id string) ([]ChangedRows, error) {
	m.later.Wait() // this process's own background vault writes first
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
		// calls that reached the outside: what was sent, what came back, how to compensate
		byID := map[string]*model.Action{}
		for _, a := range t.Actions {
			byID[a.ID] = a
		}
		comped := map[string]bool{}
		for _, c := range t.Compensations {
			if a := byID[c.ActionID]; a != nil {
				comped[a.ID] = true
				res := a.Result
				for _, o := range t.Outbox {
					if o.Action.ID == a.ID && o.Result != nil {
						res = o.Result
					}
				}
				out = append(out, ChangedRows{Tx: id, Connector: c.Connector, State: t.State, Source: "journal", Undone: c.Done,
					Rows: []vault.Row{callRow(a, res)}, Record: c.Record})
			}
		}
		for _, o := range t.Outbox {
			if o.Status == "sent" && !comped[o.Action.ID] {
				a := o.Action
				out = append(out, ChangedRows{Tx: id, Connector: a.Connector, State: t.State, Source: "journal",
					Rows: []vault.Row{callRow(&a, o.Result)}})
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
	undone := map[string]bool{}
	for _, b := range bs {
		if b.Ref == "" {
			continue
		}
		if b.Phase == "undone" {
			undone[b.Ref] = true
		} else {
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
		cr.Settled, cr.Undone, cr.Batch = settled[b.Batch], undone[b.Batch], b.Batch
		if cr.Settled == "" && len(cr.Record) > 0 {
			// written before a commit whose outcome was not recorded: the system itself says
			if c, err := m.Connector(b.Connector); err == nil {
				if r, ok := c.(InFlightResolver); ok {
					if committed, known, err := r.ResolveInFlight(cr.Record); err == nil && known {
						cr.Settled = map[bool]string{true: "committed", false: "failed"}[committed]
					}
				}
			}
		}
		switch settled[b.Batch] {
		case "committed":
			for _, c := range bs {
				if c.Ref == b.Batch && c.Phase == "committed" && c.Complete && c.Error == "" {
					if len(c.Rows) > 0 {
						cr.Rows = c.Rows
					}
					if len(c.Undo) > 0 {
						cr.Record = c.Undo
					}
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

// Calls that reach the outside world at once (an API write in the compensable lane, a
// message, a webhook, a tool on another MCP server) have no staged before state to keep:
// what the vault keeps is the call itself. The request is stored before it is sent (no
// quorum, no call), and the response and the recipe that compensates it after.

func callRow(a *model.Action, result any) vault.Row {
	r := vault.Row{Table: a.Connector + "." + a.Operation, Op: "call", Key: map[string]any{"action_id": a.ID},
		Before: map[string]any{"request": normalize(a.Args), "effect": string(a.Effect)}}
	if k, ok := a.Facts["idempotency_key"].(string); ok && k != "" {
		r.Key["idempotency_key"] = k
	}
	if result != nil {
		r.After = map[string]any{"response": normalize(result)}
	}
	return r
}

// vaultCallIntent stores a call before it is made. An error means it must not be made.
func (t *Tx) vaultCallIntent(a *model.Action) (string, error) {
	if t.Mgr.Vault == nil {
		return "", nil
	}
	rc, err := t.vaultAppend(vault.Entry{Tx: t.ID, Task: t.Task, Requester: t.Requester, Connector: a.Connector,
		Phase: "intent", Rows: []vault.Row{callRow(a, nil)}})
	if err != nil {
		return "", fmt.Errorf("%s.%s: the vault could not store the request, so it was not sent: %v", a.Connector, a.Operation, err)
	}
	return rc.Batch, nil
}

// vaultCallDone records how a call ended: committed (with its response and compensation
// recipe) or failed.
func (t *Tx) vaultCallDone(a *model.Action, batch, phase string, result any, comp json.RawMessage) {
	if t.Mgr.Vault == nil || batch == "" {
		return
	}
	e := vault.Entry{Tx: t.ID, Task: t.Task, Requester: t.Requester, Connector: a.Connector, Phase: phase, Ref: batch, Undo: comp}
	if phase == "committed" {
		e.Rows = []vault.Row{callRow(a, result)}
	}
	t.Mgr.vaultLater(func() {
		if _, err := t.vaultAppend(e); err != nil {
			fmt.Fprintf(os.Stderr, "undolayer: vault: recording the result of %s.%s in %s: %v\n", a.Connector, a.Operation, t.ID, err)
		}
	})
}

// vaultLater runs a vault write that nothing waits for (how a change ended: the intent,
// written before it, already holds everything needed to put it back, and readers settle
// an intent from the task's journal when this record is missing). Flush waits for them.
func (m *Manager) vaultLater(fn func()) {
	m.later.Add(1)
	go func() {
		defer m.later.Done()
		fn()
	}()
}

// InFlightResolver tells whether a record written before a commit (by the gateway, which
// relays an application's own COMMIT) was committed by the system it describes.
type InFlightResolver interface {
	ResolveInFlight(record json.RawMessage) (committed, known bool, err error)
}

// Hidden connectors are not offered to agents as tools (the gateway's, which exist so
// that undo and restore can reach what the gateway recorded).
type Hidden interface{ Hidden() bool }

// UndoFromVault undoes a task known only from the vault (a gateway transaction): each
// committed change is put back with its connector's undo, which refuses if what it would
// restore changed since; then the vault records that it was undone.
func (m *Manager) UndoFromVault(id string) (*UndoReport, error) {
	if m.Vault == nil {
		return nil, fmt.Errorf("%s: no journal, and the vault is disabled", id)
	}
	crs, err := m.ChangedRows(id)
	if err != nil {
		return nil, err
	}
	rep := &UndoReport{Tx: id, Undone: []string{}, Compensated: []string{}, Cancelled: []string{},
		Conflicts: []map[string]any{}, Expired: []map[string]any{}, FailedParts: []map[string]any{},
		NotUndoable: []map[string]any{}, Warnings: []string{}}
	n := 0
	for i := len(crs) - 1; i >= 0; i-- {
		cr := crs[i]
		if cr.Source != "vault" || cr.Undone || len(cr.Record) == 0 || cr.Settled == "failed" {
			continue // already undone, or it never happened
		}
		n++
		c, err := m.Connector(cr.Connector)
		if err == nil {
			err = c.Undo(cr.Record)
		}
		var cc *model.CommitConflict
		switch {
		case err == nil:
			rep.Undone = append(rep.Undone, cr.Connector)
			if _, verr := m.Vault.Append(vault.Entry{Tx: id, Connector: cr.Connector, Phase: "undone", Ref: cr.Batch}); verr != nil {
				rep.Warnings = append(rep.Warnings, "undone, but the vault could not record it: "+verr.Error())
			}
		case errors.As(err, &cc):
			rep.Conflicts = append(rep.Conflicts, map[string]any{"connector": cr.Connector, "reason": err.Error()})
		default:
			rep.FailedParts = append(rep.FailedParts, map[string]any{"connector": cr.Connector, "reason": err.Error()})
		}
	}
	if n == 0 {
		return nil, fmt.Errorf("%s: nothing in the vault left to undo", id)
	}
	rep.State = model.Undone
	if !rep.Clean() {
		rep.State = model.Failed
	}
	m.audit("undo", map[string]any{"tx": id, "from": "vault", "clean": rep.Clean()})
	return rep, nil
}
