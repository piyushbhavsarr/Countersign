package tx

import (
	"encoding/json"

	"undolayer/internal/model"
	"undolayer/internal/taint"
)

// OpSchema describes one operation as an MCP tool.
type OpSchema struct {
	Description string         `json:"description"`
	Properties  map[string]any `json:"properties"`
	Required    []string       `json:"required"`
}

// Connector knows, for one kind of system, how to classify, stage, preview, prepare,
// commit, roll back and undo. Embed Base for the defaults.
type Connector interface {
	Name() string
	Operations() map[string]OpSchema
	Egress() bool
	Classify(t *Tx, op string, args map[string]any) (model.Effect, model.Facts, error)
	Stage(t *Tx, a *model.Action) (any, error)
	RunDeferred(t *Tx, a *model.Action) (any, error)
	Compensate(record json.RawMessage) error
	Settle(t *Tx, a *model.Action)
	Discard(t *Tx, a *model.Action) bool
	ContributeSensitive(t *Tx, idx *taint.Index)
	Preview(t *Tx) map[string]any
	Totals(t *Tx) map[string]float64
	Prepare(t *Tx) error
	Commit(t *Tx) (any, error)
	Rollback(t *Tx) error
	Undo(record json.RawMessage) error
	Recover(t *Tx) error
}

// Contained is implemented by connectors whose staging of an operation changes nothing
// outside this process and the transactions it holds (a held database transaction, a
// shadow copy, a server-side dry run): if the process dies, the staged change vanishes
// with it. Such calls need no journal write of their own before or after (group commit);
// the journal is still written before anything that can escape, and at least every second.
type Contained interface{ Contained(op string) bool }

// Intender commits with write-ahead undo: Intent returns the complete undo record, computed
// from what was staged, before anything is applied; the runtime journals it, then calls
// Commit. If the process dies in between or during Commit, recovery calls UndoInFlight
// with that record, which must leave the system as it was before the commit whether none,
// some or all of it had been applied (and refuse, as a conflict, anything it cannot tell).
type Intender interface {
	Intent(t *Tx) (any, error)
	UndoInFlight(record json.RawMessage) error
}

// Reconciler answers, after a crash, whether a step logged "about to run" happened.
type Reconciler interface {
	Reconcile(t *Tx, a *model.Action, key string) (Reconciled, error)
}

type Reconciled struct {
	Status string // done | not_run | unknown
	Reason string
	Comp   *Compensation
}

// Staged is what Stage returns when an eagerly executed action recorded its way back.
type Staged struct {
	Result any
	Comp   *Compensation
}

// Compensation is a recorded way back for a step that ran for real.
type Compensation struct {
	Kind        string   // reversible | compensable
	Record      any      // connector-defined, journaled as JSON
	SideEffects []string // what cannot be taken back even after compensating
}

type Base struct{ ConnName string }

func (b Base) Name() string                  { return b.ConnName }
func (Base) Operations() map[string]OpSchema { return nil }
func (Base) Egress() bool                    { return false }
func (Base) RunDeferred(*Tx, *model.Action) (any, error) {
	return nil, errString("cannot run deferred")
}
func (Base) Compensate(json.RawMessage) error      { return errString("no compensation") }
func (Base) Settle(*Tx, *model.Action)             {}
func (Base) Discard(*Tx, *model.Action) bool       { return false }
func (Base) ContributeSensitive(*Tx, *taint.Index) {}
func (Base) Preview(*Tx) map[string]any            { return nil }
func (Base) Totals(*Tx) map[string]float64         { return nil }
func (Base) Prepare(*Tx) error                     { return nil }
func (Base) Commit(*Tx) (any, error)               { return nil, nil }
func (Base) Rollback(*Tx) error                    { return nil }
func (Base) Undo(json.RawMessage) error            { return errString("no post-commit undo") }
func (b Base) Recover(t *Tx) error                 { return nil }
func (Base) Stage(*Tx, *model.Action) (any, error) { return nil, errString("not stageable") }

type errString string

func (e errString) Error() string { return string(e) }
