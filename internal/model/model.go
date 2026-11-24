// Package model holds the data types shared by every layer of the runtime.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Effect is the lane an action runs in: how (and whether) it can be undone.
type Effect string

const (
	Read         Effect = "read"         // no side effects
	Reversible   Effect = "reversible"   // staged on a shadow copy, or run with an exact recorded inverse
	Compensable  Effect = "compensable"  // runs now; a fix recipe is recorded (refund, cancel)
	Deferrable   Effect = "deferrable"   // does not run: queued, released on commit
	Irreversible Effect = "irreversible" // a human approves the exact preview, then it runs on commit
)

type Decision string

const (
	Allow           Decision = "allow"
	Hold            Decision = "hold"
	RequireApproval Decision = "require_approval"
	Deny            Decision = "deny"
)

var DecisionRank = map[Decision]int{Allow: 0, Hold: 1, RequireApproval: 2, Deny: 3}

type TxState string

const (
	Open        TxState = "open"
	Prepared    TxState = "prepared"
	Committing  TxState = "committing"
	Committed   TxState = "committed"
	RollingBack TxState = "rolling_back"
	RolledBack  TxState = "rolled_back"
	Failed      TxState = "failed"
	Undone      TxState = "undone"
)

func (s TxState) Terminal() bool {
	return s == Committed || s == RolledBack || s == Undone || s == Failed
}

// Facts are what a classifier measured or was told about an action; policy matches on them.
type Facts map[string]any

// Action is one tool call as the runtime sees it.
type Action struct {
	ID        string         `json:"id"`
	TS        float64        `json:"ts"`
	Connector string         `json:"connector"`
	Operation string         `json:"operation"`
	Args      map[string]any `json:"args"`
	Effect    Effect         `json:"effect"`
	Facts     Facts          `json:"facts"`
	Decision  Decision       `json:"decision"`
	Reasons   []string       `json:"reasons"`
	Error     string         `json:"error,omitempty"`
	Result    any            `json:"-"`
}

func NewID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func Now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// ---------------------------------------------------------------- errors

type PolicyViolation struct{ Action *Action }

func (e *PolicyViolation) Error() string {
	if len(e.Action.Reasons) == 0 {
		return "denied by policy"
	}
	return strings.Join(e.Action.Reasons, "; ")
}

// CommitConflict: the real system changed under the transaction (or after it).
type CommitConflict struct{ Msg string }

func (e *CommitConflict) Error() string { return e.Msg }
func Conflict(format string, a ...any) error {
	return &CommitConflict{Msg: fmt.Sprintf(format, a...)}
}

type ApprovalRequired struct{ Msg string }

func (e *ApprovalRequired) Error() string { return e.Msg }

// NotOwner: this process does not own the transaction.
type NotOwner struct{ Msg string }

func (e *NotOwner) Error() string { return e.Msg }

// NotUndoable: an undo cannot be applied (window expired, no inverse).
type NotUndoable struct{ Msg string }

func (e *NotUndoable) Error() string { return e.Msg }

// Defer is returned by Stage when, on contact with the real system, the action turns
// out to have effects that cannot be staged; it is re-classified and held.
type Defer struct {
	Facts  Facts
	Reason string
}

func (e *Defer) Error() string { return "deferred to commit: " + e.Reason }

// Num turns any JSON-ish number into float64 (ok=false if v is not a number).
func Num(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case int32:
		return float64(x), true
	case uint64:
		return float64(x), true
	}
	return 0, false
}
