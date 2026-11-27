package tx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"undolayer/internal/audit"
	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/review"
	"undolayer/internal/store"
	"undolayer/internal/vault"
)

// DefaultOrder: data stores first, code next, infrastructure last.
var DefaultOrder = []string{"sql", "fs", "shell", "git", "http", "cloud", "effect"}

type Manager struct {
	// StateDir holds this node's local state (shadows, backups, plans); Store the
	// transaction state, which may be shared by several nodes.
	StateDir string
	Store    store.Store
	// Node names this gateway node (default: the host name). Tasks that touched node-local
	// resources are recovered only by their own node.
	Node   string
	Policy *policy.Policy
	Audit  *audit.Log
	// ApprovalWait > 0 lets a tool call wait this long for a reviewer's decision on an
	// action that needs approval (interactive approval). 0 = decide at commit only.
	ApprovalWait time.Duration
	// OnApprovalRequest, if set, is told about each pending decision (e.g. to notify a
	// reviewer); the decision itself still has to arrive through DecideAction.
	OnApprovalRequest func(txID string, a *model.Action)
	// Review, when it has reviewers, makes approvals signature-only: each decision must be
	// signed by a configured reviewer's key and satisfy the approval rules. Without it the
	// runtime is in single-user mode (an HMAC key in the state directory).
	Review *review.Config
	// Requester is who asks for the tasks this manager runs (default: the OS user). With
	// reviewers, the requester cannot approve their own task unless the config allows it.
	Requester string
	// Notify, if set, is called for each request that waits for a reviewer (an action or a
	// commit), with secrets already redacted.
	Notify func(PendingAction)
	// Vault, when set, keeps each change's before state on a quorum of replicas, written
	// before the change runs; a change whose before state cannot be stored does not run.
	Vault *vault.Vault

	mu          sync.Mutex
	connectors  map[string]Connector
	regOrder    []string
	approvalKey []byte
	txs         map[string]*Tx
	shapes      *shapeBook
}

func NewManager(stateDir string, pol *policy.Policy) (*Manager, error) {
	st, err := store.OpenFiles(stateDir)
	if err != nil {
		return nil, err
	}
	return NewManagerWithStore(st, stateDir, pol)
}

// NewManagerWithStore keeps transaction state in st (e.g. PostgreSQL, shared by nodes).
func NewManagerWithStore(st store.Store, stateDir string, pol *policy.Policy) (*Manager, error) {
	if pol == nil {
		pol = policy.Default()
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(stateDir, 0o700)
	host, _ := os.Hostname()
	m := &Manager{StateDir: stateDir, Store: st, Node: host, Policy: pol, connectors: map[string]Connector{}, txs: map[string]*Tx{}}
	ak, err := st.Key("audit.key")
	if err != nil {
		return nil, err
	}
	path := ""
	if f, ok := st.(*store.Files); ok {
		path = filepath.Join(f.Dir, "audit.jsonl")
	}
	m.Audit = audit.New(st, ak, path)
	if m.approvalKey, err = st.Key("approver.key"); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) audit(event string, data map[string]any) {
	_ = m.Audit.Record(event, normalizeMap(data))
}

func normalizeMap(d map[string]any) map[string]any {
	b, _ := json.Marshal(d)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func (m *Manager) Register(c Connector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.connectors[c.Name()]; !ok {
		m.regOrder = append(m.regOrder, c.Name())
	}
	m.connectors[c.Name()] = c
}

func (m *Manager) Connector(name string) (Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.connectors[name]
	if !ok {
		return nil, fmt.Errorf("no connector named %q", name)
	}
	return c, nil
}

func (m *Manager) Connectors() map[string]Connector {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]Connector{}
	for k, v := range m.connectors {
		out[k] = v
	}
	return out
}

func (m *Manager) ordered() []Connector {
	m.mu.Lock()
	names := append([]string{}, m.regOrder...)
	m.mu.Unlock()
	out := []Connector{}
	for _, n := range m.CommitOrder(names) {
		c, _ := m.Connector(n)
		out = append(out, c)
	}
	return out
}

func (m *Manager) CommitOrder(names []string) []string {
	rank := map[string]int{}
	for i, n := range DefaultOrder {
		rank[n] = i
	}
	out := append([]string{}, names...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, ok := rank[out[i]]
		if !ok {
			ri = len(rank)
		}
		rj, ok := rank[out[j]]
		if !ok {
			rj = len(rank)
		}
		if ri != rj {
			return ri < rj
		}
		return out[i] < out[j]
	})
	return out
}

// TryOwn takes ownership if no live process holds it.
func (m *Manager) TryOwn(t *Tx) bool {
	if t.owner != nil {
		return true
	}
	l, ok := m.Store.TryLock(t.ID)
	if !ok {
		return false
	}
	t.owner = l
	return true
}

func (m *Manager) Begin(task string) *Tx {
	t := newTx(m, task, "")
	t.Requester, t.Node = m.Requester, m.Node
	t.owner, _ = m.Store.TryLock(t.ID)
	m.mu.Lock()
	m.txs[t.ID] = t
	m.mu.Unlock()
	m.audit("begin", map[string]any{"tx": t.ID, "task": task})
	m.Journal(t)
	return t
}

func (m *Manager) Get(id string) (*Tx, error) {
	m.mu.Lock()
	if t, ok := m.txs[id]; ok {
		m.mu.Unlock()
		return t, nil
	}
	m.mu.Unlock()
	b, err := m.Store.LoadTx(id)
	if err != nil {
		return nil, fmt.Errorf("unknown transaction %s", id)
	}
	return fromJournal(m, b)
}

type Summary struct {
	ID      string  `json:"id"`
	Task    string  `json:"task"`
	State   string  `json:"state"`
	Actions int     `json:"actions"`
	Created float64 `json:"created"`
}

func (m *Manager) List() []Summary {
	docs, _ := m.Store.ListTx()
	out := []Summary{}
	for _, b := range docs {
		var d struct {
			ID, Task, State string
			Actions         []json.RawMessage
			Created         float64
		}
		if json.Unmarshal(b, &d) == nil && d.ID != "" {
			out = append(out, Summary{d.ID, d.Task, d.State, len(d.Actions), d.Created})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created < out[j].Created })
	return out
}

func (m *Manager) journalState(id string) string {
	b, err := m.Store.LoadTx(id)
	if err != nil {
		return ""
	}
	var d struct{ State string }
	_ = json.Unmarshal(b, &d)
	return d.State
}

// Journal writes the transaction's state durably (write-ahead: before effects run).
func (m *Manager) Journal(t *Tx) {
	if err := m.journal(t); err != nil {
		fmt.Fprintln(os.Stderr, "undolayer: journal:", err)
	}
}

// journal is Journal that reports failure: used where going on without a durable journal
// would break write-ahead (right before a connector applies its change).
func (m *Manager) journal(t *Tx) error {
	t.journaled, t.journalDirty = time.Now(), false
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return m.Store.SaveTx(t.ID, b)
}

// ---------------------------------------------------------------- approvals

func (m *Manager) ApprovalToken(id, hash string) string {
	h := hmac.New(sha256.New, m.approvalKey)
	h.Write([]byte(id + ":" + hash))
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) addApproval(id string, rec map[string]any) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return m.Store.AppendApproval(id, b)
}

func (m *Manager) approvals(id string) []map[string]any {
	lines, err := m.Store.Approvals(id)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, line := range lines {
		var r map[string]any
		if json.Unmarshal(line, &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

// ---------------------------------------------------------------- recovery

type Recovered struct {
	Tx      string   `json:"tx"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Errors  []string `json:"errors"`
	Unknown []Step   `json:"unknown_steps"`
}

// Recover resolves transactions whose owning process died. Live ones are left alone.
func (m *Manager) Recover() []Recovered {
	out := []Recovered{}
	for _, s := range m.List() {
		state := model.TxState(s.State)
		if state.Terminal() {
			continue
		}
		m.mu.Lock()
		_, mine := m.txs[s.ID]
		m.mu.Unlock()
		if mine {
			continue
		}
		t, err := m.Get(s.ID)
		if err != nil || !m.recoverable(t) || !m.TryOwn(t) {
			continue
		}
		errs := []string{}
		unknown := t.reconcileSteps()
		if state == model.Committing {
			errs = append(errs, t.undoApplied()...)
		}
		names := t.touchedNames()
		for i := len(names) - 1; i >= 0; i-- {
			c, _ := m.Connector(names[i])
			if c != nil {
				if err := c.Recover(t); err != nil {
					errs = append(errs, err.Error())
				}
			}
		}
		for _, o := range t.Outbox {
			if o.Status == "held" {
				o.Status = "cancelled"
			}
		}
		errs = append(errs, t.runCompensations()...)
		t.State = model.RolledBack
		if len(errs) > 0 {
			t.State = model.Failed
		}
		m.audit("recovered", map[string]any{"tx": t.ID, "from_state": s.State, "errors": errs})
		t.finish()
		out = append(out, Recovered{Tx: t.ID, From: s.State, To: string(t.State), Errors: errs, Unknown: unknown})
	}
	return out
}

type Released struct {
	Tx     string         `json:"tx"`
	Outbox []OutboxReport `json:"outbox"`
}

// FlushDue releases delayed effects whose time has come; run periodically.
func (m *Manager) FlushDue() []Released {
	out := []Released{}
	for _, s := range m.List() {
		if s.State != string(model.Committed) {
			continue
		}
		t, err := m.Get(s.ID)
		if err != nil {
			continue
		}
		pending := false
		for _, o := range t.Outbox {
			pending = pending || o.Status == "scheduled" || o.Status == "failed" || o.Status == "held"
		}
		if !pending || !m.TryOwn(t) {
			continue
		}
		rep := []OutboxReport{}
		for _, r := range t.FlushOutbox(0) {
			if r.Status != "scheduled" {
				rep = append(rep, r)
			}
		}
		m.Journal(t)
		still := false
		for _, o := range t.Outbox {
			still = still || o.Status == "scheduled" || o.Status == "failed"
		}
		if !still {
			t.Release()
		}
		if len(rep) > 0 {
			out = append(out, Released{Tx: t.ID, Outbox: rep})
		}
	}
	return out
}

// NodeLocal is implemented by connectors whose resources exist only on the node that ran
// the task (a workspace, a local database file, a sandbox): another node must not
// recover such a task, because the same path there is a different thing.
type NodeLocal interface{ NodeLocal() bool }

// recoverable: this node may recover t (it ran here, or everything it touched is shared).
func (m *Manager) recoverable(t *Tx) bool {
	if t.Node == "" || t.Node == m.Node {
		return true
	}
	for _, name := range t.touchedNames() {
		c, err := m.Connector(name)
		if err != nil {
			return false // a connector this node does not have
		}
		if nl, ok := c.(NodeLocal); ok && nl.NodeLocal() {
			return false
		}
	}
	return true
}
