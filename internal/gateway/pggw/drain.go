package pggw

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"undolayer/internal/connectors/postgres"
	"undolayer/internal/vault"
)

// The drainer moves the fast lane's before states from the database's outbox to the vault,
// in the background: each committed transaction becomes one vault entry, then its outbox
// rows are deleted, in that order, so a crash at any point loses nothing (an entry stored
// twice is recognized by its id: gw_<route>_<xid>). It holds an advisory lock, so with
// several gateway nodes in front of one database one drains at a time. While the vault
// cannot take an entry the rows wait in the outbox, as durable as the data they describe,
// and applications keep running.

const drainLockKey = 0x436f756e // "Coun": the gateway's advisory lock

type drainer struct {
	g    *Gateway
	mu   sync.Mutex // one pass at a time
	conn *pgx.Conn
	pks  map[string][]string
	seen map[string]bool // ids stored since start (no vault lookup needed for them)
	wake chan struct{}

	lastErr    string
	lastDrain  time.Time
	recovering bool // since (re)connecting: entries may already be in the vault
}

func (g *Gateway) startDrainer() {
	if g.M.Vault == nil {
		return
	}
	g.drain = &drainer{g: g, pks: map[string][]string{}, seen: map[string]bool{}, wake: make(chan struct{}, 1)}
	g.bg.Add(1)
	go func() {
		defer g.bg.Done()
		idle := 5 * time.Millisecond
		for !g.closed.Load() {
			n, err := g.drain.pass()
			switch {
			case err != nil:
				idle = min(max(idle*2, 50*time.Millisecond), 2*time.Second)
			case n >= 5000:
				idle = 0 // a backlog: keep going
			case n > 0:
				idle = 10 * time.Millisecond // batch what comes in the meantime into the next write
			default:
				idle = min(max(idle*2, 5*time.Millisecond), 100*time.Millisecond)
			}
			if idle > 0 {
				select {
				case <-g.drain.wake:
				case <-time.After(idle):
				}
			}
		}
	}()
}

// Drain moves everything committed in the outbox to the vault now (tests, shutdown).
func (g *Gateway) Drain() error {
	if g.drain == nil {
		return nil
	}
	for {
		n, err := g.drain.pass()
		if err != nil || n == 0 {
			return err
		}
	}
}

func (d *drainer) connect() error {
	if d.conn != nil && !d.conn.IsClosed() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dsn, err := d.g.topo.target(false)
	if err != nil {
		return err
	}
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	var got bool
	if err := c.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", int64(drainLockKey)).Scan(&got); err != nil || !got {
		c.Close(ctx)
		if err == nil {
			err = fmt.Errorf("another gateway node is draining")
		}
		return err
	}
	d.conn, d.recovering = c, true
	return nil
}

type outRow struct {
	seq           int64
	xid           int64
	usr, tbl, op  string
	oldRow, newRw string
}

// pass moves up to one batch of committed transactions; it returns how many rows it moved.
func (d *drainer) pass() (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.connect(); err != nil {
		d.lastErr = err.Error()
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fail := func(err error) (int, error) {
		d.lastErr = err.Error()
		if d.conn != nil {
			d.conn.Close(context.Background())
			d.conn = nil
		}
		return 0, err
	}
	// whole transactions only: the xids of the oldest rows, then every row of each
	rows, err := d.conn.Query(ctx, `SELECT seq, xid, coalesce(usr, ''), tbl, op, coalesce(old_row::text, ''), coalesce(new_row::text, '')
		FROM undolayer.outbox WHERE xid IN (SELECT DISTINCT xid FROM (SELECT xid FROM undolayer.outbox ORDER BY seq LIMIT 5000) f)
		ORDER BY xid, seq`)
	if err != nil {
		return fail(err)
	}
	var all []outRow
	for rows.Next() {
		var r outRow
		if err := rows.Scan(&r.seq, &r.xid, &r.usr, &r.tbl, &r.op, &r.oldRow, &r.newRw); err != nil {
			rows.Close()
			return fail(err)
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fail(err)
	}
	if len(all) == 0 {
		d.lastErr, d.lastDrain = "", time.Now()
		return 0, nil
	}
	// group by transaction
	var groups [][]outRow
	for i := 0; i < len(all); {
		j := i
		for j < len(all) && all[j].xid == all[i].xid {
			j++
		}
		groups = append(groups, all[i:j])
		i = j
	}
	tables := map[string]bool{}
	for _, r := range all {
		tables[r.tbl] = true
	}
	if err := d.lookupPKs(ctx, tables); err != nil {
		return fail(err)
	}
	// every transaction of the pass is stored at once: the vault's group commit puts them
	// in one write (one flush to disk for the pass, not one per transaction)
	var done []int64
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	stored := make([]bool, len(groups))
	for i, grp := range groups {
		id := fmt.Sprintf("gw_%s_%d", d.g.R.Name, grp[0].xid)
		if d.recovering && !d.seen[id] && d.inVault(id) {
			d.seen[id] = true
		}
		if d.seen[id] {
			stored[i] = true
			continue
		}
		wg.Add(1)
		go func(i int, id string, grp []outRow) {
			defer wg.Done()
			if err := d.store(id, grp); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			stored[i] = true
		}(i, id, grp)
	}
	wg.Wait()
	for i, grp := range groups {
		if !stored[i] {
			continue // stays in the outbox: the next pass tries again
		}
		d.seen[fmt.Sprintf("gw_%s_%d", d.g.R.Name, grp[0].xid)] = true
		for _, r := range grp {
			done = append(done, r.seq)
		}
	}
	if len(d.seen) > 1_000_000 {
		d.seen = map[string]bool{}
	}
	if len(done) == 0 && firstErr != nil {
		return fail(firstErr)
	}
	if _, err := d.conn.Exec(ctx, "DELETE FROM undolayer.outbox WHERE seq = ANY($1)", done); err != nil {
		return fail(err)
	}
	d.lastErr, d.lastDrain, d.recovering = "", time.Now(), false
	return len(done), nil
}

// inVault: whether an entry with this id is stored already (a pass cut short after storing).
func (d *drainer) inVault(id string) bool {
	bs, err := d.g.M.Vault.ForTx(id)
	return err == nil && len(bs) > 0
}

func (d *drainer) lookupPKs(ctx context.Context, tables map[string]bool) error {
	for t := range tables {
		if _, ok := d.pks[t]; ok {
			continue
		}
		rows, err := d.conn.Query(ctx, `SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
			WHERE i.indrelid = $1::regclass AND i.indisprimary ORDER BY array_position(i.indkey, a.attnum)`, t)
		if err != nil {
			return err
		}
		var cols []string
		for rows.Next() {
			var c string
			_ = rows.Scan(&c)
			cols = append(cols, c)
		}
		rows.Close()
		d.pks[t] = cols
	}
	if len(d.pks) > 10_000 {
		d.pks = map[string][]string{}
	}
	return nil
}

// store writes one committed transaction to the vault, as the strict lane would have,
// marked committed.
func (d *drainer) store(id string, grp []outRow) error {
	var events []postgres.Event
	tables := map[string]bool{}
	for _, r := range grp {
		pk := d.pks[r.tbl]
		tables[r.tbl] = true
		ev := postgres.Event{T: r.tbl}
		switch r.op {
		case "INSERT":
			ev.Op, ev.New, ev.KN = "I", r.newRw, postgres.KeyOf(r.newRw, pk)
		case "UPDATE":
			ev.Op, ev.Old, ev.New, ev.KO, ev.KN = "U", r.oldRow, r.newRw, postgres.KeyOf(r.oldRow, pk), postgres.KeyOf(r.newRw, pk)
		case "DELETE":
			ev.Op, ev.Old, ev.KO = "D", r.oldRow, postgres.KeyOf(r.oldRow, pk)
		}
		events = append(events, ev)
	}
	rec := &postgres.UndoRecord{DSN: d.g.Conn.RecordDSN(), XID: grp[0].xid,
		Changes: []*postgres.Change{{ActionID: "gateway", Events: events}}}
	raw, _ := json.Marshal(rec)
	rows, err := d.g.Conn.DescribeRows(raw)
	if err != nil {
		return err
	}
	var tl []string
	for t := range tables {
		tl = append(tl, t)
	}
	sort.Strings(tl)
	user := grp[0].usr
	rc, err := d.g.M.Vault.Append(vault.Entry{Tx: id, Task: "gateway " + d.g.R.Name + " (fast lane): " + strings.Join(tl, ", ") +
		", " + strconv.Itoa(len(grp)) + " rows", Requester: user, Connector: d.g.Conn.Name(), Phase: "intent", Rows: rows, Undo: raw})
	if err != nil {
		return err
	}
	d.g.M.Vault.AppendLater(vault.Entry{Tx: id, Requester: user, Connector: d.g.Conn.Name(), Phase: "committed", Ref: rc.Batch})
	d.g.stats.commits.Add(1)
	d.g.M.Audit.Note("gateway_commit", map[string]any{"tx": id, "gateway": d.g.R.Name, "user": user, "outcome": "committed",
		"lane": "fast", "rows": len(grp)})
	return nil
}

// DrainStatus says how far behind the vault is.
type DrainStatus struct {
	LastError string    `json:"last_error,omitempty"`
	LastDrain time.Time `json:"last_drain"`
}

func (g *Gateway) DrainStatus() DrainStatus {
	if g.drain == nil {
		return DrainStatus{}
	}
	g.drain.mu.Lock()
	defer g.drain.mu.Unlock()
	return DrainStatus{LastError: g.drain.lastErr, LastDrain: g.drain.lastDrain}
}
