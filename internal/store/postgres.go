package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres keeps state in PostgreSQL, shared by every gateway that uses the same database.
type Postgres struct {
	pool *pgxpool.Pool
	// locks are session advisory locks on one dedicated connection: if this process dies
	// or loses the connection, the server releases them and another node may recover.
	lmu   sync.Mutex
	lconn *pgx.Conn
	dsn   string
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS undolayer_tx (
	id text PRIMARY KEY, doc jsonb NOT NULL, updated timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS undolayer_approvals (
	seq bigserial PRIMARY KEY, tx text NOT NULL, rec jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS undolayer_approvals_tx ON undolayer_approvals (tx, seq);
CREATE TABLE IF NOT EXISTS undolayer_audit (seq bigserial PRIMARY KEY, line text NOT NULL);
CREATE TABLE IF NOT EXISTS undolayer_keys (name text PRIMARY KEY, value bytea NOT NULL);
CREATE TABLE IF NOT EXISTS undolayer_shared (name text PRIMARY KEY, value bytea NOT NULL);
`

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func OpenPostgres(dsn string) (*Postgres, error) {
	c, cancel := ctx()
	defer cancel()
	pool, err := pgxpool.New(c, dsn)
	if err != nil {
		return nil, fmt.Errorf("state store: %v", err)
	}
	// one node creates the tables at a time
	if _, err := pool.Exec(c, `SELECT pg_advisory_lock($1)`, lockKey("schema")); err != nil {
		pool.Close()
		return nil, fmt.Errorf("state store: %v", err)
	}
	_, err = pool.Exec(c, schemaSQL)
	_, _ = pool.Exec(c, `SELECT pg_advisory_unlock($1)`, lockKey("schema"))
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("state store schema: %v", err)
	}
	p := &Postgres{pool: pool, dsn: dsn}
	if err := p.lockConn(); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

func (p *Postgres) lockConn() error {
	if p.lconn != nil && !p.lconn.IsClosed() {
		return nil
	}
	c, cancel := ctx()
	defer cancel()
	conn, err := pgx.Connect(c, p.dsn)
	if err != nil {
		return fmt.Errorf("state store lock connection: %v", err)
	}
	p.lconn = conn
	return nil
}

func lockKey(s string) int64 {
	h := fnv.New64a()
	h.Write([]byte("undolayer:" + s))
	return int64(h.Sum64())
}

func (p *Postgres) Shared() bool { return true }

func (p *Postgres) Close() error {
	p.lmu.Lock()
	if p.lconn != nil {
		c, cancel := ctx()
		_ = p.lconn.Close(c)
		cancel()
	}
	p.lmu.Unlock()
	p.pool.Close()
	return nil
}

func (p *Postgres) SaveTx(id string, doc []byte) error {
	c, cancel := ctx()
	defer cancel()
	_, err := p.pool.Exec(c, `INSERT INTO undolayer_tx (id, doc) VALUES ($1, $2)
		ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc, updated = now()`, id, string(doc))
	return err
}

func (p *Postgres) LoadTx(id string) ([]byte, error) {
	c, cancel := ctx()
	defer cancel()
	var doc string
	err := p.pool.QueryRow(c, `SELECT doc::text FROM undolayer_tx WHERE id = $1`, id).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return []byte(doc), err
}

func (p *Postgres) ListTx() ([][]byte, error) {
	c, cancel := ctx()
	defer cancel()
	rows, err := p.pool.Query(c, `SELECT doc::text FROM undolayer_tx ORDER BY (doc->>'created')::float8`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, []byte(d))
	}
	return out, rows.Err()
}

type pgLock struct {
	p   *Postgres
	key int64
	gen *pgx.Conn // the connection that holds it
}

func (l *pgLock) Release() {
	l.p.lmu.Lock()
	defer l.p.lmu.Unlock()
	if l.gen != nil && l.gen == l.p.lconn && !l.gen.IsClosed() {
		c, cancel := ctx()
		_, _ = l.gen.Exec(c, `SELECT pg_advisory_unlock($1)`, l.key)
		cancel()
	}
	l.gen = nil
}

// Held reports whether the lock's connection is still alive (if it is not, the server has
// released the lock and another node may have taken the transaction over).
func (l *pgLock) Held() bool {
	l.p.lmu.Lock()
	defer l.p.lmu.Unlock()
	if l.gen == nil || l.gen != l.p.lconn || l.gen.IsClosed() {
		return false
	}
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.gen.Ping(c) == nil
}

func (p *Postgres) TryLock(id string) (Lock, bool) {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	if err := p.lockConn(); err != nil {
		return nil, false
	}
	c, cancel := ctx()
	defer cancel()
	k := lockKey("tx:" + id)
	var ok bool
	if err := p.lconn.QueryRow(c, `SELECT pg_try_advisory_lock($1)`, k).Scan(&ok); err != nil || !ok {
		return nil, false
	}
	return &pgLock{p: p, key: k, gen: p.lconn}, true
}

func (p *Postgres) AppendApproval(id string, rec []byte) error {
	c, cancel := ctx()
	defer cancel()
	_, err := p.pool.Exec(c, `INSERT INTO undolayer_approvals (tx, rec) VALUES ($1, $2)`, id, string(rec))
	return err
}

func (p *Postgres) Approvals(id string) ([][]byte, error) {
	c, cancel := ctx()
	defer cancel()
	rows, err := p.pool.Query(c, `SELECT rec::text FROM undolayer_approvals WHERE tx = $1 ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, []byte(r))
	}
	return out, rows.Err()
}

func (p *Postgres) AppendAudit(next func(prev []byte) ([]byte, error)) error {
	c, cancel := ctx()
	defer cancel()
	tx, err := p.pool.Begin(c)
	if err != nil {
		return err
	}
	defer tx.Rollback(c) //nolint:errcheck
	if _, err := tx.Exec(c, `SELECT pg_advisory_xact_lock($1)`, lockKey("audit")); err != nil {
		return err
	}
	var prev []byte
	var last string
	switch err := tx.QueryRow(c, `SELECT line FROM undolayer_audit ORDER BY seq DESC LIMIT 1`).Scan(&last); {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return err
	default:
		prev = []byte(last)
	}
	line, err := next(prev)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(c, `INSERT INTO undolayer_audit (line) VALUES ($1)`, string(line)); err != nil {
		return err
	}
	return tx.Commit(c)
}

func (p *Postgres) AuditLines(fn func(line []byte) error) error {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	rows, err := p.pool.Query(c, `SELECT line FROM undolayer_audit ORDER BY seq`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			return err
		}
		if err := fn([]byte(l)); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (p *Postgres) Key(name string) ([]byte, error) {
	c, cancel := ctx()
	defer cancel()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if _, err := p.pool.Exec(c, `INSERT INTO undolayer_keys (name, value) VALUES ($1, $2) ON CONFLICT DO NOTHING`, name, k); err != nil {
		return nil, err
	}
	var v []byte
	err := p.pool.QueryRow(c, `SELECT value FROM undolayer_keys WHERE name = $1`, name).Scan(&v)
	return v, err
}

func (p *Postgres) Get(name string) ([]byte, error) {
	c, cancel := ctx()
	defer cancel()
	var v []byte
	err := p.pool.QueryRow(c, `SELECT value FROM undolayer_shared WHERE name = $1`, name).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

func (p *Postgres) Put(name string, b []byte) error {
	c, cancel := ctx()
	defer cancel()
	_, err := p.pool.Exec(c, `INSERT INTO undolayer_shared (name, value) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value`, name, b)
	return err
}
