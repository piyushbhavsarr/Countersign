// Package store keeps the runtime's state: transaction journals, approvals, ownership,
// the audit chain, keys and small shared documents.
//
// Two backends behave the same way:
//
//   - Files (the default): one directory on one machine. Ownership is a kernel file lock
//     (flock), released by the kernel when the owning process dies.
//   - PostgreSQL: several gateway processes on several machines share one database, and
//     availability is the database's own (replication, failover, backups). Ownership is a
//     session advisory lock, released by the server when the owner's connection dies, so
//     crash recovery works across machines exactly as it does on one.
//
// Both serialise the audit chain: every appender links to the record actually last, under
// an exclusive lock (flock, or a transaction-scoped advisory lock).
package store

import (
	"errors"
)

// ErrNotFound: no such transaction.
var ErrNotFound = errors.New("not found")

// Lock is held ownership of one transaction.
type Lock interface{ Release() }

type Store interface {
	SaveTx(id string, doc []byte) error
	LoadTx(id string) ([]byte, error)
	ListTx() ([][]byte, error)
	// TryLock takes ownership of a transaction if no live process holds it.
	TryLock(id string) (Lock, bool)
	AppendApproval(id string, rec []byte) error
	Approvals(id string) ([][]byte, error)
	// AppendAudit appends the lines next(last line) returns, in order, atomically with
	// respect to every other appender, and makes them durable together (one sync).
	AppendAudit(next func(prev []byte) ([][]byte, error)) error
	AuditLines(fn func(line []byte) error) error
	// Key returns a named 32-byte secret, creating it once.
	Key(name string) ([]byte, error)
	// Get / Put: small documents shared by every node (nil, nil when absent).
	Get(name string) ([]byte, error)
	Put(name string, b []byte) error
	// Shared: whether other machines see this store.
	Shared() bool
	Close() error
}
