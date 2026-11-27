// Package mysqlgw is Countersign as a MySQL gateway: applications and agents connect to it
// with any MySQL driver, as to the database.
//
//   - Protect and block: each statement is judged by the gateway policy (injection signs,
//     time delays, file access, destroying schema, privileges, dynamic SQL, routines,
//     server administration, tampering with capture); a transaction is judged again before
//     its COMMIT, on what it actually changed.
//   - Undo: triggers the gateway installs and keeps in step with the schema record every
//     changed row, before and after, into a per-session temporary table. Before COMMIT is
//     passed on, the rows are read, checked against the tables' current columns, and
//     stored in the vault on a quorum. No quorum, no commit. A write outside a transaction
//     runs in one the gateway opens. A statement that changed rows nothing recorded (a
//     table without triggers yet) is refused, and its transaction cannot commit.
//
// Foreign key actions (ON DELETE CASCADE, SET NULL) change rows InnoDB never shows to
// triggers, so a change that would set them off is refused at commit.
package mysqlgw

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"

	"undolayer/internal/connectors/mysql"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

//go:embed policy.toml
var defaultPolicy string

// Route is one MySQL gateway listener.
type Route struct {
	Name   string `toml:"name"`
	Listen string `toml:"listen"`
	// URI of the server with the gateway's own credentials: mysql://countersign:pw@db:3306/app.
	// The gateway needs TRIGGER and CREATE TEMPORARY TABLES on the databases it captures.
	URI string `toml:"uri"`
	// Databases captured (default: the URI's). Writes elsewhere are refused.
	Databases []string          `toml:"databases"`
	Mode      string            `toml:"mode"` // enforce (default) | watch
	Users     map[string]string `toml:"users"`
	Trust     bool              `toml:"trust"` // loopback only: any user, no password
	Policy    string            `toml:"policy"`
	// SyncEvery: how often the triggers are checked against the schema (default 10s).
	SyncEvery time.Duration `toml:"sync_every"`
}

type Gateway struct {
	R    Route
	M    *tx.Manager
	Conn *mysql.Connector
	A    mysql.Addr
	pol  *policy.Policy
	srv  *server.Server
	auth server.AuthenticationHandler
	an   analyzer

	adminMu sync.Mutex
	admin   *client.Conn

	casMu   sync.Mutex
	cas     map[string]casEntry
	sizesMu sync.Mutex
	sizes   map[string]sizeEntry

	closed atomic.Bool
	stop   chan struct{}
	stats  struct{ statements, refused, commits atomic.Int64 }
}

type casEntry struct {
	m  map[string]*mysql.Cascade
	at time.Time
}

type sizeEntry struct {
	n  float64
	at time.Time
}

// trustAll lets any user in without a password (loopback only).
type trustAll struct{}

func (trustAll) GetCredential(string) (server.Credential, bool, error) {
	return server.Credential{Passwords: []string{""}, AuthPluginName: gomysql.AUTH_NATIVE_PASSWORD}, true, nil
}
func (trustAll) OnAuthSuccess(*server.Conn) error  { return nil }
func (trustAll) OnAuthFailure(*server.Conn, error) {}

func New(r Route, m *tx.Manager) (*Gateway, error) {
	if r.Name == "" || r.Listen == "" || r.URI == "" {
		return nil, errors.New("[[mysql_gateway]] needs name, listen and uri")
	}
	if r.Mode == "" {
		r.Mode = "enforce"
	}
	if r.Mode != "enforce" && r.Mode != "watch" {
		return nil, fmt.Errorf("[[mysql_gateway]] %s: mode is enforce or watch", r.Name)
	}
	if r.SyncEvery <= 0 {
		r.SyncEvery = 10 * time.Second
	}
	a, err := mysql.ParseURI(r.URI)
	if err != nil {
		return nil, fmt.Errorf("[[mysql_gateway]] %s: %v", r.Name, err)
	}
	if len(r.Databases) == 0 {
		if a.DB == "" {
			return nil, fmt.Errorf("[[mysql_gateway]] %s: name the database in the uri, or list databases", r.Name)
		}
		r.Databases = []string{a.DB}
	}
	g := &Gateway{R: r, M: m, A: a, an: analyzer{m: map[string]*stmtInfo{}}, cas: map[string]casEntry{},
		sizes: map[string]sizeEntry{}, stop: make(chan struct{})}
	if r.Trust {
		host, _, _ := net.SplitHostPort(r.Listen)
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("[[mysql_gateway]] %s: trust is allowed only on a loopback address", r.Name)
		}
		g.auth = trustAll{}
	} else {
		if len(r.Users) == 0 {
			return nil, fmt.Errorf("[[mysql_gateway]] %s: list users, or set trust on a loopback address", r.Name)
		}
		h := server.NewInMemoryAuthenticationHandler(gomysql.AUTH_NATIVE_PASSWORD)
		for u, p := range r.Users {
			if err := h.AddUser(u, p); err != nil {
				return nil, err
			}
		}
		g.auth = h
	}
	g.srv = server.NewDefaultServer()
	pol, err := policy.Parse(defaultPolicy)
	if err != nil {
		return nil, err
	}
	if r.Policy != "" {
		if pol, err = policy.Load(r.Policy); err != nil {
			return nil, err
		}
	}
	g.pol = pol
	g.Conn = mysql.New("gw-"+r.Name, a)
	return g, nil
}

// Sync installs capture on every captured database (and remakes triggers whose table
// changed).
func (g *Gateway) Sync() error {
	g.adminMu.Lock()
	defer g.adminMu.Unlock()
	var last error
	for try := 0; try < 2; try++ {
		if g.admin == nil {
			c, err := mysql.Dial(g.A, "")
			if err != nil {
				return err
			}
			g.admin = c
		}
		last = nil
		for _, db := range g.R.Databases {
			made, err := mysql.Sync(g.admin, db)
			if err != nil {
				last = err
				break
			}
			if len(made) > 0 {
				g.M.Audit.Note("gateway_capture_installed", map[string]any{"gateway": g.R.Name, "database": db, "tables": made})
			}
		}
		if last == nil {
			return nil
		}
		g.admin.Close()
		g.admin = nil
	}
	return last
}

// Serve installs capture, then accepts connections until l is closed.
func (g *Gateway) Serve(l net.Listener) error {
	if err := g.Sync(); err != nil {
		return fmt.Errorf("installing capture: %v", err)
	}
	go func() {
		t := time.NewTicker(g.R.SyncEvery)
		defer t.Stop()
		for {
			select {
			case <-g.stop:
				return
			case <-t.C:
				if err := g.Sync(); err != nil {
					g.M.Audit.Note("gateway_capture_failed", map[string]any{"gateway": g.R.Name, "error": err.Error()})
				}
			}
		}
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if g.closed.Load() {
				return nil
			}
			return err
		}
		go g.handle(c)
	}
}

func (g *Gateway) Close() {
	if g.closed.CompareAndSwap(false, true) {
		close(g.stop)
	}
	if g.M.Vault != nil {
		_ = g.M.Vault.Flush()
	}
	g.adminMu.Lock()
	if g.admin != nil {
		g.admin.Close()
		g.admin = nil
	}
	g.adminMu.Unlock()
}

func (g *Gateway) cascades(db string) map[string]*mysql.Cascade {
	g.casMu.Lock()
	e, ok := g.cas[db]
	g.casMu.Unlock()
	if ok && time.Since(e.at) < 10*time.Second {
		return e.m
	}
	g.adminMu.Lock()
	var m map[string]*mysql.Cascade
	var err error
	if g.admin != nil {
		m, err = mysql.Cascades(g.admin, db)
	}
	g.adminMu.Unlock()
	if err != nil || m == nil {
		return e.m
	}
	g.casMu.Lock()
	g.cas[db] = casEntry{m: m, at: time.Now()}
	g.casMu.Unlock()
	return m
}

func (g *Gateway) tableSize(up *client.Conn, db, t string) float64 {
	k := db + "." + t
	g.sizesMu.Lock()
	e, ok := g.sizes[k]
	g.sizesMu.Unlock()
	if ok && time.Since(e.at) < time.Minute {
		return e.n
	}
	r, err := up.Execute("SELECT COALESCE(TABLE_ROWS, 0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = " +
		mysql.Lit(db) + " AND TABLE_NAME = " + mysql.Lit(t))
	n := 0.0
	if err == nil && r.RowNumber() > 0 {
		v, _ := r.GetInt(0, 0)
		n = float64(v)
	}
	g.sizesMu.Lock()
	g.sizes[k] = sizeEntry{n: n, at: time.Now()}
	g.sizesMu.Unlock()
	return n
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "gwy_" + hex.EncodeToString(b)
}
