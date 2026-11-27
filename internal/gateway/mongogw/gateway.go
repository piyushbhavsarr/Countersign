// Package mongogw is Countersign as a MongoDB gateway: it speaks the MongoDB wire protocol,
// so applications and agents connect to it as to the database.
//
//   - It presents itself to drivers as a router (mongos), so they never discover and
//     connect to the replica set members behind it, and sessions and transactions work.
//   - Protect and block: each command is judged by the gateway policy (server-side
//     JavaScript, collection drops, writes through aggregation, admin commands); a write
//     is judged again before it commits, on what it actually changed.
//   - Undo: every write runs in a transaction. Inside it the gateway reads the documents
//     the write will change, narrows the write to exactly those (_id), reads them again
//     after, and stores their before and after state in the vault on a quorum before the
//     transaction commits. No quorum, no commit. A client's own transactions are captured
//     statement by statement and stored at their commitTransaction.
//
// Exact capture needs transactions, so the server must be a replica set member (or a
// mongos); against a standalone server writes are refused in enforce mode. Through the
// gateway a multi-document write is atomic: one that fails part way changes nothing.
package mongogw

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	_ "embed"

	"undolayer/internal/connectors/mongo"
	"undolayer/internal/gateway/scram"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

//go:embed policy.toml
var defaultPolicy string

// Route is one MongoDB gateway listener.
type Route struct {
	Name   string `toml:"name"`
	Listen string `toml:"listen"`
	// URI of the server, with the gateway's own credentials, e.g.
	// mongodb://countersign:pw@db1:27017/?authSource=admin (one host: the gateway speaks
	// to it directly; point it at the primary or at a mongos).
	URI   string            `toml:"uri"`
	Mode  string            `toml:"mode"` // enforce (default) | watch
	Users map[string]string `toml:"users"`
	Trust bool              `toml:"trust"` // loopback only
	// Policy file (default: the built-in MongoDB gateway policy).
	Policy string `toml:"policy"`
	// MaxCaptureDocs: a write changing more documents is refused (default 100,000).
	MaxCaptureDocs int `toml:"max_capture_docs"`
}

// Gateway serves one route.
type Gateway struct {
	R      Route
	M      *tx.Manager
	Conn   *mongo.Connector
	pol    *policy.Policy
	users  map[string]*scram.Verifier
	addr   string
	user   string
	pass   string
	authDB string

	txMu sync.Mutex
	txs  map[string]*clientTx // a client transaction: lsid id + txnNumber

	counts sync.Map // ns -> collCount
	closed atomic.Bool
	bg     sync.WaitGroup
	reqID  atomic.Int32
	stats  struct{ commands, refused, commits atomic.Int64 }
}

type collCount struct {
	n  int64
	at time.Time
}

// clientTx is what a client's transaction changed so far.
type clientTx struct {
	changes []mongo.Change
	cmds    []string
	failed  string // a refusal inside the transaction: its commit is refused
}

func New(r Route, m *tx.Manager) (*Gateway, error) {
	if r.Name == "" || r.Listen == "" || r.URI == "" {
		return nil, errors.New("[[mongo_gateway]] needs name, listen and uri")
	}
	if r.Mode == "" {
		r.Mode = "enforce"
	}
	if r.Mode != "enforce" && r.Mode != "watch" {
		return nil, fmt.Errorf("[[mongo_gateway]] %s: mode is enforce or watch", r.Name)
	}
	if r.MaxCaptureDocs <= 0 {
		r.MaxCaptureDocs = 100_000
	}
	u, err := url.Parse(r.URI)
	if err != nil || u.Scheme != "mongodb" {
		return nil, fmt.Errorf("[[mongo_gateway]] %s: uri must be mongodb://host:port/...", r.Name)
	}
	if strings.Contains(u.Host, ",") {
		return nil, fmt.Errorf("[[mongo_gateway]] %s: give one host (the primary or a mongos)", r.Name)
	}
	g := &Gateway{R: r, M: m, users: map[string]*scram.Verifier{}, txs: map[string]*clientTx{}, addr: u.Host, authDB: "admin"}
	if u.User != nil {
		g.user = u.User.Username()
		g.pass, _ = u.User.Password()
	}
	if a := u.Query().Get("authSource"); a != "" {
		g.authDB = a
	}
	if r.Trust {
		host, _, _ := net.SplitHostPort(r.Listen)
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("[[mongo_gateway]] %s: trust is allowed only on a loopback address", r.Name)
		}
	} else if len(r.Users) == 0 {
		return nil, fmt.Errorf("[[mongo_gateway]] %s: list users, or set trust on a loopback address", r.Name)
	}
	for name, p := range r.Users {
		v, err := scram.NewVerifier(p)
		if err != nil {
			return nil, err
		}
		g.users[name] = v
	}
	text := defaultPolicy
	pol, err := policy.Parse(text)
	if err != nil {
		return nil, err
	}
	if r.Policy != "" {
		if pol, err = policy.Load(r.Policy); err != nil {
			return nil, err
		}
	}
	g.pol = pol
	g.Conn = mongo.New("gw-"+r.Name, r.URI)
	return g, nil
}

// Serve accepts connections until l is closed.
func (g *Gateway) Serve(l net.Listener) error {
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

// Close stops accepting and finishes background vault writes.
func (g *Gateway) Close() {
	g.closed.Store(true)
	g.bg.Wait()
	if g.M.Vault != nil {
		_ = g.M.Vault.Flush()
	}
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "gwm_" + hex.EncodeToString(b)
}

// upstream is one server connection.
type upstream struct {
	g    *Gateway
	conn net.Conn
	// a session of the gateway's own, for writes the client did not put in a transaction
	// and gave no transaction number for
	lsid  bson.Binary
	txnNo int64
	info  serverInfo
}

func (g *Gateway) dial() (*upstream, error) {
	c, err := net.DialTimeout("tcp", g.addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	u := &upstream{g: g, conn: c, lsid: bson.Binary{Subtype: 4, Data: id}}
	h, err := u.run("admin", bson.D{{Key: "hello", Value: 1}})
	if err != nil {
		c.Close()
		return nil, err
	}
	i32 := func(k string, def int32) int32 {
		if v, err := h.LookupErr(k); err == nil {
			if n, ok := v.AsInt64OK(); ok {
				return int32(n)
			}
		}
		return def
	}
	u.info = serverInfo{maxWire: i32("maxWireVersion", 21), maxBSON: i32("maxBsonObjectSize", 16<<20),
		maxMsg: i32("maxMessageSizeBytes", 48000000), maxBatch: i32("maxWriteBatchSize", 100000),
		sessionMins: i32("logicalSessionTimeoutMinutes", 30)}
	_, rs := h.LookupErr("setName")
	msgv, _ := h.Lookup("msg").StringValueOK()
	isRouter := msgv == "isdbgrid"
	u.info.replicated = rs == nil || isRouter
	if g.user != "" {
		if err := u.auth(); err != nil {
			c.Close()
			return nil, fmt.Errorf("logging in to MongoDB: %v", err)
		}
	}
	return u, nil
}

// roundTrip sends one OP_MSG and reads its reply (and any further replies a moreToCome
// stream sends, handed to more).
func (u *upstream) roundTrip(m *opmsg, more func(*message) error) (*message, error) {
	req := &message{h: header{requestID: u.g.reqID.Add(1), opCode: opMsg}, body: m.encode()}
	if _, err := u.conn.Write(req.bytes()); err != nil {
		return nil, err
	}
	if m.flags&flagMoreToCome != 0 {
		return nil, nil
	}
	for {
		rep, err := readMessage(u.conn)
		if err != nil {
			return nil, err
		}
		if rep.h.opCode != opMsg || len(rep.body) < 4 {
			return rep, nil
		}
		if binary.LittleEndian.Uint32(rep.body)&flagMoreToCome == 0 || more == nil {
			return rep, nil
		}
		if err := more(rep); err != nil {
			return nil, err
		}
	}
}

// run sends a command of the gateway's own and returns its reply document; an error reply
// ({ok: 0}) is an error.
func (u *upstream) run(db string, cmd bson.D) (bson.Raw, error) {
	cmd = append(cmd, bson.E{Key: "$db", Value: db})
	m, err := newMsg(cmd, 0)
	if err != nil {
		return nil, err
	}
	rep, err := u.roundTrip(m, nil)
	if err != nil {
		return nil, err
	}
	pm, err := parseMsg(rep.body)
	if err != nil {
		return nil, err
	}
	if !okReply(pm.body) {
		return pm.body, replyErr(pm.body)
	}
	return pm.body, nil
}

func okReply(b bson.Raw) bool {
	v, err := b.LookupErr("ok")
	if err != nil {
		return false
	}
	switch v.Type {
	case bson.TypeDouble:
		return v.Double() == 1
	case bson.TypeInt32:
		return v.Int32() == 1
	case bson.TypeInt64:
		return v.Int64() == 1
	case bson.TypeBoolean:
		return v.Boolean()
	}
	return false
}

type cmdError struct {
	Code int32
	Name string
	Msg  string
}

func (e *cmdError) Error() string { return fmt.Sprintf("%s (%d): %s", e.Name, e.Code, e.Msg) }

func replyErr(b bson.Raw) error {
	e := &cmdError{}
	if v, err := b.LookupErr("code"); err == nil {
		e.Code, _ = v.Int32OK()
	}
	if v, err := b.LookupErr("codeName"); err == nil {
		e.Name, _ = v.StringValueOK()
	}
	if v, err := b.LookupErr("errmsg"); err == nil {
		e.Msg, _ = v.StringValueOK()
	}
	return e
}

func (u *upstream) auth() error {
	c := &scram.Client{User: u.g.user, Password: u.g.pass}
	r, err := u.run(u.g.authDB, bson.D{{Key: "saslStart", Value: 1}, {Key: "mechanism", Value: "SCRAM-SHA-256"},
		{Key: "payload", Value: bson.Binary{Data: []byte(c.First())}}, {Key: "options", Value: bson.D{{Key: "skipEmptyExchange", Value: true}}}})
	if err != nil {
		return err
	}
	conv := r.Lookup("conversationId")
	_, sf := r.Lookup("payload").Binary()
	fin, err := c.Final(string(sf))
	if err != nil {
		return err
	}
	r, err = u.run(u.g.authDB, bson.D{{Key: "saslContinue", Value: 1}, {Key: "conversationId", Value: conv},
		{Key: "payload", Value: bson.Binary{Data: []byte(fin)}}})
	if err != nil {
		return err
	}
	_, sfin := r.Lookup("payload").Binary()
	if err := c.Verify(string(sfin)); err != nil {
		return err
	}
	if done, _ := r.Lookup("done").BooleanOK(); !done {
		_, err = u.run(u.g.authDB, bson.D{{Key: "saslContinue", Value: 1}, {Key: "conversationId", Value: conv},
			{Key: "payload", Value: bson.Binary{Data: []byte{}}}})
	}
	return err
}
