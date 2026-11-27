package mongogw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"undolayer/internal/gateway/scram"
)

var connIDs atomic.Int32

// session is one client connection and the server connection behind it.
type session struct {
	g      *Gateway
	c      net.Conn
	up     *upstream
	user   string
	authed bool
	sasl   *scram.Server
	saslU  string
	saslOK bool // the proof checked; waiting for the client's last (empty) step
	id     int32
	info   serverInfo
}

// serverInfo is what the server said of itself, passed on in the gateway's own hello.
type serverInfo struct {
	maxWire, maxBSON, maxMsg, maxBatch, sessionMins int32
	replicated                                      bool
}

func (g *Gateway) handle(c net.Conn) {
	defer c.Close()
	up, err := g.dial()
	if err != nil {
		g.M.Audit.Note("gateway_upstream_failed", map[string]any{"gateway": g.R.Name, "error": err.Error()})
		return
	}
	defer up.conn.Close()
	s := &session{g: g, c: c, up: up, id: connIDs.Add(1), authed: g.R.Trust, info: up.info}
	if g.R.Trust {
		s.user = "trusted"
	}
	for {
		m, err := readMessage(c)
		if err != nil {
			return
		}
		if err := s.serve(m); err != nil {
			return
		}
	}
}

func (s *session) send(responseTo int32, body []byte, op int32) error {
	m := &message{h: header{requestID: s.g.reqID.Add(1), responseTo: responseTo, opCode: op}, body: body}
	_, err := s.c.Write(m.bytes())
	return err
}

// reply answers the client's request with one document.
func (s *session) reply(to int32, doc any) error {
	b, err := bson.Marshal(doc)
	if err != nil {
		return err
	}
	return s.send(to, (&opmsg{body: b}).encode(), opMsg)
}

func errDoc(code int32, name, msg string) bson.D {
	return bson.D{{Key: "ok", Value: 0.0}, {Key: "errmsg", Value: msg}, {Key: "code", Value: code}, {Key: "codeName", Value: name}}
}

func refusedDoc(why string) bson.D {
	return errDoc(13, "Unauthorized", "refused by Countersign: "+why)
}

func (s *session) serve(m *message) error {
	switch m.h.opCode {
	case opQuery:
		return s.legacy(m)
	case opMsg:
	default:
		return fmt.Errorf("unsupported opcode %d", m.h.opCode)
	}
	full := m.bytes()
	if len(m.body) < 4 {
		return errors.New("short OP_MSG")
	}
	pm, err := parseMsg(m.body)
	if err != nil {
		return err
	}
	if !checksumOK(full, pm.flags) {
		return errors.New("OP_MSG checksum mismatch")
	}
	noReply := pm.flags&flagMoreToCome != 0
	answer := func(doc any) error {
		if noReply {
			return nil
		}
		return s.reply(m.h.requestID, doc)
	}
	name, db := cmdName(pm.body)
	lname := strings.ToLower(name)
	s.g.stats.commands.Add(1)

	switch lname {
	case "hello", "ismaster":
		return answer(s.hello(pm.body, name))
	case "saslstart":
		return answer(s.saslStart(pm.body))
	case "saslcontinue":
		return answer(s.saslContinue(pm.body))
	case "authenticate":
		return answer(errDoc(334, "MechanismUnavailable", "use SCRAM-SHA-256"))
	case "logout":
		return answer(bson.D{{Key: "ok", Value: 1.0}})
	case "ping", "buildinfo", "getparameter":
		if !s.authed && lname != "ping" && lname != "buildinfo" {
			return answer(errDoc(13, "Unauthorized", "command "+name+" requires authentication"))
		}
		return s.forward(m.h.requestID, pm)
	}
	if !s.authed {
		return answer(errDoc(13, "Unauthorized", "command "+name+" requires authentication"))
	}
	c := &command{name: name, lname: lname, db: db, msg: pm}
	c.parse()
	if why := s.g.judge(s, c); why != "" {
		return answer(refusedDoc(why))
	}
	switch {
	case c.write:
		doc := s.write(c)
		return answer(doc)
	case lname == "committransaction":
		return answer(s.commitClient(c))
	case lname == "aborttransaction":
		s.g.dropTx(c.txKey())
		return s.forward(m.h.requestID, pm)
	}
	if c.inTx && c.start {
		s.g.beginTx(c.txKey())
	}
	if noReply {
		_, err := s.up.roundTrip(pm, nil)
		return err
	}
	return s.forward(m.h.requestID, pm)
}

// forward sends the client's message as it is and relays the reply (every reply of an
// exhaust stream).
func (s *session) forward(clientReq int32, pm *opmsg) error {
	prev := clientReq
	var werr error
	rep, err := s.up.roundTrip(pm, func(r *message) error {
		id := s.g.reqID.Add(1)
		out := &message{h: header{requestID: id, responseTo: prev, opCode: r.h.opCode}, body: stripChecksum(r.body)}
		prev = id
		if _, err := s.c.Write(out.bytes()); err != nil {
			werr = err
			return err
		}
		return nil
	})
	if err != nil {
		if werr != nil {
			return werr
		}
		return err
	}
	if rep == nil {
		return nil
	}
	return s.send(prev, stripChecksum(rep.body), rep.h.opCode)
}

func stripChecksum(body []byte) []byte {
	if len(body) < 4 {
		return body
	}
	f := binary.LittleEndian.Uint32(body)
	if f&flagChecksum == 0 {
		return body
	}
	out := append([]byte{}, body[:len(body)-4]...)
	binary.LittleEndian.PutUint32(out, f&^flagChecksum)
	return out
}

// legacy answers the OP_QUERY hello of older drivers (anything else over OP_QUERY is gone
// from MongoDB).
func (s *session) legacy(m *message) error {
	coll, q, err := parseQuery(m.body)
	if err != nil {
		return err
	}
	name, _ := cmdName(q)
	var doc bson.D
	switch {
	case strings.HasSuffix(coll, ".$cmd") && (strings.EqualFold(name, "ismaster") || name == "hello"):
		doc = s.hello(q, name)
	case strings.HasSuffix(coll, ".$cmd") && name == "$query":
		inner, ok := q.Lookup("$query").DocumentOK()
		if n, _ := cmdName(inner); ok && (strings.EqualFold(n, "ismaster") || n == "hello") {
			doc = s.hello(inner, n)
		} else {
			doc = errDoc(352, "UnsupportedOpQueryCommand", "OP_QUERY is only supported for hello")
		}
	default:
		doc = errDoc(352, "UnsupportedOpQueryCommand", "OP_QUERY is only supported for hello")
	}
	b, err := bson.Marshal(doc)
	if err != nil {
		return err
	}
	return s.send(m.h.requestID, reply(b), opReply)
}

func cmdName(b bson.Raw) (name, db string) {
	els, err := b.Elements()
	if err != nil || len(els) == 0 {
		return "", ""
	}
	name = els[0].Key()
	if v, err := b.LookupErr("$db"); err == nil {
		db, _ = v.StringValueOK()
	}
	return name, db
}

// hello: the gateway presents itself as a router, so drivers keep every connection on it.
// No compression is offered and no topology version, so drivers poll it.
func (s *session) hello(b bson.Raw, name string) bson.D {
	d := bson.D{}
	if strings.EqualFold(name, "ismaster") {
		d = append(d, bson.E{Key: "ismaster", Value: true})
	} else {
		d = append(d, bson.E{Key: "isWritablePrimary", Value: true})
	}
	i := s.info
	d = append(d, bson.E{Key: "msg", Value: "isdbgrid"},
		bson.E{Key: "maxBsonObjectSize", Value: i.maxBSON}, bson.E{Key: "maxMessageSizeBytes", Value: i.maxMsg},
		bson.E{Key: "maxWriteBatchSize", Value: i.maxBatch}, bson.E{Key: "localTime", Value: bson.NewDateTimeFromTime(time.Now())},
		bson.E{Key: "logicalSessionTimeoutMinutes", Value: i.sessionMins}, bson.E{Key: "connectionId", Value: s.id},
		bson.E{Key: "minWireVersion", Value: int32(0)}, bson.E{Key: "maxWireVersion", Value: i.maxWire},
		bson.E{Key: "readOnly", Value: false})
	if v, err := b.LookupErr("saslSupportedMechs"); err == nil {
		if _, ok := v.StringValueOK(); ok {
			d = append(d, bson.E{Key: "saslSupportedMechs", Value: bson.A{"SCRAM-SHA-256"}})
		}
	}
	return append(d, bson.E{Key: "ok", Value: 1.0})
}

// ---------------------------------------------------------------- logging in

func (s *session) saslStart(b bson.Raw) bson.D {
	if s.g.R.Trust {
		return errDoc(18, "AuthenticationFailed", "this gateway trusts loopback clients; connect without credentials")
	}
	mech, _ := b.Lookup("mechanism").StringValueOK()
	if mech != "SCRAM-SHA-256" {
		return errDoc(334, "MechanismUnavailable", "the gateway supports SCRAM-SHA-256")
	}
	_, payload, ok := b.Lookup("payload").BinaryOK()
	if !ok {
		return errDoc(18, "AuthenticationFailed", "no payload")
	}
	msg := string(payload)
	user := ""
	if p := strings.SplitN(msg, ",", 3); len(p) == 3 {
		for _, a := range strings.Split(p[2], ",") {
			if strings.HasPrefix(a, "n=") {
				user = strings.NewReplacer("=2C", ",", "=3D", "=").Replace(a[2:])
			}
		}
	}
	v := s.g.users[user]
	if v == nil { // an unknown user goes through the same steps and fails at the proof
		v, _ = scram.NewVerifier(newID())
	}
	s.sasl, s.saslU, s.saslOK = &scram.Server{V: v}, user, false
	first, err := s.sasl.First(msg)
	if err != nil {
		return errDoc(18, "AuthenticationFailed", err.Error())
	}
	return bson.D{{Key: "conversationId", Value: int32(1)}, {Key: "done", Value: false},
		{Key: "payload", Value: bson.Binary{Data: []byte(first)}}, {Key: "ok", Value: 1.0}}
}

func (s *session) saslContinue(b bson.Raw) bson.D {
	if s.sasl == nil {
		return errDoc(17, "ProtocolError", "no SASL conversation")
	}
	if s.saslOK { // the client's empty last step
		s.sasl, s.saslOK = nil, false
		return bson.D{{Key: "conversationId", Value: int32(1)}, {Key: "done", Value: true},
			{Key: "payload", Value: bson.Binary{Data: []byte{}}}, {Key: "ok", Value: 1.0}}
	}
	_, payload, _ := b.Lookup("payload").BinaryOK()
	fin, err := s.sasl.Final(string(payload))
	if err != nil || s.g.users[s.saslU] == nil {
		s.sasl = nil
		s.g.M.Audit.Note("gateway_auth_failed", map[string]any{"gateway": s.g.R.Name, "user": s.saslU})
		return errDoc(18, "AuthenticationFailed", "Authentication failed.")
	}
	s.authed, s.user, s.saslOK = true, s.saslU, true
	return bson.D{{Key: "conversationId", Value: int32(1)}, {Key: "done", Value: false},
		{Key: "payload", Value: bson.Binary{Data: []byte(fin)}}, {Key: "ok", Value: 1.0}}
}

// ---------------------------------------------------------------- client transactions

func (g *Gateway) beginTx(k string) {
	if k == "" {
		return
	}
	g.txMu.Lock()
	if _, ok := g.txs[k]; !ok {
		if len(g.txs) > 100_000 {
			g.txs = map[string]*clientTx{}
		}
		g.txs[k] = &clientTx{}
	}
	g.txMu.Unlock()
}

func (g *Gateway) getTx(k string) *clientTx {
	g.txMu.Lock()
	defer g.txMu.Unlock()
	t := g.txs[k]
	if t == nil {
		t = &clientTx{}
		g.txs[k] = t
	}
	return t
}

func (g *Gateway) takeTx(k string) *clientTx {
	g.txMu.Lock()
	defer g.txMu.Unlock()
	t := g.txs[k]
	delete(g.txs, k)
	return t
}

func (g *Gateway) dropTx(k string) { g.takeTx(k) }

// retryable writes: a write the client retries (the same session and transaction number)
// gets the first answer again instead of running twice.
type retryCache struct {
	mu sync.Mutex
	m  map[string]bson.D
}

var retries = &retryCache{m: map[string]bson.D{}}

func (r *retryCache) get(k string) (bson.D, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.m[k]
	return d, ok
}

func (r *retryCache) put(k string, d bson.D) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.m) > 200_000 {
		r.m = map[string]bson.D{}
	}
	r.m[k] = d
}
