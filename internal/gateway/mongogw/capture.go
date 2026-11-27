package mongogw

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"undolayer/internal/connectors/mongo"
	"undolayer/internal/model"
	"undolayer/internal/vault"
)

// command is one client command, as the gateway sees it.
type command struct {
	name, lname, db, coll string
	msg                   *opmsg
	write                 bool
	lsid                  bson.Raw
	txn                   int64
	hasTxn                bool
	inTx                  bool // autocommit: false (part of a client transaction)
	start                 bool // startTransaction: true
	facts                 model.Facts
}

var writeCmds = map[string]bool{"insert": true, "update": true, "delete": true, "findandmodify": true}

var privilegeCmds = setOf("createuser", "updateuser", "dropuser", "dropallusersfromdatabase", "grantrolestouser",
	"revokerolesfromuser", "createrole", "updaterole", "droprole", "dropallrolesfromdatabase", "grantprivilegestorole",
	"revokeprivilegesfromrole", "grantrolestorole", "revokerolesfromrole")

var adminCmds = setOf("shutdown", "setparameter", "fsync", "fsyncunlock", "replsetreconfig", "replsetstepdown",
	"replsetfreeze", "replsetinitiate", "replsetsyncfrom", "replsetmaintenance", "applyops", "dotxn",
	"setfeaturecompatibilityversion", "compact", "logrotate", "setdefaultrwconcern", "configurefailpoint",
	"rotatecertificates", "cloneCollectionAsCapped", "converttocapped", "emptycapped", "godinsert", "cleanuporphaned",
	"killallsessions", "killallsessionsbypattern", "setuserwritewriteblockmode", "setclusterparameter",
	"addshard", "removeshard", "enablesharding", "shardcollection", "reshardcollection", "movechunk", "moveprimary",
	"clonecollection", "copydb", "repairdatabase", "validate", "resync", "sleep", "hostinfo", "getcmdlineopts")

var unsupportedWrites = setOf("bulkwrite", "mapreduce", "eval", "$eval", "geonear", "group")

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[strings.ToLower(x)] = true
	}
	return m
}

func (c *command) parse() {
	if v, err := c.msg.body.LookupErr(c.name); err == nil {
		c.coll, _ = v.StringValueOK()
	}
	c.write = writeCmds[c.lname]
	if v, err := c.msg.body.LookupErr("lsid"); err == nil {
		c.lsid, _ = v.DocumentOK()
	}
	if v, err := c.msg.body.LookupErr("txnNumber"); err == nil {
		c.txn, c.hasTxn = v.AsInt64OK()
	}
	if v, err := c.msg.body.LookupErr("autocommit"); err == nil {
		if b, ok := v.BooleanOK(); ok && !b {
			c.inTx = true
		}
	}
	if v, err := c.msg.body.LookupErr("startTransaction"); err == nil {
		c.start, _ = v.BooleanOK()
	}
	f := model.Facts{"command": c.name, "database": c.db, "collection": c.coll}
	switch {
	case c.lname == "drop" || c.lname == "dropdatabase" || c.lname == "renamecollection":
		f["destroys_data"] = true
	case privilegeCmds[c.lname]:
		f["privilege_change"] = true
	case adminCmds[c.lname]:
		f["admin_command"] = true
	case unsupportedWrites[c.lname]:
		f["unsupported_write"] = true
	}
	if c.lname == "mapreduce" || c.lname == "eval" || c.lname == "$eval" || hasServerJS(c.msg) {
		f["server_js"] = true
	}
	if c.lname == "aggregate" && pipelineWrites(c.msg.body) {
		f["aggregation_write"] = true
	}
	if c.write && (c.db == "admin" || c.db == "config" || c.db == "local" || strings.HasPrefix(c.coll, "system.")) {
		f["system_namespace"] = true
	}
	c.facts = f
}

// hasServerJS looks through the whole command for operators that run JavaScript.
func hasServerJS(m *opmsg) bool {
	if rawHas(m.body, 0) {
		return true
	}
	for _, s := range m.seqs {
		for _, d := range s.docs {
			if rawHas(d, 0) {
				return true
			}
		}
	}
	return false
}

func rawHas(d bson.Raw, depth int) bool {
	if depth > 100 {
		return true // nesting this deep is not a query anyone writes: treat it as hiding something
	}
	els, err := d.Elements()
	if err != nil {
		return false
	}
	for _, e := range els {
		switch e.Key() {
		case "$where", "$function", "$accumulator":
			return true
		}
		v := e.Value()
		if v.Type == bson.TypeJavaScript || v.Type == bson.TypeCodeWithScope {
			return true
		}
		if sub, ok := v.DocumentOK(); ok && rawHas(sub, depth+1) {
			return true
		}
		if arr, ok := v.ArrayOK(); ok && rawHas(bson.Raw(arr), depth+1) {
			return true
		}
	}
	return false
}

func pipelineWrites(b bson.Raw) bool {
	arr, ok := b.Lookup("pipeline").ArrayOK()
	if !ok {
		return false
	}
	vals, _ := arr.Values()
	for _, v := range vals {
		st, ok := v.DocumentOK()
		if !ok {
			continue
		}
		if _, err := st.LookupErr("$out"); err == nil {
			return true
		}
		if _, err := st.LookupErr("$merge"); err == nil {
			return true
		}
	}
	return false
}

func (c *command) txKey() string {
	if c.lsid == nil || !c.hasTxn {
		return ""
	}
	_, id, _ := c.lsid.Lookup("id").BinaryOK()
	return fmt.Sprintf("%s:%d", hex.EncodeToString(id), c.txn)
}

// judge applies the policy to a command; it returns why it is refused, or "".
func (g *Gateway) judge(s *session, c *command) string {
	f := model.Facts{}
	for k, v := range c.facts {
		f[k] = v
	}
	f["requester"], f["gateway"] = s.user, g.R.Name
	eff := model.Read
	if c.write {
		eff = model.Reversible
	}
	a := &model.Action{Connector: "mongo", Operation: c.name, Effect: eff, Facts: f}
	return g.decide(s, a, c.name)
}

func (g *Gateway) decide(s *session, a *model.Action, what string) string {
	g.pol.Evaluate(a)
	if a.Decision != model.Deny && a.Decision != model.RequireApproval {
		return ""
	}
	reason := strings.Join(a.Reasons, "; ")
	g.M.Audit.Note("gateway_refused", map[string]any{"gateway": g.R.Name, "user": s.user, "command": what,
		"reason": reason, "mode": g.R.Mode})
	if g.R.Mode == "watch" {
		return ""
	}
	g.stats.refused.Add(1)
	return reason
}

// ---------------------------------------------------------------- transactions

// txCtx is the transaction the gateway's commands run in: its own, or the client's.
type txCtx struct {
	lsid        any
	txn         int64
	first       bool     // the next command starts it
	readConcern bson.Raw // the client's, for the first command
}

func (u *upstream) inTx(db string, cmd bson.D, seqs []docSeq, t *txCtx) (bson.Raw, error) {
	cmd = append(cmd, bson.E{Key: "lsid", Value: t.lsid}, bson.E{Key: "txnNumber", Value: t.txn},
		bson.E{Key: "autocommit", Value: false})
	if t.first {
		cmd = append(cmd, bson.E{Key: "startTransaction", Value: true})
		if t.readConcern != nil {
			cmd = append(cmd, bson.E{Key: "readConcern", Value: t.readConcern})
		}
		t.first = false
	}
	cmd = append(cmd, bson.E{Key: "$db", Value: db})
	m, err := newMsg(cmd, 0)
	if err != nil {
		return nil, err
	}
	m.seqs = seqs
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

func (u *upstream) endTx(name string, t *txCtx, wc bson.Raw) (bson.Raw, error) {
	cmd := bson.D{{Key: name, Value: 1}, {Key: "lsid", Value: t.lsid}, {Key: "txnNumber", Value: t.txn},
		{Key: "autocommit", Value: false}}
	if wc != nil {
		cmd = append(cmd, bson.E{Key: "writeConcern", Value: wc})
	}
	return u.run("admin", cmd)
}

var errTooMany = errors.New("too many documents")

// findAll reads every document matching filter inside the transaction.
func (u *upstream) findAll(db, coll string, filter, sort, collation, let any, limit int64, t *txCtx) ([]bson.Raw, error) {
	cmd := bson.D{{Key: "find", Value: coll}, {Key: "filter", Value: filter}, {Key: "batchSize", Value: int32(10000)}}
	if sort != nil {
		cmd = append(cmd, bson.E{Key: "sort", Value: sort})
	}
	if collation != nil {
		cmd = append(cmd, bson.E{Key: "collation", Value: collation})
	}
	if let != nil {
		cmd = append(cmd, bson.E{Key: "let", Value: let})
	}
	if limit > 0 {
		cmd = append(cmd, bson.E{Key: "limit", Value: limit}, bson.E{Key: "singleBatch", Value: limit == 1})
	}
	r, err := u.inTx(db, cmd, nil, t)
	if err != nil {
		return nil, err
	}
	var out []bson.Raw
	max := u.g.R.MaxCaptureDocs
	batch := "firstBatch"
	for {
		cur, _ := r.Lookup("cursor").DocumentOK()
		arr, _ := cur.Lookup(batch).ArrayOK()
		vals, _ := arr.Values()
		for _, v := range vals {
			d, _ := v.DocumentOK()
			out = append(out, append(bson.Raw{}, d...))
		}
		id, _ := cur.Lookup("id").AsInt64OK()
		if len(out) > max {
			if id != 0 {
				_, _ = u.inTx(db, bson.D{{Key: "killCursors", Value: coll}, {Key: "cursors", Value: bson.A{id}}}, nil, t)
			}
			return nil, errTooMany
		}
		if id == 0 {
			return out, nil
		}
		r, err = u.inTx(db, bson.D{{Key: "getMore", Value: id}, {Key: "collection", Value: coll},
			{Key: "batchSize", Value: int32(10000)}}, nil, t)
		if err != nil {
			return nil, err
		}
		batch = "nextBatch"
	}
}

// ---------------------------------------------------------------- capturing writes

func idString(v bson.RawValue) string {
	b, err := bson.MarshalExtJSON(bson.D{{Key: "_id", Value: v}}, true, false)
	if err != nil {
		return ""
	}
	s := string(b)
	s = strings.TrimPrefix(s, `{"_id":`)
	return strings.TrimSuffix(s, "}")
}

func canonDoc(d bson.Raw) string {
	s, _ := mongo.Canon(d)
	return s
}

// changeSet keeps each document's state before the first change and after the last.
type changeSet struct {
	order []string
	m     map[string]*mongo.Change
}

func newChangeSet() *changeSet { return &changeSet{m: map[string]*mongo.Change{}} }

func (cs *changeSet) before(db, coll string, docs []bson.Raw) {
	for _, d := range docs {
		id := idString(d.Lookup("_id"))
		k := db + "\x00" + coll + "\x00" + id
		if _, ok := cs.m[k]; !ok {
			cs.m[k] = &mongo.Change{DB: db, Coll: coll, ID: id, Before: canonDoc(d), After: canonDoc(d)}
			cs.order = append(cs.order, k)
		}
	}
}

// after sets the state after: ids lists every document the write may have touched; those
// not in docs no longer exist.
func (cs *changeSet) after(db, coll string, ids []bson.RawValue, docs []bson.Raw) {
	now := map[string]string{}
	for _, d := range docs {
		now[idString(d.Lookup("_id"))] = canonDoc(d)
	}
	for _, v := range ids {
		id := idString(v)
		k := db + "\x00" + coll + "\x00" + id
		ch, ok := cs.m[k]
		if !ok {
			ch = &mongo.Change{DB: db, Coll: coll, ID: id}
			cs.m[k] = ch
			cs.order = append(cs.order, k)
		}
		ch.After = now[id]
	}
}

func (cs *changeSet) list() []mongo.Change {
	var out []mongo.Change
	for _, k := range cs.order {
		if ch := cs.m[k]; ch.Before != ch.After {
			out = append(out, *ch)
		}
	}
	return out
}

func ids(docs []bson.Raw) []bson.RawValue {
	out := make([]bson.RawValue, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.Lookup("_id"))
	}
	return out
}

func inFilter(vs []bson.RawValue) bson.D {
	a := bson.A{}
	for _, v := range vs {
		a = append(a, v)
	}
	return bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: a}}}}
}

// postImages reads the documents with these ids, a thousand at a time.
func (u *upstream) postImages(db, coll string, vs []bson.RawValue, t *txCtx) ([]bson.Raw, error) {
	var out []bson.Raw
	for i := 0; i < len(vs); i += 1000 {
		j := min(i+1000, len(vs))
		d, err := u.findAll(db, coll, inFilter(vs[i:j]), nil, nil, nil, 0, t)
		if err != nil {
			return nil, err
		}
		out = append(out, d...)
	}
	return out, nil
}

// the client's fields a write keeps (the rest: the session, the transaction and the write
// concern, are the gateway's to set)
var dropped = setOf("lsid", "txnnumber", "autocommit", "starttransaction", "writeconcern", "readconcern",
	"$readpreference", "$db", "$clustertime", "documents", "updates", "deletes")

func baseCmd(b bson.Raw) bson.D {
	var out bson.D
	els, _ := b.Elements()
	for _, e := range els {
		if !dropped[strings.ToLower(e.Key())] {
			out = append(out, bson.E{Key: e.Key(), Value: e.Value()})
		}
	}
	return out
}

func statements(m *opmsg, name string) []bson.Raw {
	for _, s := range m.seqs {
		if s.id == name {
			return s.docs
		}
	}
	arr, ok := m.body.Lookup(name).ArrayOK()
	if !ok {
		return nil
	}
	vals, _ := arr.Values()
	var out []bson.Raw
	for _, v := range vals {
		if d, ok := v.DocumentOK(); ok {
			out = append(out, d)
		}
	}
	return out
}

func lookup(d bson.Raw, k string) any {
	v, err := d.LookupErr(k)
	if err != nil {
		return nil
	}
	return v
}

func boolOf(d bson.Raw, k string) bool {
	v, err := d.LookupErr(k)
	if err != nil {
		return false
	}
	if b, ok := v.BooleanOK(); ok {
		return b
	}
	n, _ := v.AsInt64OK()
	return n != 0
}

// writeResult is the reply the client gets, merged over the statements run one by one.
type writeResult struct {
	n, nModified int64
	upserted     bson.A
	writeErr     bson.Raw // the first write error (it ends the write: inside a transaction nothing of it stays)
	errIndex     int
	extra        bson.D // findAndModify's reply
}

// execWrite runs the client's write inside t, statement by statement, each narrowed to
// exactly the documents read before it, and returns what it changed.
func (s *session) execWrite(c *command, t *txCtx) (*writeResult, *changeSet, error) {
	u, db, coll := s.up, c.db, c.coll
	cs := newChangeSet()
	res := &writeResult{errIndex: -1}
	base := baseCmd(c.msg.body)
	switch c.lname {
	case "insert":
		docs := statements(c.msg, "documents")
		var withID []bson.Raw
		for _, d := range docs {
			if _, err := d.LookupErr("_id"); err != nil {
				nd, _ := bson.Marshal(append(bson.D{{Key: "_id", Value: bson.NewObjectID()}}, rawD(d)...))
				d = nd
			}
			withID = append(withID, d)
		}
		r, err := u.inTx(db, base, []docSeq{{id: "documents", docs: withID}}, t)
		if err != nil {
			return nil, nil, err
		}
		res.n, _ = r.Lookup("n").AsInt64OK()
		if we := firstWriteError(r); we != nil {
			res.writeErr = we
			return res, cs, nil
		}
		post, err := u.postImages(db, coll, ids(withID), t)
		if err != nil {
			return nil, nil, err
		}
		cs.after(db, coll, ids(withID), post)
	case "update", "delete":
		key := "updates"
		if c.lname == "delete" {
			key = "deletes"
		}
		for i, st := range statements(c.msg, key) {
			single := !boolOf(st, "multi")
			if c.lname == "delete" {
				l, _ := st.Lookup("limit").AsInt64OK()
				single = l == 1
			}
			var limit int64
			if single {
				limit = 1
			}
			let := lookup(c.msg.body, "let")
			pre, err := u.findAll(db, coll, lookup(st, "q"), lookup(st, "sort"), lookup(st, "collation"), let, limit, t)
			if err != nil {
				return nil, nil, err
			}
			cs.before(db, coll, pre)
			nst := narrow(st, "q", pre, single, "hint", "sort")
			cmd := append(bson.D{}, base...)
			r, err := u.inTx(db, cmd, []docSeq{{id: key, docs: []bson.Raw{nst}}}, t)
			if err != nil {
				return nil, nil, err
			}
			n, _ := r.Lookup("n").AsInt64OK()
			nm, _ := r.Lookup("nModified").AsInt64OK()
			res.n += n
			res.nModified += nm
			touched := ids(pre)
			if up, ok := r.Lookup("upserted").ArrayOK(); ok {
				vals, _ := up.Values()
				for _, v := range vals {
					ud, _ := v.DocumentOK()
					res.upserted = append(res.upserted, bson.D{{Key: "index", Value: int32(i)}, {Key: "_id", Value: ud.Lookup("_id")}})
					touched = append(touched, ud.Lookup("_id"))
				}
			}
			if we := firstWriteError(r); we != nil {
				res.writeErr, res.errIndex = we, i
				return res, cs, nil
			}
			post, err := u.postImages(db, coll, touched, t)
			if err != nil {
				return nil, nil, err
			}
			cs.after(db, coll, touched, post)
		}
	case "findandmodify":
		b := c.msg.body
		pre, err := u.findAll(db, coll, lookup(b, "query"), lookup(b, "sort"), lookup(b, "collation"), lookup(b, "let"), 1, t)
		if err != nil {
			return nil, nil, err
		}
		cs.before(db, coll, pre)
		nb := narrow(b, "query", pre, true, "hint", "sort")
		r, err := u.inTx(db, baseCmd(nb), nil, t)
		if err != nil {
			return nil, nil, err
		}
		touched := ids(pre)
		if leo, ok := r.Lookup("lastErrorObject").DocumentOK(); ok {
			if v, err := leo.LookupErr("upserted"); err == nil {
				touched = append(touched, v)
			}
		}
		post, err := u.postImages(db, coll, touched, t)
		if err != nil {
			return nil, nil, err
		}
		cs.after(db, coll, touched, post)
		els, _ := r.Elements()
		for _, e := range els {
			switch e.Key() {
			case "ok", "$clusterTime", "operationTime":
			default:
				res.extra = append(res.extra, bson.E{Key: e.Key(), Value: e.Value()})
			}
		}
	}
	return res, cs, nil
}

func rawD(d bson.Raw) bson.D {
	var out bson.D
	_ = bson.Unmarshal(d, &out)
	return out
}

// narrow rewrites a statement's filter to exactly the documents read before it (when it
// matched none it is left as it is: nothing matches it in this transaction, and an upsert
// needs its fields).
func narrow(st bson.Raw, field string, pre []bson.Raw, single bool, drop ...string) bson.Raw {
	if len(pre) == 0 {
		return st
	}
	var f bson.D
	if single {
		f = bson.D{{Key: "_id", Value: pre[0].Lookup("_id")}}
	} else {
		f = inFilter(ids(pre))
	}
	var out bson.D
	els, _ := st.Elements()
	for _, e := range els {
		k := e.Key()
		switch {
		case k == field:
			out = append(out, bson.E{Key: k, Value: f})
		case contains(drop, k):
		default:
			out = append(out, bson.E{Key: k, Value: e.Value()})
		}
	}
	b, _ := bson.Marshal(out)
	return b
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func firstWriteError(r bson.Raw) bson.Raw {
	arr, ok := r.Lookup("writeErrors").ArrayOK()
	if !ok {
		return nil
	}
	vals, _ := arr.Values()
	if len(vals) == 0 {
		return nil
	}
	d, _ := vals[0].DocumentOK()
	return d
}

func (res *writeResult) doc(lname string) bson.D {
	if lname == "findandmodify" {
		return append(res.extra, bson.E{Key: "ok", Value: 1.0})
	}
	d := bson.D{{Key: "n", Value: res.n}}
	if lname == "update" {
		d = append(d, bson.E{Key: "nModified", Value: res.nModified})
		if len(res.upserted) > 0 {
			d = append(d, bson.E{Key: "upserted", Value: res.upserted})
		}
	}
	if res.writeErr != nil {
		we := rawD(res.writeErr)
		if res.errIndex >= 0 {
			for i := range we {
				if we[i].Key == "index" {
					we[i].Value = int32(res.errIndex)
				}
			}
		}
		d = append(d, bson.E{Key: "writeErrors", Value: bson.A{we}})
		d[0].Value = int64(0) // in a transaction, nothing of a failed write stays
	}
	return append(d, bson.E{Key: "ok", Value: 1.0})
}

func errorReply(err error) bson.D {
	var ce *cmdError
	if errors.As(err, &ce) {
		return errDoc(ce.Code, ce.Name, ce.Msg)
	}
	if errors.Is(err, errTooMany) {
		return refusedDoc("the write would change too many documents to keep their before state")
	}
	return errDoc(1, "InternalError", "Countersign gateway: "+err.Error())
}

// write runs a client write so that what it changes is in the vault before it commits.
func (s *session) write(c *command) bson.D {
	g := s.g
	retryKey := ""
	if c.hasTxn && !c.inTx {
		retryKey = c.txKey()
		if d, ok := retries.get(retryKey); ok {
			return d
		}
	}
	if !s.info.replicated {
		if g.R.Mode == "watch" {
			g.M.Audit.Note("gateway_uncaptured", map[string]any{"gateway": g.R.Name, "user": s.user, "command": c.name,
				"reason": "the server is not a replica set member"})
			r, err := s.passThrough(c.msg)
			if err != nil {
				return errorReply(err)
			}
			return rawD(r)
		}
		return refusedDoc("the server is not a replica set member, so writes cannot run in a transaction and be captured exactly")
	}
	if c.inTx {
		return s.writeInClientTx(c)
	}
	s.up.txnNo++
	t := &txCtx{lsid: bson.D{{Key: "id", Value: s.up.lsid}}, txn: s.up.txnNo, first: true}
	abort := func() { _, _ = s.up.endTx("abortTransaction", t, nil) }
	res, cs, err := s.execWrite(c, t)
	if err != nil {
		abort()
		return errorReply(err)
	}
	if res.writeErr != nil {
		abort()
		return res.doc(c.lname)
	}
	changes := cs.list()
	if why := s.judgeChanges(changes); why != "" {
		abort()
		return refusedDoc(why)
	}
	var wc bson.Raw
	if v, err := c.msg.body.LookupErr("writeConcern"); err == nil {
		if d, ok := v.DocumentOK(); ok && !isW0(d) {
			wc = d
		}
	}
	id, batch, why := s.intent(changes, c.name+" "+c.db+"."+c.coll)
	if why != "" {
		abort()
		return refusedDoc(why)
	}
	if _, err := s.up.endTx("commitTransaction", t, wc); err != nil {
		var ce *cmdError
		if errors.As(err, &ce) && ce.Code != 50 && ce.Code != 91 && ce.Code != 189 && ce.Code != 11602 {
			s.settle(id, batch, false) // a definite failure; otherwise the database itself will tell
		}
		return errorReply(err)
	}
	s.settle(id, batch, true)
	d := res.doc(c.lname)
	if retryKey != "" {
		retries.put(retryKey, d)
	}
	return d
}

func isW0(d bson.Raw) bool {
	v, err := d.LookupErr("w")
	if err != nil {
		return false
	}
	n, ok := v.AsInt64OK()
	return ok && n == 0
}

// passThrough sends the client's message unchanged and returns the reply document.
func (s *session) passThrough(pm *opmsg) (bson.Raw, error) {
	m := *pm
	m.flags &^= flagMoreToCome
	rep, err := s.up.roundTrip(&m, nil)
	if err != nil {
		return nil, err
	}
	r, err := parseMsg(rep.body)
	if err != nil {
		return nil, err
	}
	return r.body, nil
}

// writeInClientTx: a write in the client's own transaction is captured the same way; what
// it changed is kept until the client commits.
func (s *session) writeInClientTx(c *command) bson.D {
	t := &txCtx{lsid: c.lsid, txn: c.txn, first: c.start}
	if c.start {
		s.g.beginTx(c.txKey())
		if v, err := c.msg.body.LookupErr("readConcern"); err == nil {
			t.readConcern, _ = v.DocumentOK()
		}
	}
	ct := s.g.getTx(c.txKey())
	res, cs, err := s.execWrite(c, t)
	if err != nil {
		var ce *cmdError
		if !errors.As(err, &ce) {
			ct.failed = err.Error()
		}
		return errorReply(err)
	}
	if res.writeErr != nil {
		return res.doc(c.lname) // the server aborted the transaction
	}
	s.g.txMu.Lock()
	ct.changes = append(ct.changes, cs.list()...)
	ct.cmds = append(ct.cmds, c.name+" "+c.db+"."+c.coll)
	s.g.txMu.Unlock()
	return res.doc(c.lname)
}

// commitClient: the client commits its transaction; what it changed goes to the vault first.
func (s *session) commitClient(c *command) bson.D {
	ct := s.g.takeTx(c.txKey())
	if ct == nil || (len(ct.changes) == 0 && ct.failed == "") {
		r, err := s.passThrough(c.msg)
		if err != nil {
			return errorReply(err)
		}
		return rawD(r)
	}
	t := &txCtx{lsid: c.lsid, txn: c.txn}
	if ct.failed != "" {
		_, _ = s.up.endTx("abortTransaction", t, nil)
		return refusedDoc("a write in this transaction could not be captured (" + ct.failed + "); the transaction was rolled back")
	}
	changes := merge(ct.changes)
	if why := s.judgeChanges(changes); why != "" {
		_, _ = s.up.endTx("abortTransaction", t, nil)
		return refusedDoc(why)
	}
	id, batch, why := s.intent(changes, strings.Join(ct.cmds, "; "))
	if why != "" {
		_, _ = s.up.endTx("abortTransaction", t, nil)
		return refusedDoc(why)
	}
	r, err := s.passThrough(c.msg)
	if err != nil {
		return errorReply(err)
	}
	s.settle(id, batch, okReply(r))
	return rawD(r)
}

// merge folds changes of the same document across a transaction's writes.
func merge(cs []mongo.Change) []mongo.Change {
	idx := map[string]int{}
	var out []mongo.Change
	for _, ch := range cs {
		k := ch.DB + "\x00" + ch.Coll + "\x00" + ch.ID
		if i, ok := idx[k]; ok {
			out[i].After = ch.After
			continue
		}
		idx[k] = len(out)
		out = append(out, ch)
	}
	kept := out[:0]
	for _, ch := range out {
		if ch.Before != ch.After {
			kept = append(kept, ch)
		}
	}
	return kept
}

// judgeChanges applies the commit rules to what a write actually changed.
func (s *session) judgeChanges(changes []mongo.Change) string {
	per := map[string]int{}
	deleted := 0
	for _, ch := range changes {
		per[ch.DB+"."+ch.Coll]++
		if ch.After == "" {
			deleted++
		}
	}
	frac := 0.0
	touched := []string{}
	for ns, n := range per {
		touched = append(touched, ns)
		total := float64(s.collCount(ns))
		if float64(n) > total {
			total = float64(n)
		}
		if total >= 20 && float64(n)/total > frac {
			frac = float64(n) / total
		}
	}
	f := model.Facts{"docs_affected": len(changes), "docs_deleted": deleted, "collections_touched": touched,
		"collection_fraction_changed": frac, "requester": s.user, "gateway": s.g.R.Name}
	return s.g.decide(s, &model.Action{Connector: "mongo", Operation: "commit", Effect: model.Reversible, Facts: f}, "commit")
}

// collCount is a collection's size before the write (from its metadata, cached a minute).
func (s *session) collCount(ns string) int64 {
	if v, ok := s.g.counts.Load(ns); ok {
		if cc := v.(collCount); time.Since(cc.at) < time.Minute {
			return cc.n
		}
	}
	db, coll, _ := strings.Cut(ns, ".")
	r, err := s.up.run(db, bson.D{{Key: "count", Value: coll}})
	if err != nil {
		return 0
	}
	n, _ := r.Lookup("n").AsInt64OK()
	s.g.counts.Store(ns, collCount{n: n, at: time.Now()})
	return n
}

// intent stores what the write changed, on a quorum, before it commits.
func (s *session) intent(changes []mongo.Change, what string) (id, batch, why string) {
	if len(changes) == 0 {
		return "", "", ""
	}
	if s.g.M.Vault == nil {
		return "", "", "the vault is disabled, so no before state can be kept"
	}
	raw, _ := json.Marshal(mongo.UndoRecord{URI: redact(s.g.R.URI), Changes: changes})
	rows, _ := s.g.Conn.DescribeRows(raw)
	id = newID()
	rc, err := s.g.M.Vault.Append(vault.Entry{Tx: id, Task: clipS("gateway "+s.g.R.Name+": "+what, 500),
		Requester: s.user, Connector: s.g.Conn.Name(), Phase: "intent", Rows: rows, Undo: raw})
	if err != nil {
		return "", "", "the vault could not store the before state: " + err.Error()
	}
	return id, rc.Batch, ""
}

func (s *session) settle(id, batch string, committed bool) {
	if batch == "" {
		return
	}
	s.g.stats.commits.Add(1)
	phase := "committed"
	if !committed {
		phase = "failed"
	}
	s.g.M.Audit.Note("gateway_commit", map[string]any{"tx": id, "gateway": s.g.R.Name, "user": s.user, "outcome": phase})
	s.g.M.Vault.AppendLater(vault.Entry{Tx: id, Requester: s.user, Connector: s.g.Conn.Name(), Phase: phase, Ref: batch})
}

func clipS(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func redact(uri string) string {
	if i := strings.Index(uri, "://"); i >= 0 {
		if j := strings.Index(uri[i+3:], "@"); j >= 0 {
			cred := uri[i+3 : i+3+j]
			if k := strings.Index(cred, ":"); k >= 0 {
				return uri[:i+3] + cred[:k] + ":xxx" + uri[i+3+j:]
			}
		}
	}
	return uri
}
