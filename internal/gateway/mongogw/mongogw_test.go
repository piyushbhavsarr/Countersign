package mongogw

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"undolayer/internal/policy"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

// UNDOLAYER_TEST_MONGO: a replica set member, e.g.
// mongodb://127.0.0.1:57017/?directConnection=true
type env struct {
	direct *mongo.Client
	gw     *Gateway
	m      *tx.Manager
	v      *vault.Vault
	addr   string
	db     string
}

func setup(t *testing.T, mod func(*Route)) *env {
	t.Helper()
	uri := os.Getenv("UNDOLAYER_TEST_MONGO")
	if uri == "" {
		t.Skip("set UNDOLAYER_TEST_MONGO to run the MongoDB gateway tests")
	}
	ctx := context.Background()
	direct, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = direct.Disconnect(ctx) })
	db := "gw_" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))
	_ = direct.Database(db).Drop(ctx)
	var docs []any
	for i := 1; i <= 3000; i++ {
		docs = append(docs, bson.D{{Key: "_id", Value: i}, {Key: "owner", Value: fmt.Sprintf("o%d", i)},
			{Key: "balance", Value: float64(i) * 10.5}, {Key: "tags", Value: bson.A{"a"}}})
	}
	if _, err := direct.Database(db).Collection("accounts").InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	m, err := tx.NewManager(filepath.Join(d, "state"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(vault.Options{Replicas: []string{filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")},
		LockPath: filepath.Join(d, "l")})
	if err != nil {
		t.Fatal(err)
	}
	m.Vault = v
	host := strings.TrimPrefix(uri, "mongodb://")
	host = host[:strings.IndexAny(host+"/", "/?")]
	r := Route{Name: "main", Listen: "127.0.0.1:0", URI: "mongodb://" + host + "/", Trust: true}
	if mod != nil {
		mod(&r)
	}
	g, err := New(r, m)
	if err != nil {
		t.Fatal(err)
	}
	m.Register(g.Conn)
	g.Conn.URI = uri
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Serve(l) }()
	t.Cleanup(func() { g.Close(); _ = l.Close(); _ = m.Flush() })
	return &env{direct: direct, gw: g, m: m, v: v, addr: l.Addr().String(), db: db}
}

func (e *env) client(t *testing.T, cred string) *mongo.Client {
	t.Helper()
	u := "mongodb://" + cred + e.addr + "/?retryWrites=true"
	if cred != "" {
		u += "&authSource=admin&authMechanism=SCRAM-SHA-256"
	}
	c, err := mongo.Connect(options.Client().ApplyURI(u).SetServerSelectionTimeout(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })
	return c
}

func (e *env) doc(t *testing.T, id int) bson.M {
	t.Helper()
	var m bson.M
	err := e.direct.Database(e.db).Collection("accounts").FindOne(context.Background(), bson.D{{Key: "_id", Value: id}}).Decode(&m)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// the gateway transactions in the vault whose rows match
func (e *env) txWith(t *testing.T, op string, id int) string {
	t.Helper()
	bs, _, err := e.v.Batches(func(r *vault.Record) bool { return r.Phase == "intent" })
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bs {
		for _, r := range b.Rows {
			if r.Op == op && fmt.Sprint(r.Key["_id"]) == fmt.Sprint(map[string]any{"$numberInt": fmt.Sprint(id)}) {
				return b.Tx
			}
		}
	}
	return ""
}

func refused(err error) bool {
	var ce mongo.CommandError
	if errors.As(err, &ce) {
		return strings.Contains(ce.Message, "refused by Countersign")
	}
	var we mongo.WriteException
	if errors.As(err, &we) {
		return strings.Contains(we.Error(), "refused by Countersign")
	}
	return strings.Contains(fmt.Sprint(err), "refused by Countersign")
}

// Reads and every kind of write pass through; each committed write is in the vault and can
// be undone from it, exactly.
func TestWritesAreCapturedAndUndone(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	c := e.client(t, "").Database(e.db).Collection("accounts")
	var got bson.M
	if err := c.FindOne(ctx, bson.D{{Key: "_id", Value: 7}}).Decode(&got); err != nil || got["owner"] != "o7" {
		t.Fatalf("read: %v %v", err, got)
	}
	// a cursor over several batches
	cur, err := c.Find(ctx, bson.D{}, options.Find().SetBatchSize(100))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for cur.Next(ctx) {
		n++
	}
	if n != 3000 {
		t.Fatalf("cursor read %d documents", n)
	}
	if _, err := c.UpdateOne(ctx, bson.D{{Key: "_id", Value: 7}}, bson.D{{Key: "$inc", Value: bson.D{{Key: "balance", Value: 1}}}}); err != nil {
		t.Fatal(err)
	}
	before7 := e.doc(t, 7)
	if r, err := c.DeleteOne(ctx, bson.D{{Key: "_id", Value: 8}}); err != nil || r.DeletedCount != 1 {
		t.Fatalf("delete: %v %+v", err, r)
	}
	if _, err := c.InsertMany(ctx, []any{bson.D{{Key: "owner", Value: "new"}, {Key: "_id", Value: 100000}}, bson.D{{Key: "_id", Value: 100001}}}); err != nil {
		t.Fatal(err)
	}
	if r, err := c.UpdateMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$gte", Value: 10}, {Key: "$lt", Value: 20}}}},
		bson.D{{Key: "$push", Value: bson.D{{Key: "tags", Value: "b"}}}}); err != nil || r.ModifiedCount != 10 {
		t.Fatalf("update many: %v %+v", err, r)
	}
	if r, err := c.UpdateOne(ctx, bson.D{{Key: "_id", Value: 200000}}, bson.D{{Key: "$set", Value: bson.D{{Key: "owner", Value: "up"}}}},
		options.UpdateOne().SetUpsert(true)); err != nil || r.UpsertedID == nil {
		t.Fatalf("upsert: %v %+v", err, r)
	}
	var fam bson.M
	if err := c.FindOneAndUpdate(ctx, bson.D{{Key: "owner", Value: "o30"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "owner", Value: "x"}}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&fam); err != nil || fam["owner"] != "x" {
		t.Fatalf("findAndModify: %v %v", err, fam)
	}
	// a duplicate key fails, and leaves nothing of the write
	_, err = c.InsertMany(ctx, []any{bson.D{{Key: "_id", Value: 300000}}, bson.D{{Key: "_id", Value: 1}}})
	if !mongo.IsDuplicateKeyError(err) {
		t.Fatalf("duplicate key: %v", err)
	}
	if e.doc(t, 300000) != nil {
		t.Fatal("a failed write kept part of itself")
	}
	_ = e.v.Flush()
	del := e.txWith(t, "delete", 8)
	if del == "" {
		t.Fatal("the delete is not in the vault")
	}
	if rep, err := e.m.UndoFromVault(del); err != nil || !rep.Clean() {
		t.Fatalf("undo delete: %v %+v", err, rep)
	}
	if d := e.doc(t, 8); d == nil || d["owner"] != "o8" {
		t.Fatalf("undo did not put the document back: %v", d)
	}
	if !reflect.DeepEqual(e.doc(t, 7), before7) {
		t.Fatalf("undo touched another write: %v vs %v", e.doc(t, 7), before7)
	}
	for _, w := range []struct {
		op string
		id int
	}{{"insert", 100000}, {"update", 15}, {"insert", 200000}, {"update", 30}} {
		id := e.txWith(t, w.op, w.id)
		if id == "" {
			t.Fatalf("%s %d is not in the vault", w.op, w.id)
		}
		if rep, err := e.m.UndoFromVault(id); err != nil || !rep.Clean() {
			t.Fatalf("undo %s %d: %v %+v", w.op, w.id, err, rep)
		}
	}
	if e.doc(t, 100000) != nil || e.doc(t, 100001) != nil || e.doc(t, 200000) != nil {
		t.Fatal("undo did not remove the inserted documents")
	}
	if d := e.doc(t, 15); len(d["tags"].(bson.A)) != 1 {
		t.Fatalf("undo did not restore the update: %v", d)
	}
	if d := e.doc(t, 30); d["owner"] != "o30" {
		t.Fatalf("undo did not restore findAndModify: %v", d)
	}
	// a document changed after the write is a conflict, and nothing is written
	if _, err := c.UpdateOne(ctx, bson.D{{Key: "_id", Value: 40}}, bson.D{{Key: "$set", Value: bson.D{{Key: "owner", Value: "a"}}}}); err != nil {
		t.Fatal(err)
	}
	_ = e.v.Flush()
	id := e.txWith(t, "update", 40)
	if _, err := e.direct.Database(e.db).Collection("accounts").UpdateOne(ctx, bson.D{{Key: "_id", Value: 40}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "owner", Value: "later"}}}}); err != nil {
		t.Fatal(err)
	}
	if rep, err := e.m.UndoFromVault(id); err == nil && rep.Clean() {
		t.Fatal("undo overwrote a later change")
	}
	if e.doc(t, 40)["owner"] != "later" {
		t.Fatal("a refused undo wrote")
	}
}

// A client's own transaction is stored at its commit; one it aborts leaves nothing.
func TestClientTransactions(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	cl := e.client(t, "")
	c := cl.Database(e.db).Collection("accounts")
	sess, err := cl.StartSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.EndSession(ctx)
	_, err = sess.WithTransaction(ctx, func(ctx context.Context) (any, error) {
		if _, err := c.UpdateOne(ctx, bson.D{{Key: "_id", Value: 1}}, bson.D{{Key: "$set", Value: bson.D{{Key: "owner", Value: "t1"}}}}); err != nil {
			return nil, err
		}
		if _, err := c.UpdateOne(ctx, bson.D{{Key: "_id", Value: 1}}, bson.D{{Key: "$set", Value: bson.D{{Key: "owner", Value: "t2"}}}}); err != nil {
			return nil, err
		}
		_, err := c.DeleteOne(ctx, bson.D{{Key: "_id", Value: 2}})
		return nil, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.doc(t, 1)["owner"] != "t2" || e.doc(t, 2) != nil {
		t.Fatal("the transaction did not commit")
	}
	// aborted
	s2, _ := cl.StartSession()
	defer s2.EndSession(ctx)
	_ = s2.StartTransaction()
	sc := mongo.NewSessionContext(ctx, s2)
	if _, err := c.DeleteOne(sc, bson.D{{Key: "_id", Value: 3}}); err != nil {
		t.Fatal(err)
	}
	if err := s2.AbortTransaction(ctx); err != nil {
		t.Fatal(err)
	}
	if e.doc(t, 3) == nil {
		t.Fatal("abort did not hold")
	}
	_ = e.v.Flush()
	if e.txWith(t, "delete", 3) != "" {
		t.Fatal("an aborted transaction is in the vault")
	}
	id := e.txWith(t, "delete", 2)
	if id == "" || id != e.txWith(t, "update", 1) {
		t.Fatal("the transaction is not one vault entry")
	}
	if rep, err := e.m.UndoFromVault(id); err != nil || !rep.Clean() {
		t.Fatalf("undo: %v %+v", err, rep)
	}
	if e.doc(t, 1)["owner"] != "o1" || e.doc(t, 2) == nil {
		t.Fatal("undo did not restore the transaction")
	}
}

// The policy refuses server-side JavaScript, $out, drops, user changes and mass changes;
// in watch mode it only audits.
func TestRefusals(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	db := e.client(t, "").Database(e.db)
	c := db.Collection("accounts")
	cases := map[string]error{}
	_, cases["$where"] = c.Find(ctx, bson.D{{Key: "$where", Value: "sleep(100) || true"}})
	_, cases["$out"] = c.Aggregate(ctx, mongo.Pipeline{{{Key: "$out", Value: "copy"}}})
	cases["drop"] = c.Drop(ctx)
	cases["createUser"] = db.RunCommand(ctx, bson.D{{Key: "createUser", Value: "x"}, {Key: "pwd", Value: "y"}, {Key: "roles", Value: bson.A{}}}).Err()
	_, cases["mass"] = c.UpdateMany(ctx, bson.D{}, bson.D{{Key: "$set", Value: bson.D{{Key: "owner", Value: "all"}}}})
	_, cases["mass delete"] = c.DeleteMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$gt", Value: 1000}}}})
	for name, err := range cases {
		if !refused(err) {
			t.Errorf("%s was not refused: %v", name, err)
		}
	}
	if n, _ := e.direct.Database(e.db).Collection("accounts").CountDocuments(ctx, bson.D{{Key: "owner", Value: "all"}}); n != 0 {
		t.Fatal("a refused write changed documents")
	}
	if n, _ := e.direct.Database(e.db).Collection("accounts").CountDocuments(ctx, bson.D{}); n != 3000 {
		t.Fatal("a refused delete removed documents")
	}
	// a transaction that is refused at its commit is rolled back
	cl := e.client(t, "")
	sess, _ := cl.StartSession()
	defer sess.EndSession(ctx)
	_ = sess.StartTransaction()
	sc := mongo.NewSessionContext(ctx, sess)
	if _, err := cl.Database(e.db).Collection("accounts").UpdateMany(sc, bson.D{}, bson.D{{Key: "$set", Value: bson.D{{Key: "owner", Value: "all"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := sess.CommitTransaction(ctx); !refused(err) {
		t.Fatalf("a mass change in a transaction was not refused: %v", err)
	}
	if n, _ := e.direct.Database(e.db).Collection("accounts").CountDocuments(ctx, bson.D{{Key: "owner", Value: "all"}}); n != 0 {
		t.Fatal("a refused transaction committed")
	}
}

func TestWatchMode(t *testing.T) {
	e := setup(t, func(r *Route) { r.Mode = "watch" })
	ctx := context.Background()
	c := e.client(t, "").Database(e.db).Collection("accounts")
	if _, err := c.Find(ctx, bson.D{{Key: "$where", Value: "true"}}); err != nil {
		t.Fatalf("watch mode refused: %v", err)
	}
	if _, err := c.UpdateMany(ctx, bson.D{}, bson.D{{Key: "$set", Value: bson.D{{Key: "w", Value: 1}}}}); err != nil {
		t.Fatalf("watch mode refused: %v", err)
	}
	_ = e.v.Flush()
	if e.txWith(t, "update", 1) == "" {
		t.Fatal("watch mode did not capture the write")
	}
}

// Clients log in with SCRAM-SHA-256 to the gateway's own users; the gateway logs in to
// MongoDB with its own credentials.
func TestLogin(t *testing.T) {
	e := setup(t, func(r *Route) { r.Trust = false; r.Users = map[string]string{"app": "s3cret"} })
	ctx := context.Background()
	if err := e.client(t, "app:s3cret@").Database(e.db).Collection("accounts").FindOne(ctx, bson.D{{Key: "_id", Value: 1}}).Err(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := e.client(t, "app:wrong@").Database(e.db).Collection("accounts").FindOne(ctx, bson.D{}).Err(); err == nil {
		t.Fatal("a wrong password logged in")
	}
	if err := e.client(t, "").Database(e.db).Collection("accounts").FindOne(ctx, bson.D{}).Err(); err == nil {
		t.Fatal("no credentials got in")
	}
}

// The gateway logs in to a server that requires it (UNDOLAYER_TEST_MONGO_AUTH: a URI with
// credentials; a standalone server, so writes are refused: they cannot run in a transaction).
func TestUpstreamLogin(t *testing.T) {
	uri := os.Getenv("UNDOLAYER_TEST_MONGO_AUTH")
	if uri == "" {
		t.Skip("set UNDOLAYER_TEST_MONGO_AUTH to run")
	}
	d := t.TempDir()
	m, err := tx.NewManager(filepath.Join(d, "state"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(Route{Name: "a", Listen: "127.0.0.1:0", URI: uri, Trust: true}, m)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = g.Serve(l) }()
	defer l.Close()
	ctx := context.Background()
	cl, err := mongo.Connect(options.Client().ApplyURI("mongodb://" + l.Addr().String() + "/").SetServerSelectionTimeout(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Disconnect(ctx)
	if _, err := cl.ListDatabaseNames(ctx, bson.D{}); err != nil {
		t.Fatalf("through a logged-in gateway: %v", err)
	}
	_, err = cl.Database("t").Collection("c").InsertOne(ctx, bson.D{{Key: "x", Value: 1}})
	if !refused(err) {
		t.Fatalf("a write to a standalone server was not refused: %v", err)
	}
	g.R.URI = strings.Replace(uri, ":pw@", ":bad@", 1)
	bad, _ := New(Route{Name: "b", Listen: "127.0.0.1:0", URI: g.R.URI, Trust: true}, m)
	if _, err := bad.dial(); err == nil {
		t.Fatal("a wrong password logged in to MongoDB")
	}
}
