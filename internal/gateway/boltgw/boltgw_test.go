package boltgw

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"undolayer/internal/policy"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

// UNDOLAYER_TEST_NEO4J: bolt://neo4j:password@127.0.0.1:7687 (Neo4j 5 with APOC triggers);
// UNDOLAYER_TEST_NEO4J_CALLBACK_HOST: how the database reaches this machine (default
// host.docker.internal).
type env struct {
	direct neo4j.DriverWithContext
	gw     *Gateway
	m      *tx.Manager
	v      *vault.Vault
	addr   string
}

func setup(t *testing.T, mod func(*Route)) *env {
	t.Helper()
	uri := os.Getenv("UNDOLAYER_TEST_NEO4J")
	if uri == "" {
		t.Skip("set UNDOLAYER_TEST_NEO4J to run the Neo4j gateway tests")
	}
	cbHost := os.Getenv("UNDOLAYER_TEST_NEO4J_CALLBACK_HOST")
	if cbHost == "" {
		cbHost = "host.docker.internal"
	}
	ctx := context.Background()
	g0, _ := New(Route{Name: "x", Listen: "127.0.0.1:0", URI: uri, Callback: "x", CallbackURL: "x", Trust: true}, &tx.Manager{})
	direct, err := neo4j.NewDriverWithContext("bolt://"+g0.addr, neo4j.BasicAuth(g0.user, g0.pass, ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { direct.Close(ctx) })
	if _, err := neo4j.ExecuteQuery(ctx, direct, "MATCH (n) DETACH DELETE n", nil, neo4j.EagerResultTransformer); err != nil {
		t.Fatal(err)
	}
	if _, err := neo4j.ExecuteQuery(ctx, direct, `UNWIND range(1, 3000) AS i CREATE (:Person {id: i, name: 'p' + i, born: date('1990-01-01'),
		score: i * 1.5, tags: ['a', 'b'], seen: datetime('2024-05-01T10:00:00Z')})`, nil, neo4j.EagerResultTransformer); err != nil {
		t.Fatal(err)
	}
	if _, err := neo4j.ExecuteQuery(ctx, direct, "MATCH (a:Person {id: 1}), (b:Person {id: 2}) CREATE (a)-[:KNOWS {since: 2020}]->(b)", nil, neo4j.EagerResultTransformer); err != nil {
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
	cl, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := cl.Addr().(*net.TCPAddr).Port
	cl.Close()
	r := Route{Name: "main", Listen: "127.0.0.1:0", URI: uri, Trust: true, Callback: fmt.Sprintf("0.0.0.0:%d", port),
		CallbackURL: fmt.Sprintf("http://%s:%d/capture", cbHost, port)}
	if mod != nil {
		mod(&r)
	}
	g, err := New(r, m)
	if err != nil {
		t.Fatal(err)
	}
	m.Register(g.Conn)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g.R.Advertise = l.Addr().String()
	go func() { _ = g.Serve(l) }()
	t.Cleanup(func() { g.Close(); _ = l.Close(); _ = m.Flush() })
	for i := 0; !g.healthy.Load(); i++ {
		if i > 600 {
			t.Fatal("capture never became healthy")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return &env{direct: direct, gw: g, m: m, v: v, addr: l.Addr().String()}
}

func (e *env) client(t *testing.T, auth neo4j.AuthToken) neo4j.DriverWithContext {
	t.Helper()
	if auth.Tokens == nil {
		auth = neo4j.NoAuth()
	}
	d, err := neo4j.NewDriverWithContext("bolt://"+e.addr, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close(context.Background()) })
	return d
}

func (e *env) one(t *testing.T, q string) any {
	t.Helper()
	r, err := neo4j.ExecuteQuery(context.Background(), e.direct, q, nil, neo4j.EagerResultTransformer)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Records) == 0 {
		return nil
	}
	return r.Records[0].Values[0]
}

func (e *env) txWith(t *testing.T, op, table string) string {
	t.Helper()
	_ = e.v.Flush()
	bs, _, err := e.v.Batches(func(r *vault.Record) bool { return r.Phase == "intent" })
	if err != nil {
		t.Fatal(err)
	}
	last := ""
	for _, b := range bs {
		for _, r := range b.Rows {
			if r.Op == op && strings.HasPrefix(r.Table, table) {
				last = b.Tx
			}
		}
	}
	return last
}

func refused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "refused by Countersign")
}

func TestWritesAreCapturedAndUndone(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	d := e.client(t, neo4j.AuthToken{})
	q := func(cypher string, p map[string]any) (*neo4j.EagerResult, error) {
		return neo4j.ExecuteQuery(ctx, d, cypher, p, neo4j.EagerResultTransformer)
	}
	r, err := q("MATCH (p:Person {id: $id}) RETURN p.name", map[string]any{"id": 7})
	if err != nil || r.Records[0].Values[0] != "p7" {
		t.Fatalf("read: %v %v", err, r)
	}
	before5 := e.one(t, "MATCH (p:Person {id: 5}) RETURN apoc.convert.toJson(properties(p)) + apoc.convert.toJson(labels(p))")
	// changed in place: properties, a new label, a removed property
	if _, err := q("MATCH (p:Person {id: 5}) SET p.score = 99, p.born = date('2000-02-02'), p:VIP REMOVE p.tags", nil); err != nil {
		t.Fatalf("update: %v", err)
	}
	upd := e.txWith(t, "update", "node")
	if upd == "" {
		t.Fatal("the update is not in the vault")
	}
	// deleted with its relationship, in an explicit transaction, and a new node
	sess := d.NewSession(ctx, neo4j.SessionConfig{})
	_, err = sess.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		if _, err := tx.Run(ctx, "MATCH (p:Person {id: 1}) DETACH DELETE p", nil); err != nil {
			return nil, err
		}
		_, err := tx.Run(ctx, "CREATE (:Person {id: 9999, name: 'new'})", nil)
		return nil, err
	})
	sess.Close(ctx)
	if err != nil {
		t.Fatalf("transaction: %v", err)
	}
	del := e.txWith(t, "delete", "node")
	if del == "" || del != e.txWith(t, "insert", "node") {
		t.Fatal("the transaction is not one vault entry")
	}
	if rep, err := e.m.UndoFromVault(del); err != nil || !rep.Clean() {
		t.Fatalf("undo: %v %+v", err, rep)
	}
	if n := e.one(t, "MATCH (p:Person {id: 1})-[k:KNOWS {since: 2020}]->(:Person {id: 2}) RETURN count(k)"); n != int64(1) {
		t.Fatalf("undo did not put back the node and its relationship: %v", n)
	}
	if n := e.one(t, "MATCH (p:Person {id: 9999}) RETURN count(p)"); n != int64(0) {
		t.Fatal("undo did not remove the new node")
	}
	if b := e.one(t, "MATCH (p:Person {id: 1}) RETURN toString(p.born) + '|' + toString(p.seen) + '|' + toString(p.score)"); b != "1990-01-01|2024-05-01T10:00:00Z|1.5" {
		t.Fatalf("types did not survive: %v", b)
	}
	if rep, err := e.m.UndoFromVault(upd); err != nil || !rep.Clean() {
		t.Fatalf("undo update: %v %+v", err, rep)
	}
	if got := e.one(t, "MATCH (p:Person {id: 5}) RETURN apoc.convert.toJson(properties(p)) + apoc.convert.toJson(labels(p))"); got != before5 {
		t.Fatalf("undo did not restore the node:\n got %v\nwant %v", got, before5)
	}
	// a node changed after the write is a conflict, and nothing is written
	if _, err := q("MATCH (p:Person {id: 40}) SET p.name = 'a'", nil); err != nil {
		t.Fatal(err)
	}
	id := e.txWith(t, "update", "node")
	e.one(t, "MATCH (p:Person {id: 40}) SET p.name = 'later' RETURN 1")
	if rep, err := e.m.UndoFromVault(id); err == nil && rep.Clean() {
		t.Fatal("undo overwrote a later change")
	}
	if e.one(t, "MATCH (p:Person {id: 40}) RETURN p.name") != "later" {
		t.Fatal("a refused undo wrote")
	}
}

func TestRefusals(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	d := e.client(t, neo4j.AuthToken{})
	for name, q := range map[string]string{
		"tautology": "MATCH (p:Person) WHERE p.name = 'x' OR 1=1 RETURN p",
		"sleep":     "CALL apoc.util.sleep(10)",
		"load csv":  "LOAD CSV FROM 'file:///etc/passwd' AS l RETURN l",
		"dynamic":   "CALL apoc.cypher.run('MATCH (n) DETACH DELETE n', {})",
		"periodic":  "CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DETACH DELETE n', {})",
		"in txs":    "MATCH (n) CALL { WITH n DETACH DELETE n } IN TRANSACTIONS",
		"trigger":   "CALL apoc.trigger.drop('neo4j', 'countersign')",
		"user":      "CREATE USER x SET PASSWORD 'y'",
		"dbms":      "CALL dbms.setConfigValue('x', 'y')",
		"mass":      "MATCH (p:Person) WHERE p.id > 100 DETACH DELETE p",
	} {
		if _, err := neo4j.ExecuteQuery(ctx, d, q, nil, neo4j.EagerResultTransformer); !refused(err) {
			t.Errorf("%s was not refused: %v", name, err)
		}
	}
	if n := e.one(t, "MATCH (p:Person) RETURN count(p)"); n != int64(3000) {
		t.Fatalf("a refused write changed the graph: %v nodes", n)
	}
}

func TestLogin(t *testing.T) {
	e := setup(t, func(r *Route) { r.Trust = false; r.Users = map[string]string{"app": "s3cret"} })
	ctx := context.Background()
	if err := e.client(t, neo4j.BasicAuth("app", "s3cret", "")).VerifyConnectivity(ctx); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := e.client(t, neo4j.BasicAuth("app", "wrong", "")).VerifyConnectivity(ctx); err == nil {
		t.Fatal("a wrong password logged in")
	}
}
