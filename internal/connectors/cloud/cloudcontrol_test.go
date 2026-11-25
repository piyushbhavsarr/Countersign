package cloud

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"

	"undolayer/internal/model"
	"undolayer/internal/policy"
	"undolayer/internal/tx"
)

// The schemas in testdata are AWS's published resource schemas (CloudformationSchema.zip),
// so what is create-only, write-only or read-only comes from AWS, not from these tests.
// store stands in for the Cloud Control service so the undo logic can be tested in full;
// the real API path is proven against an account by `undolayer aws verify`.
type store struct {
	mu      sync.Mutex
	schemas map[string]*Schema
	res     map[string]map[string]any // "type|id" -> properties
	tokens  map[string]string
	n       int
}

func newStore(t *testing.T) *store {
	s := &store{schemas: map[string]*Schema{}, res: map[string]map[string]any{}, tokens: map[string]string{}}
	for _, f := range []string{"aws-sqs-queue.json", "aws-rds-dbinstance.json", "aws-lambda-function.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		sch, err := ParseSchema(b)
		if err != nil {
			t.Fatal(err)
		}
		s.schemas[sch.TypeName] = sch
	}
	return s
}

func (s *store) Schema(typ string) (*Schema, error) {
	if sch := s.schemas[typ]; sch != nil {
		return sch, nil
	}
	return nil, fmt.Errorf("TypeNotFoundException: %s", typ)
}

func (s *store) Get(typ, id string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.res[typ+"|"+id]; r != nil {
		return deep(r), nil
	}
	return nil, nil
}

func (s *store) List(typ string) (any, error) { return nil, nil }

func (s *store) Create(typ string, desired map[string]any, token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.tokens[token]; ok && token != "" { // Cloud Control: same ClientToken, same request
		return id, nil
	}
	s.n++
	id := fmt.Sprintf("https://sqs.example/%d", s.n)
	props := deep(desired)
	props["QueueUrl"], props["Arn"] = id, fmt.Sprintf("arn:aws:sqs:::%d", s.n) // read-only, set by AWS
	s.res[typ+"|"+id] = props
	if token != "" {
		s.tokens[token] = id
	}
	return id, nil
}

func (s *store) Update(typ, id string, patch []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.res[typ+"|"+id]
	if r == nil {
		return errors.New("ResourceNotFoundException")
	}
	p, err := jsonpatch.DecodePatch(patch)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(r)
	out, err := p.Apply(b)
	if err != nil {
		return err
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	s.res[typ+"|"+id] = m
	return nil
}

func (s *store) Delete(typ, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.res, typ+"|"+id)
	return nil
}

func (s *store) set(typ, id, key string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.res[typ+"|"+id][key] = v
}

func ccSetup(t *testing.T) (*tx.Manager, *Connector, *store) {
	dir := t.TempDir()
	m, err := tx.NewManager(filepath.Join(dir, "state"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	c := New(filepath.Join(dir, "state"))
	st := newStore(t)
	c.CC = st
	m.Register(c)
	return m, c, st
}

const sqs = "AWS::SQS::Queue"

func res(t *testing.T, x *tx.Tx, op string, args map[string]any) (map[string]any, error) {
	t.Helper()
	r, err := x.Call("cloud", op, args)
	m, _ := r.(map[string]any)
	return m, err
}

func TestCreatesAndUpdatesAreCheckedAgainstAWSsSchema(t *testing.T) {
	m, _, st := ccSetup(t)
	x := m.Begin("set up queues")
	if _, err := res(t, x, "resource_create", map[string]any{"type": sqs, "desired_state": map[string]any{"QueueName": "q", "Colour": "red"}}); err == nil || !strings.Contains(err.Error(), "Colour is not a property") {
		t.Fatalf("an unknown property was accepted: %v", err)
	}
	if _, err := res(t, x, "resource_create", map[string]any{"type": sqs, "desired_state": map[string]any{"QueueName": "q", "Arn": "x"}}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("a read-only property was accepted: %v", err)
	}
	id, _ := st.Create(sqs, map[string]any{"QueueName": "orders", "VisibilityTimeout": 30}, "")
	if _, err := res(t, x, "resource_update", map[string]any{"type": sqs, "identifier": id,
		"patch": []any{map[string]any{"op": "replace", "path": "/QueueName", "value": "orders2"}}}); err == nil || !strings.Contains(err.Error(), "create") {
		t.Fatalf("a create-only change was accepted: %v", err)
	}
}

func TestWriteOnlyChangesCannotBeUndoneSoTheyNeedApproval(t *testing.T) {
	m, c, st := ccSetup(t)
	sch, _ := st.Schema("AWS::RDS::DBInstance")
	_ = c.markVerified(sch)
	st.res["AWS::RDS::DBInstance|db1"] = map[string]any{"DBInstanceIdentifier": "db1", "DBInstanceClass": "db.t3.micro"}
	x := m.Begin("rotate the database password")
	r, err := res(t, x, "resource_update", map[string]any{"type": "AWS::RDS::DBInstance", "identifier": "db1",
		"patch": []any{map[string]any{"op": "replace", "path": "/MasterUserPassword", "value": "new-secret-pw"}}})
	if err != nil {
		t.Fatal(err)
	}
	if r["held"] != true {
		t.Fatalf("a write-only change was not held for approval: %v", r)
	}
	if a := x.Actions[len(x.Actions)-1]; a.Effect != model.Irreversible {
		t.Fatalf("write-only change classified %s", a.Effect)
	}
}

func TestUnverifiedTypesNeedApprovalUntilVerified(t *testing.T) {
	m, c, _ := ccSetup(t)
	x := m.Begin("create a queue")
	if r, _ := res(t, x, "resource_create", map[string]any{"type": sqs, "desired_state": map[string]any{"QueueName": "q"}}); r["held"] != true {
		t.Fatalf("an unverified type's create was not held: %v", r)
	}
	_, _ = x.Rollback("t")
	patch := []byte(`[{"op":"replace","path":"/VisibilityTimeout","value":45}]`)
	if err := c.Verify(sqs, map[string]any{"QueueName": "verify-q", "VisibilityTimeout": 30}, patch); err != nil {
		t.Fatal(err)
	}
	y := m.Begin("create a queue")
	if r, _ := res(t, y, "resource_create", map[string]any{"type": sqs, "desired_state": map[string]any{"QueueName": "q"}}); r["held"] == true {
		t.Fatalf("a verified type's create still needs approval: %v", r)
	}
}

func markTypeVerified(t *testing.T, c *Connector, st *store) {
	t.Helper()
	sch, _ := st.Schema(sqs)
	if err := c.markVerified(sch); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateUndoRevertsOnlyItsOwnProperties(t *testing.T) {
	m, c, st := ccSetup(t)
	markTypeVerified(t, c, st)
	id, _ := st.Create(sqs, map[string]any{"QueueName": "orders", "VisibilityTimeout": 30, "MessageRetentionPeriod": 345600}, "")
	x := m.Begin("raise the orders queue visibility timeout")
	r, err := res(t, x, "resource_update", map[string]any{"type": sqs, "identifier": id,
		"patch": []any{map[string]any{"op": "replace", "path": "/VisibilityTimeout", "value": 120}}})
	if err != nil || r["held"] == true {
		t.Fatalf("%v %v", r, err)
	}
	if got, _ := st.Get(sqs, id); got["VisibilityTimeout"] != float64(30) {
		t.Fatal("the update reached AWS before commit")
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	st.set(sqs, id, "MessageRetentionPeriod", 86400) // someone else, meanwhile
	if _, err := x.Undo(""); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(sqs, id)
	if got["VisibilityTimeout"] != float64(30) || got["MessageRetentionPeriod"] != float64(86400) {
		t.Fatalf("undo did not revert only its own property: %v", got)
	}

	y := m.Begin("raise it again")
	_, _ = res(t, y, "resource_update", map[string]any{"type": sqs, "identifier": id,
		"patch": []any{map[string]any{"op": "replace", "path": "/VisibilityTimeout", "value": 120}}})
	if _, err := y.Commit(); err != nil {
		t.Fatal(err)
	}
	st.set(sqs, id, "VisibilityTimeout", 300) // the same property, changed again
	rep, _ := y.Undo("")
	if rep == nil || len(rep.Conflicts) == 0 {
		t.Fatalf("undo overwrote a later change to the same property: %+v", rep)
	}
	if got, _ := st.Get(sqs, id); got["VisibilityTimeout"] != float64(300) {
		t.Fatal("the later change was lost")
	}
}

func TestAConcurrentChangeToTheSamePropertyStopsTheCommit(t *testing.T) {
	m, c, st := ccSetup(t)
	markTypeVerified(t, c, st)
	id, _ := st.Create(sqs, map[string]any{"QueueName": "orders", "VisibilityTimeout": 30, "DelaySeconds": 0}, "")
	x := m.Begin("raise the timeout")
	_, _ = res(t, x, "resource_update", map[string]any{"type": sqs, "identifier": id,
		"patch": []any{map[string]any{"op": "replace", "path": "/VisibilityTimeout", "value": 120}}})
	st.set(sqs, id, "DelaySeconds", 5) // another property: fine
	st.set(sqs, id, "VisibilityTimeout", 60)
	var cc *model.CommitConflict
	if _, err := x.Commit(); !errors.As(err, &cc) {
		t.Fatalf("committed over a concurrent change: %v", err)
	}
	if got, _ := st.Get(sqs, id); got["VisibilityTimeout"] != float64(60) {
		t.Fatal("the concurrent change was overwritten")
	}
}

func TestCreateIsUndoneByDeletingAndDeleteNeedsApproval(t *testing.T) {
	m, c, st := ccSetup(t)
	markTypeVerified(t, c, st)
	x := m.Begin("create the alerts queue")
	_, _ = res(t, x, "resource_create", map[string]any{"type": sqs, "desired_state": map[string]any{"QueueName": "alerts"}})
	if len(st.res) != 0 {
		t.Fatal("created before commit")
	}
	if _, err := x.Commit(); err != nil {
		t.Fatal(err)
	}
	if len(st.res) != 1 {
		t.Fatal("not created on commit")
	}
	var id string
	for k := range st.res {
		id = strings.SplitN(k, "|", 2)[1]
	}
	if _, err := x.Undo(""); err != nil {
		t.Fatal(err)
	}
	if len(st.res) != 0 {
		t.Fatal("undo did not delete what the commit created")
	}

	id, _ = st.Create(sqs, map[string]any{"QueueName": "keep"}, "")
	y := m.Begin("clean up")
	if r, _ := res(t, y, "resource_delete", map[string]any{"type": sqs, "identifier": id}); r["held"] != true {
		t.Fatalf("a delete was not held for approval: %v", r)
	}
	var ar *model.ApprovalRequired
	if _, err := y.Commit(); !errors.As(err, &ar) {
		t.Fatalf("deleted without approval: %v", err)
	}
	if got, _ := st.Get(sqs, id); got == nil {
		t.Fatal("the queue was deleted")
	}
}

func TestSchemaPointersMatchPatchPaths(t *testing.T) {
	for _, tc := range []struct {
		path, pointer string
		want          bool
	}{
		{"/VisibilityTimeout", "/properties/VisibilityTimeout", true},
		{"/Endpoint/Address", "/properties/Endpoint", true},
		{"/Endpoint", "/properties/Endpoint/Address", true},
		{"/AdditionalStorageVolumes/0/StorageOperationStatus", "/properties/AdditionalStorageVolumes/*/StorageOperationStatus", true},
		{"/AdditionalStorageVolumes/0/Size", "/properties/AdditionalStorageVolumes/*/StorageOperationStatus", false},
		{"/QueueName", "/properties/FifoQueue", false},
	} {
		if got := touches(tc.path, tc.pointer); got != tc.want {
			t.Errorf("touches(%s, %s) = %v", tc.path, tc.pointer, got)
		}
	}
}
