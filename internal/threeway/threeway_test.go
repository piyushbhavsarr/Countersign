package threeway

import (
	"encoding/json"
	"testing"
)

func doc(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(err)
	}
	return v
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRevertKeepsOtherPeoplesChanges(t *testing.T) {
	before := doc(`{"spec":{"replicas":1,"image":"v1","env":{"A":"1"}}}`)
	after := doc(`{"spec":{"replicas":1,"image":"v2","env":{"A":"1"}}}`)                // we changed the image
	now := doc(`{"spec":{"replicas":5,"image":"v2","env":{"A":"1","B":"2"}},"x":true}`) // autoscaler + someone else
	got, conflicts, err := Revert(before, after, now)
	if err != nil || len(conflicts) > 0 {
		t.Fatal(err, conflicts)
	}
	want := `{"spec":{"env":{"A":"1","B":"2"},"image":"v1","replicas":5},"x":true}`
	if js(got) != want {
		t.Fatalf("got %s want %s", js(got), want)
	}
}

func TestSameFieldChangedAgainIsAConflict(t *testing.T) {
	before := doc(`{"image":"v1"}`)
	after := doc(`{"image":"v2"}`)
	now := doc(`{"image":"v3"}`)
	if _, c, _ := Revert(before, after, now); len(c) != 1 || c[0].Path != "image" {
		t.Fatalf("conflict not found: %v", c)
	}
}

func TestAddedAndRemovedFields(t *testing.T) {
	before := doc(`{"a":1,"gone":"x"}`)
	after := doc(`{"a":1,"new":"y"}`) // we removed "gone" and added "new"
	now := doc(`{"a":2,"new":"y"}`)
	got, c, err := Revert(before, after, now)
	if err != nil || len(c) > 0 {
		t.Fatal(err, c)
	}
	if js(got) != `{"a":2,"gone":"x"}` {
		t.Fatalf("got %s", js(got))
	}
}

func TestArraysPerElementWhenShapeHolds(t *testing.T) {
	before := doc(`{"containers":[{"name":"app","image":"v1"},{"name":"sidecar","image":"s1"}]}`)
	after := doc(`{"containers":[{"name":"app","image":"v2"},{"name":"sidecar","image":"s1"}]}`)
	now := doc(`{"containers":[{"name":"app","image":"v2"},{"name":"sidecar","image":"s9"}]}`)
	got, c, err := Revert(before, after, now)
	if err != nil || len(c) > 0 {
		t.Fatal(err, c)
	}
	if js(got) != `{"containers":[{"image":"v1","name":"app"},{"image":"s9","name":"sidecar"}]}` {
		t.Fatalf("got %s", js(got))
	}
	// someone added a container since: indexes no longer line up, the array is one value
	now2 := doc(`{"containers":[{"name":"app","image":"v2"},{"name":"sidecar","image":"s1"},{"name":"x","image":"x"}]}`)
	if _, c, err := Revert(before, after, now2); err == nil && len(c) == 0 {
		t.Fatal("restored per index into an array whose shape changed")
	}
}

func TestAlreadyRevertedIsLeftAlone(t *testing.T) {
	before, after := doc(`{"a":1}`), doc(`{"a":2}`)
	got, c, _ := Revert(before, after, doc(`{"a":1,"b":3}`))
	if len(c) > 0 || js(got) != `{"a":1,"b":3}` {
		t.Fatalf("%v %s", c, js(got))
	}
}

func TestTouchedFindsOverlap(t *testing.T) {
	before, after := doc(`{"a":1,"b":1}`), doc(`{"a":2,"b":1}`)
	if c := Touched(before, after, doc(`{"a":1,"b":9}`)); len(c) != 0 {
		t.Fatalf("a change to another field counted: %v", c)
	}
	if c := Touched(before, after, doc(`{"a":7,"b":1}`)); len(c) != 1 {
		t.Fatalf("a change to our field was missed: %v", c)
	}
}
