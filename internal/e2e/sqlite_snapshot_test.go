package e2e

import (
	"errors"
	"strings"
	"testing"

	"undolayer/internal/model"
)

// Two agents on one SQLite database at the same time (snapshot staging).

func TestTwoAgentsOnDifferentRowsBothCommit(t *testing.T) {
	w := world(t)
	a := w.Mgr.Begin("a")
	b := w.MakeManager().Begin("b")
	call(t, a, "sql", "execute", map[string]any{"sql": "UPDATE users SET plan = 'pro' WHERE id = 1"})
	call(t, b, "sql", "execute", map[string]any{"sql": "UPDATE users SET plan = 'team' WHERE id = 2"}) // no waiting for a
	if _, err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Commit(); err != nil {
		t.Fatalf("an agent on other rows could not commit: %v", err)
	}
	if w.Count("users", "id = 1 AND plan = 'pro'") != 1 || w.Count("users", "id = 2 AND plan = 'team'") != 1 {
		t.Fatal("a commit was lost")
	}
}

func TestTheSecondWriterOfARowGetsAConflictNotAnOverwrite(t *testing.T) {
	w := world(t)
	a := w.Mgr.Begin("a")
	b := w.MakeManager().Begin("b")
	call(t, a, "sql", "execute", map[string]any{"sql": "UPDATE users SET plan = 'pro' WHERE id = 1"})
	call(t, b, "sql", "execute", map[string]any{"sql": "UPDATE users SET plan = 'free' WHERE id = 1"})
	if _, err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	var cc *model.CommitConflict
	_, err := b.Commit()
	if !errors.As(err, &cc) && !strings.Contains(fmtErr(err), "changed since") {
		t.Fatalf("the second writer overwrote the first: %v", err)
	}
	if w.Count("users", "id = 1 AND plan = 'pro'") != 1 {
		t.Fatal("the first commit was overwritten")
	}
}

func TestAWhereThatNowMatchesOtherRowsIsAConflict(t *testing.T) {
	w := world(t)
	a := w.Mgr.Begin("a")
	b := w.MakeManager().Begin("b")
	// b previews deleting the 'team' users: none exist in its snapshot
	call(t, b, "sql", "execute", map[string]any{"sql": "DELETE FROM users WHERE plan = 'team'"})
	call(t, a, "sql", "execute", map[string]any{"sql": "UPDATE users SET plan = 'team' WHERE id = 3"})
	if _, err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Commit(); err == nil {
		t.Fatal("a delete that now matches a row nobody previewed was committed")
	}
	if w.Count("users", "id = 3") != 1 {
		t.Fatal("a row was deleted that the preview never showed")
	}
}

func fmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
