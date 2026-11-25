package e2e

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// How the cost of one call grows with the length of the task (UNDOLAYER_GROWTH=1).
func TestCallCostGrowth(t *testing.T) {
	if os.Getenv("UNDOLAYER_GROWTH") == "" {
		t.Skip("set UNDOLAYER_GROWTH=1")
	}
	w := world(t)
	x := w.Mgr.Begin("long task")
	start := time.Now()
	var marks []string
	for i := 0; i < 1000; i++ {
		t0 := time.Now()
		call(t, x, "sql", "execute", map[string]any{"sql": fmt.Sprintf("UPDATE users SET plan = 'p%d' WHERE id = %d", i, i%50+1)})
		if i%250 == 0 || i == 999 {
			marks = append(marks, fmt.Sprintf("call %d: %s", i, time.Since(t0)))
		}
	}
	t.Logf("%v total %s", marks, time.Since(start))
	_, _ = x.Rollback("t")
}
