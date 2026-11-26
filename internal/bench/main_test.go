package bench

import (
	"os"
	"testing"

	"undolayer/internal/egress"
)

// Sandboxed shells re-execute this binary as their network-namespace init on Linux.
func TestMain(m *testing.M) {
	egress.MaybeNetinit()
	os.Exit(m.Run())
}
