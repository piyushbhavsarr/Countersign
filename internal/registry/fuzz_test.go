package registry

import (
	"strings"
	"testing"
)

// Whatever the value, it stays one path segment: no new segment, no "..", no query, no fragment.
func FuzzRenderPath(f *testing.F) {
	for _, s := range []string{"evt_1", "../admin", "..", ".", "a/b", "x?y=1#z", "%2e%2e", "\x00", "a\\b", "@evil.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		got, err := RenderPath("/v1/items/{args.id}/sub", map[string]any{"args": map[string]any{"id": v}})
		if err != nil {
			return
		}
		mid := strings.TrimSuffix(strings.TrimPrefix(got, "/v1/items/"), "/sub")
		if !strings.HasPrefix(got, "/v1/items/") || !strings.HasSuffix(got, "/sub") ||
			strings.ContainsAny(mid, "/?#") || mid == ".." || mid == "." {
			t.Fatalf("value %q escaped its segment: %q", v, got)
		}
	})
}
