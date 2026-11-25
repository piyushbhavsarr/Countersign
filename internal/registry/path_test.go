package registry

import "testing"

func TestPathValuesAreOneSegment(t *testing.T) {
	for in, want := range map[string]string{
		"evt_1":        "/calendars/primary/events/evt_1",
		"../admin":     "/calendars/primary/events/..%2Fadmin",
		"..":           "/calendars/primary/events/%2E%2E",
		"x?delete=1#y": "/calendars/primary/events/x%3Fdelete=1%23y",
		"a/b":          "/calendars/primary/events/a%2Fb",
	} {
		got, err := RenderPath("/calendars/primary/events/{args.id}", map[string]any{"args": map[string]any{"id": in}})
		if err != nil || got != want {
			t.Errorf("%q -> %q (%v), want %q", in, got, err, want)
		}
	}
}
