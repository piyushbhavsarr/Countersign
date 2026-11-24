package policy

import "testing"

// Any policy text either loads or is refused; none crashes the loader.
func FuzzParse(f *testing.F) {
	f.Add(`[[rule]]
id = "x"
when = { a = { gt = 1 } }
decision = "deny"`)
	f.Add(`[budget]
max_rows_changed = 5`)
	f.Fuzz(func(t *testing.T, text string) {
		_, _ = Parse(text)
	})
}
