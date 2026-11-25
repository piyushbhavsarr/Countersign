package kube

import (
	"strings"
	"testing"
)

// Nothing that passes ident can be an option, a path or more than one word.
func FuzzIdent(f *testing.F) {
	for _, s := range []string{"web", "-x", "--kubeconfig=/tmp", "a b", "a/b", "system:node", "\t", "é"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if ident("name", v) != nil {
			return
		}
		if strings.HasPrefix(v, "-") || strings.ContainsAny(v, " \t\n\r/\\%\x00") {
			t.Fatalf("ident accepted %q", v)
		}
	})
}

func FuzzManifest(f *testing.F) {
	f.Add("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n---\nkind: List\nitems: [1, {a: b}]\n")
	f.Add("[1,2,3]")
	f.Fuzz(func(t *testing.T, m string) { _, _ = documents(m) })
}
