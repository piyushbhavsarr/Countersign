package cloud

import (
	"strings"
	"testing"
)

func FuzzAWSNames(f *testing.F) {
	f.Add("s3", "ListBuckets")
	f.Add("--endpoint-url=x", "A")
	f.Fuzz(func(t *testing.T, svc, act string) {
		if awsNames(svc, act) != nil {
			return
		}
		if strings.HasPrefix(svc, "-") || strings.HasPrefix(act, "-") || strings.ContainsAny(svc+act, " =\t\n/") {
			t.Fatalf("accepted service %q action %q", svc, act)
		}
	})
}

func FuzzPatchPaths(f *testing.F) {
	f.Add([]byte(`[{"op":"replace","path":"/A/0/B","value":1},{"op":"move","from":"/x","path":"/y"}]`))
	f.Fuzz(func(t *testing.T, patch []byte) {
		paths, err := patchPaths(patch)
		if err != nil {
			return
		}
		for _, p := range paths {
			_ = touches(p, "/properties/A/*/B")
		}
	})
}
