// Package scanner provides the second secret signal: gitleaks, and repository visibility.
// Committed content counts as public only in a public repository; private, local and
// undeterminable repositories are scanned. Hits send egress to the approval lane.
package scanner

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Finding struct {
	Secret string `json:"Secret"`
	RuleID string `json:"RuleID"`
	File   string `json:"File"`
}

func Available() bool { _, err := exec.LookPath("gitleaks"); return err == nil }

func run(args []string, stdin string) []Finding {
	full := append(args, "--no-banner", "--report-format", "json", "--report-path", "-", "--exit-code", "0",
		"--log-level", "error")
	cmd := exec.Command("gitleaks", full...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, _ := cmd.Output()
	var f []Finding
	_ = json.Unmarshal(bytes.TrimSpace(out), &f)
	var keep []Finding
	for _, x := range f {
		if x.Secret != "" {
			keep = append(keep, x)
		}
	}
	return keep
}

func ScanText(text string) []Finding {
	if text == "" || !Available() {
		return nil
	}
	return run([]string{"stdin"}, text)
}

func ScanDir(root string) []Finding {
	if !Available() {
		return nil
	}
	return run([]string{"dir", root}, "")
}

var (
	visMu    sync.Mutex
	visCache = map[string]string{}
)

func githubSlug(url string) string {
	for _, p := range []string{"https://github.com/", "http://github.com/", "git@github.com:", "ssh://git@github.com/"} {
		if strings.HasPrefix(url, p) {
			return strings.TrimSuffix(strings.TrimSuffix(url[len(p):], "/"), ".git")
		}
	}
	return ""
}

// Visibility returns "public", "private" or "local"; undeterminable counts as private.
func Visibility(root, override string) string {
	if override != "" {
		return override
	}
	visMu.Lock()
	defer visMu.Unlock()
	if v, ok := visCache[root]; ok {
		return v
	}
	vis := "local"
	out, err := exec.Command("git", "-C", root, "remote", "-v").Output()
	if err == nil {
		urls := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) >= 2 {
				urls[f[1]] = true
			}
		}
		if len(urls) > 0 {
			vis = "private"
			allPublic := true
			for u := range urls {
				s := githubSlug(u)
				if s == "" || !githubPublic(s) {
					allPublic = false
					break
				}
			}
			if allPublic {
				vis = "public"
			}
		}
	}
	visCache[filepath.Clean(root)] = vis
	return vis
}

func githubPublic(slug string) bool {
	if _, err := exec.LookPath("gh"); err == nil {
		out, err := exec.Command("gh", "repo", "view", slug, "--json", "visibility", "-q", ".visibility").Output()
		if err == nil {
			return strings.EqualFold(strings.TrimSpace(string(out)), "PUBLIC")
		}
	}
	c := http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get("https://api.github.com/repos/" + slug)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var body struct {
		Private *bool `json:"private"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&body) != nil || body.Private == nil {
		return false
	}
	return !*body.Private
}
