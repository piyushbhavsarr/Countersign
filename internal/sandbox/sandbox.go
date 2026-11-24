// Package sandbox confines a process with the kernel: sandbox-exec (Seatbelt) on macOS,
// bubblewrap (namespaces) on Linux. Nothing here recognises commands; the guarantees
// come from what the kernel refuses:
//
//   - writes only under Spec.Write (plus /dev/null and friends),
//   - Spec.Hide cannot be read (contents or listings; metadata stays readable so tools
//     can stat ancestors), except paths re-allowed in Spec.ReadAllow,
//   - network: none at all (including DNS), or only the listed proxy endpoints.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type Spec struct {
	Write     []string // writable subtrees
	Hide      []string // unreadable subtrees
	ReadAllow []string // readable even inside Hide
	// Network: "none" (no IP, no DNS), "full", or "proxy" (only ProxyPort on loopback on
	// macOS; on Linux a private network namespace where UnixSockets are the only way out).
	Network     string
	ProxyPort   int
	UnixSockets []string // sockets the process may connect to (gateway, proxy)
	Workdir     string
	// LinuxInit, if set, is run inside the Linux namespace before the command (used to
	// start the loopback->unix-socket bridge for the egress proxy).
	LinuxInit []string
}

var ErrUnavailable = errors.New("no OS sandbox found (need sandbox-exec on macOS or bwrap on Linux)")

// Backend reports which mechanism is available on this machine ("" if none).
func Backend() string {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("sandbox-exec"); err == nil {
			return "sandbox-exec"
		}
	case "linux":
		if _, err := exec.LookPath("bwrap"); err == nil {
			return "bwrap"
		}
	}
	return ""
}

func real(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(h, p[2:])
		}
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}

func uniqReal(ps []string) []string {
	set := map[string]bool{}
	for _, p := range ps {
		if p != "" {
			set[real(p)] = true
		}
	}
	out := []string{}
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func sbplString(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func subpaths(ps []string) string {
	var b strings.Builder
	for _, p := range ps {
		fmt.Fprintf(&b, " (subpath %s)", sbplString(p))
	}
	return b.String()
}

// SeatbeltProfile builds the macOS profile. Last matching rule wins, and a rule naming a
// specific operation beats one naming a wildcard, so re-allows name the same operations.
func SeatbeltProfile(s Spec) string {
	var b strings.Builder
	b.WriteString("(version 1)(allow default)")
	b.WriteString(`(deny file-write* (subpath "/"))`)
	b.WriteString("(allow file-write*" + subpaths(uniqReal(s.Write)) +
		` (literal "/dev/null") (literal "/dev/zero") (literal "/dev/stdout") (literal "/dev/stderr")` +
		` (literal "/dev/tty") (literal "/dev/dtracehelper") (subpath "/dev/fd"))`)
	if hide := uniqReal(s.Hide); len(hide) > 0 {
		b.WriteString("(deny file-read-data file-read-xattr" + subpaths(hide) + ")")
	}
	if allow := uniqReal(append(append([]string{}, s.Write...), s.ReadAllow...)); len(allow) > 0 {
		b.WriteString("(allow file-read-data file-read-xattr file-read-metadata" + subpaths(allow) + ")")
	}
	switch s.Network {
	case "full":
	case "proxy":
		b.WriteString("(deny network*)")
		b.WriteString(`(deny mach-lookup (global-name "com.apple.dnssd.service"))`)
		if s.ProxyPort > 0 {
			fmt.Fprintf(&b, `(allow network-outbound (remote ip "localhost:%d"))`, s.ProxyPort)
		}
		for _, u := range s.UnixSockets {
			fmt.Fprintf(&b, "(allow network-outbound (remote unix-socket (path-literal %s)))", sbplString(real(u)))
		}
	default: // none: no IP traffic, no binding, no name resolution
		b.WriteString("(deny network-outbound (remote ip))(deny network-bind)(deny network-inbound)")
		b.WriteString(`(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))`)
		b.WriteString(`(deny mach-lookup (global-name "com.apple.dnssd.service"))`)
		for _, u := range s.UnixSockets {
			fmt.Fprintf(&b, "(allow network-outbound (remote unix-socket (path-literal %s)))", sbplString(real(u)))
		}
	}
	return b.String()
}

// BwrapArgs builds the Linux bubblewrap invocation (without the trailing command).
func BwrapArgs(s Spec) []string {
	// No blanket tmpfs over /tmp: like the rest of the system it is read-only, and each
	// confined process gets its own private TMPDIR under Write. (A tmpfs would also hide
	// legitimate files under /tmp, such as the binary or the workspace.)
	args := []string{"bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
		"--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts"}
	for _, h := range uniqReal(s.Hide) {
		if st, err := os.Stat(h); err == nil && st.IsDir() {
			args = append(args, "--tmpfs", h)
		} else if err == nil {
			args = append(args, "--ro-bind", "/dev/null", h) // a hidden file reads as empty
		}
	}
	for _, r := range uniqReal(s.ReadAllow) {
		if _, err := os.Stat(r); err == nil {
			args = append(args, "--ro-bind", r, r)
		}
	}
	for _, w := range uniqReal(s.Write) {
		if _, err := os.Stat(w); err == nil {
			args = append(args, "--bind", w, w)
		}
	}
	for _, u := range s.UnixSockets {
		if _, err := os.Stat(u); err == nil {
			args = append(args, "--bind", real(u), real(u))
		}
	}
	if s.Network != "full" {
		args = append(args, "--unshare-net")
	}
	if s.Workdir != "" {
		args = append(args, "--chdir", real(s.Workdir))
	}
	return args
}

// Command returns argv that runs argv confined by s.
func Command(s Spec, argv []string) ([]string, error) {
	switch Backend() {
	case "sandbox-exec":
		return append([]string{"sandbox-exec", "-p", SeatbeltProfile(s)}, argv...), nil
	case "bwrap":
		out := BwrapArgs(s)
		if len(s.LinuxInit) > 0 {
			out = append(out, s.LinuxInit...)
			out = append(out, "--")
		}
		return append(out, argv...), nil
	}
	return nil, ErrUnavailable
}
