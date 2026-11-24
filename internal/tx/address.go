package tx

import (
	"net"
	"net/mail"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// isAddress reports whether a token names somewhere a message could send a person:
// a URL with a host, an e-mail address, or a domain name. Recognised by parsers - net/url,
// net/mail and the Public Suffix List - so "report.pdf" is not a domain but
// "secure-systems-252.com" is.
func isAddress(tok string) bool {
	tok = strings.Trim(tok, ".,;:!?()[]{}<>\"'")
	if tok == "" {
		return false
	}
	if strings.Contains(tok, "@") {
		if a, err := mail.ParseAddress(tok); err == nil && strings.Contains(a.Address, ".") {
			return true
		}
	}
	host := tok
	if u, err := url.Parse(tok); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if u, err := url.Parse("//" + tok); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	if net.ParseIP(host) != nil {
		return strings.Contains(tok, "://")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	suffix, icann := publicsuffix.PublicSuffix(host)
	return icann && suffix != host
}

// untrustedAddresses: addresses in outgoing content that came from data the agent read
// and that the user's request does not name.
func (t *Tx) untrustedAddresses(blob string) []string {
	if len(t.readTokens) == 0 {
		return nil
	}
	req := normDest(t.Task)
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.FieldsFunc(strings.NewReplacer(`\n`, " ", `\"`, " ").Replace(blob), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '"' || r == '\'' || r == '<' || r == '>' || r == ',' || r == '(' || r == ')'
	}) {
		tok = strings.Trim(tok, ".,;:!?()[]{}<>\"'")
		if seen[tok] || !isAddress(tok) {
			continue
		}
		seen[tok] = true
		if t.readTokens[tok] && !strings.Contains(req, normDest(tok)) {
			out = append(out, tok)
		}
	}
	return out
}

func (t *Tx) learnReadTokens(result any) {
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case string:
			for _, tok := range strings.FieldsFunc(x, func(r rune) bool {
				return r == ' ' || r == '\t' || r == '\n' || r == '"' || r == '\'' || r == '<' || r == '>' || r == ',' || r == '(' || r == ')'
			}) {
				tok = strings.Trim(tok, ".,;:!?()[]{}<>\"'")
				if isAddress(tok) {
					t.readTokens[tok] = true
				}
			}
		}
	}
	walk(normalize(result))
}

// IsAddress is exported for tests and tools.
func IsAddress(tok string) bool { return isAddress(tok) }
