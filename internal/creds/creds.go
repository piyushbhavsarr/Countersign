// Package creds holds operator-delegated credentials. The agent names a handle; the
// gateway injects the secret, and only for the hosts the handle is scoped to.
package creds

import (
	"fmt"
	"os"
	"path"

	"undolayer/internal/taint"
)

type Spec struct {
	Secret string   `toml:"secret" json:"secret"`
	Env    string   `toml:"env" json:"env"`
	Hosts  []string `toml:"hosts" json:"hosts"`
}

type Store map[string]Spec

func (s Store) secret(name string) string {
	c := s[name]
	if c.Secret != "" {
		return c.Secret
	}
	if c.Env != "" {
		return os.Getenv(c.Env)
	}
	return ""
}

func (s Store) Covers(name, host string) bool {
	c, ok := s[name]
	if !ok {
		return false
	}
	for _, h := range c.Hosts {
		if m, _ := path.Match(h, host); m {
			return true
		}
	}
	return false
}

func (s Store) Resolve(name, host string) (string, error) {
	if _, ok := s[name]; !ok {
		return "", fmt.Errorf("credential %q is not delegated to this agent", name)
	}
	if !s.Covers(name, host) {
		return "", fmt.Errorf("credential %q is not scoped to host %s", name, host)
	}
	sec := s.secret(name)
	if sec == "" {
		return "", fmt.Errorf("credential %q has no secret configured", name)
	}
	return sec, nil
}

func (s Store) Contribute(idx *taint.Index) {
	for name := range s {
		if v := s.secret(name); v != "" {
			idx.AddValue(v, "credential:"+name)
		}
	}
}
