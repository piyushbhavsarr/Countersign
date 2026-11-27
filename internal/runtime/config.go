// Package runtime builds a Manager from undolayer.toml.
//
//	state_dir = "~/.undolayer"
//	policy    = "policy.toml"              # extends (can only tighten) the default policy
//
//	[workspace]  root, exclude, sensitive, visibility ("public"/"private"), scanner,
//	             sandbox (default true), allow_network, read_allow, deny_read, timeout
//	[sql]        dsn (SQLite file), env, fraction_min_rows
//	[git]        protected, repo_subdir
//	[registry]   paths = ["registry/"]
//	[credentials.<name>] secret | env, hosts
//	[http]       allow_hosts, allowed_headers
//	[effects]    org_domains, slack_token_env, delays = { email = 30 }, outbox_file
//	[aws]        view_profile, read_profile, write_profile, sensitive_reads, bin
//	[agent]      allow_hosts (egress proxy allow-list), write (paths the agent may write)
//	[integrations.claude_code] deny, allow
package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"undolayer/internal/connectors/api"
	"undolayer/internal/connectors/cloud"
	"undolayer/internal/connectors/effects"
	gitc "undolayer/internal/connectors/git"
	"undolayer/internal/connectors/kube"
	"undolayer/internal/connectors/postgres"
	"undolayer/internal/connectors/sqlite"
	"undolayer/internal/connectors/workspace"
	"undolayer/internal/creds"
	"undolayer/internal/policy"
	"undolayer/internal/registry"
	"undolayer/internal/review"
	"undolayer/internal/risk"
	"undolayer/internal/store"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

type Config struct {
	StateDir  string `toml:"state_dir"`
	Policy    string `toml:"policy"`
	Workspace *struct {
		Root         string   `toml:"root"`
		Exclude      []string `toml:"exclude"`
		Sensitive    []string `toml:"sensitive"`
		Visibility   string   `toml:"visibility"`
		Scanner      *bool    `toml:"scanner"`
		Mask         *bool    `toml:"mask_sensitive"` // default true: secrets are not in the agent's shadow
		Sandbox      *bool    `toml:"sandbox"`
		AllowNetwork bool     `toml:"allow_network"`
		ReadAllow    []string `toml:"read_allow"`
		DenyRead     []string `toml:"deny_read"`
		ReadHosts    []string `toml:"read_hosts"` // hosts shell commands may read from (GET/HEAD/OPTIONS only)
		Timeout      int      `toml:"timeout"`
	} `toml:"workspace"`
	SQL *struct {
		DSN             string `toml:"dsn"`
		Env             string `toml:"env"`
		FractionMinRows int64  `toml:"fraction_min_rows"`
		// SQLite staging: "snapshot" (default: each task on its own copy, many agents at
		// once) or "lock" (on the real database, one task at a time, no copy).
		Staging string `toml:"staging"`
	} `toml:"sql"`
	Git *struct {
		Protected  []string `toml:"protected"`
		RepoSubdir string   `toml:"repo_subdir"`
	} `toml:"git"`
	Registry struct {
		Paths []string `toml:"paths"`
	} `toml:"registry"`
	Credentials map[string]creds.Spec `toml:"credentials"`
	HTTP        struct {
		AllowHosts []string `toml:"allow_hosts"`
		// AllowPrivateHosts: hosts (globs) http.request may reach on loopback or private
		// networks. Cloud metadata services are refused regardless.
		AllowPrivateHosts []string `toml:"allow_private_hosts"`
		AllowedHeaders    []string `toml:"allowed_headers"`
	} `toml:"http"`
	Effects struct {
		OrgDomains    []string           `toml:"org_domains"`
		SlackTokenEnv string             `toml:"slack_token_env"`
		Delays        map[string]float64 `toml:"delays"`
		OutboxFile    string             `toml:"outbox_file"`
		WebhookHosts  []string           `toml:"webhook_hosts"`
	} `toml:"effects"`
	AWS struct {
		Bin            string   `toml:"bin"`
		ViewProfile    string   `toml:"view_profile"`
		ReadProfile    string   `toml:"read_profile"`
		WriteProfile   string   `toml:"write_profile"`
		SensitiveReads []string `toml:"sensitive_reads"`
		// how long a resource create/update/delete may take before it is reported as stuck
		ResourceTimeout string `toml:"resource_timeout"`
	} `toml:"aws"`
	Kubernetes struct {
		Context     string `toml:"context"`     // kubeconfig context; the connector is enabled when set
		Kubeconfig  string `toml:"kubeconfig"`  // default: kubectl's own ($KUBECONFIG, ~/.kube/config)
		Kubectl     string `toml:"kubectl"`     // default: kubectl on PATH
		Namespace   string `toml:"namespace"`   // default namespace for objects that name none
		Environment string `toml:"environment"` // e.g. "production": reported to policy as env
	} `toml:"kubernetes"`
	Agent struct {
		AllowHosts []string `toml:"allow_hosts"` // egress proxy allow-list (e.g. the model API)
		Write      []string `toml:"write"`       // paths the agent may write (its own config, caches)
		Read       []string `toml:"read"`        // paths under $HOME the agent may read
		// TempEnv: environment variables that, like TMPDIR, are pointed at the agent's own
		// private temp directory (agents that pick their scratch place from another
		// variable, e.g. CLAUDE_CODE_TMPDIR for Claude Code).
		TempEnv []string `toml:"temp_env"`
	} `toml:"agent"`
	Approvals struct {
		Wait              string   `toml:"wait"`                // e.g. "5m": tool calls wait this long for a reviewer's decision
		AllowSelfApproval bool     `toml:"allow_self_approval"` // the requester may approve their own task
		NotifyCommand     []string `toml:"notify_command"`      // run per request, the request as JSON on stdin
		NotifyURL         string   `toml:"notify_url"`          // POSTed the request as JSON (has a "text" field)
		Requester         string   `toml:"requester"`           // who asks for tasks (default: the OS user)
	} `toml:"approvals"`
	// [reviewers.<name>] key = "ssh-ed25519 AAAA... alice", roles = [...], users = [...]
	// Risk: a model trained with `undolayer risk train` scores every action (the fact
	// risk_score, 0 to 1); policy rules decide what a score means.
	Risk struct {
		Model string `toml:"model"`
	} `toml:"risk"`
	// Vault: where each change's before state is kept, written before the change runs.
	// replicas are directories, ideally on independent disks or volumes; a change runs only
	// once write_quorum of them (default: a majority) have its before state on disk.
	// Default: one replica in state_dir/vault.
	// Content is sealed with AES-256-GCM under keys in key_file (default state_dir/vault.keys),
	// kept apart from the replicas: shredding a key makes what it sealed unreadable on every
	// replica. encrypt = false stores it in the clear. require_independent_replicas refuses
	// replicas on the same device.
	Vault struct {
		Replicas           []string `toml:"replicas"`
		WriteQuorum        int      `toml:"write_quorum"`
		Disabled           bool     `toml:"disabled"`
		Encrypt            *bool    `toml:"encrypt"`
		KeyFile            string   `toml:"key_file"`
		RequireIndependent bool     `toml:"require_independent_replicas"`
	} `toml:"vault"`
	Reviewers map[string]map[string]any `toml:"reviewers"`
	// [[approval_rule]] id, connector, operation, effect, when, roles, count, reason
	ApprovalRules []map[string]any `toml:"approval_rule"`
	Integrations  struct {
		ClaudeCode map[string][]string `toml:"claude_code"`
	} `toml:"integrations"`

	// StateStore: where transaction state lives. Empty: files in state_dir (one machine).
	// A postgres:// DSN: shared by every gateway using it (several machines, HA through
	// PostgreSQL's own replication and failover).
	StateStore string `toml:"state_store"`
	// Node names this gateway (default: the host name).
	Node string `toml:"node"`

	Base string `toml:"-"`
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		h, _ := os.UserHomeDir()
		return filepath.Join(h, strings.TrimPrefix(p, "~"))
	}
	return p
}

func (c *Config) Abs(p string) string {
	p = expand(p)
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Base, p)
}

func LoadConfig(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if _, err := toml.DecodeFile(abs, &c); err != nil {
		return nil, err
	}
	c.Base = filepath.Dir(abs)
	if c.StateDir == "" {
		c.StateDir = "~/.undolayer"
	}
	c.StateDir = c.Abs(c.StateDir)
	return &c, nil
}

// Build creates the manager and registers every configured connector.
func Build(c *Config) (*tx.Manager, *workspace.FS, error) {
	pol := policy.Default()
	if c.Policy != "" {
		p, err := policy.Load(c.Abs(c.Policy))
		if err != nil {
			return nil, nil, err
		}
		pol = pol.Extend(p)
	}
	if c.Risk.Model != "" {
		rm, err := risk.Load(c.Abs(c.Risk.Model))
		if err != nil {
			return nil, nil, fmt.Errorf("[risk] model: %v", err)
		}
		pol.Risk = rm
	}
	var m *tx.Manager
	var err error
	if c.StateStore != "" {
		if !strings.HasPrefix(c.StateStore, "postgres://") && !strings.HasPrefix(c.StateStore, "postgresql://") {
			return nil, nil, fmt.Errorf("state_store must be a postgres:// DSN (or empty for files in state_dir)")
		}
		st, err := store.OpenPostgres(c.StateStore)
		if err != nil {
			return nil, nil, err
		}
		m, err = tx.NewManagerWithStore(st, c.StateDir, pol)
		if err != nil {
			return nil, nil, err
		}
	} else if m, err = tx.NewManager(c.StateDir, pol); err != nil {
		return nil, nil, err
	}
	if c.Node != "" {
		m.Node = c.Node
	}
	if !c.Vault.Disabled {
		reps := []string{}
		for _, r := range c.Vault.Replicas {
			reps = append(reps, c.Abs(r))
		}
		if len(reps) == 0 {
			reps = []string{filepath.Join(c.StateDir, "vault")}
		}
		var keys *vault.Keyring
		if c.Vault.Encrypt == nil || *c.Vault.Encrypt {
			kf := filepath.Join(c.StateDir, "vault.keys")
			if c.Vault.KeyFile != "" {
				kf = c.Abs(c.Vault.KeyFile)
			}
			for _, r := range reps {
				if rel, err := filepath.Rel(r, kf); err == nil && !strings.HasPrefix(rel, "..") {
					return nil, nil, fmt.Errorf("[vault] key_file must not be inside a replica (%s): shredding a key would not reach copies of the replica", r)
				}
			}
			var err error
			if keys, err = vault.OpenKeyring(kf); err != nil {
				return nil, nil, fmt.Errorf("[vault] key_file: %w", err)
			}
		}
		v, err := vault.Open(vault.Options{Replicas: reps, WriteQuorum: c.Vault.WriteQuorum, Keys: keys,
			RequireIndependent: c.Vault.RequireIndependent, LockPath: filepath.Join(c.StateDir, "vault.lock")})
		if err != nil {
			return nil, nil, fmt.Errorf("[vault]: %w", err)
		}
		m.Vault = v
	}
	if c.Approvals.Wait != "" {
		d, err := time.ParseDuration(c.Approvals.Wait)
		if err != nil {
			return nil, nil, fmt.Errorf("[approvals] wait: %w", err)
		}
		m.ApprovalWait = d
	}
	if len(c.Reviewers) > 0 {
		rc, err := review.FromMap(c.Reviewers, c.ApprovalRules, c.Approvals.AllowSelfApproval)
		if err != nil {
			return nil, nil, fmt.Errorf("[reviewers]: %w", err)
		}
		m.Review = rc
	} else if len(c.ApprovalRules) > 0 {
		return nil, nil, errors.New("[[approval_rule]] needs [reviewers] to approve under it")
	}
	m.Requester = c.Approvals.Requester
	if m.Requester == "" {
		if u, err := user.Current(); err == nil {
			m.Requester = u.Username
		}
	}
	m.Notify = notifier(c.Approvals.NotifyCommand, c.Approvals.NotifyURL)
	store := creds.Store(c.Credentials)
	var fs *workspace.FS
	if w := c.Workspace; w != nil {
		root := w.Root
		if root == "" {
			root = "."
		}
		fs = workspace.NewFS(c.Abs(root), c.StateDir)
		fs.Exclude, fs.Sensitive, fs.Visibility = w.Exclude, w.Sensitive, w.Visibility
		if w.Scanner != nil {
			fs.Scanner = *w.Scanner
		}
		if w.Mask != nil {
			fs.MaskSensitive = *w.Mask
		}
		m.Register(fs)
		useSandbox := w.Sandbox == nil || *w.Sandbox
		sh, err := workspace.NewShell(fs, useSandbox)
		if err != nil {
			return nil, nil, err
		}
		sh.AllowNetwork, sh.ReadAllow, sh.DenyRead, sh.AllowHosts = w.AllowNetwork, w.ReadAllow, w.DenyRead, w.ReadHosts
		if c.SQL != nil && !strings.Contains(c.SQL.DSN, "://") {
			sh.DenyRead = append(sh.DenyRead, c.Abs(c.SQL.DSN)) // the database is reached through the gateway only
		}
		if w.Timeout > 0 {
			sh.Timeout = time.Duration(w.Timeout) * time.Second
		}
		m.Register(sh)
		if c.Git != nil {
			g := gitc.New(fs, c.StateDir)
			if len(c.Git.Protected) > 0 {
				g.Protected = c.Git.Protected
			}
			if c.Git.RepoSubdir != "" {
				g.RepoSub = c.Git.RepoSubdir
			}
			m.Register(g)
		}
	}
	if s := c.SQL; s != nil {
		if strings.HasPrefix(s.DSN, "postgres://") || strings.HasPrefix(s.DSN, "postgresql://") {
			pc := postgres.New(s.DSN)
			if s.Env != "" {
				pc.Env = s.Env
			}
			if s.FractionMinRows > 0 {
				pc.FractionMinRows = s.FractionMinRows
			}
			m.Register(pc)
			goto registry
		}
		sc := sqlite.New(c.Abs(s.DSN))
		switch s.Staging {
		case "", "snapshot", "lock":
			sc.Staging = s.Staging
		default:
			return nil, nil, fmt.Errorf("[sql] staging must be \"snapshot\" or \"lock\", not %q", s.Staging)
		}
		sc.SnapshotDir = filepath.Join(c.StateDir, "sqlite")
		if s.Env != "" {
			sc.Env = s.Env
		}
		if s.FractionMinRows > 0 {
			sc.FractionMinRows = s.FractionMinRows
		}
		m.Register(sc)
	}
registry:
	for _, p := range c.Registry.Paths {
		tools, err := registry.LoadDir(c.Abs(p))
		if err != nil {
			return nil, nil, err
		}
		for _, t := range tools {
			m.Register(api.New(t, store, nil))
		}
	}
	ef := effects.NewEffect()
	ef.OrgDomains = c.Effects.OrgDomains
	ef.WebhookHosts = c.Effects.WebhookHosts
	if c.Effects.Delays != nil {
		ef.Delays = c.Effects.Delays
	}
	if c.Effects.SlackTokenEnv != "" {
		ef.Audience = effects.SlackAudience(c.Effects.SlackTokenEnv, nil)
	}
	if c.Effects.OutboxFile != "" {
		ef.OutboxFile = c.Abs(c.Effects.OutboxFile)
	}
	m.Register(ef)
	h := effects.NewHTTP(store, nil)
	h.AllowHosts, h.AllowPrivateHosts = c.HTTP.AllowHosts, c.HTTP.AllowPrivateHosts
	if len(c.HTTP.AllowedHeaders) > 0 {
		h.AllowedHeaders = c.HTTP.AllowedHeaders
	}
	m.Register(h)
	cl := cloud.New(c.StateDir)
	cl.Shared = m.Store
	if fs != nil {
		cl.WorkspaceRoot = fs.Root
	}
	cl.ViewProfile, cl.ReadProfile, cl.WriteProfile = c.AWS.ViewProfile, c.AWS.ReadProfile, c.AWS.WriteProfile
	if c.AWS.Bin != "" {
		cl.AWSBin = c.AWS.Bin
	}
	if len(c.AWS.SensitiveReads) > 0 {
		cl.SensitiveReads = append(append([]string{}, cloud.DefaultSensitiveReads...), c.AWS.SensitiveReads...)
	}
	if c.AWS.ReadProfile != "" {
		to := 30 * time.Minute
		if c.AWS.ResourceTimeout != "" {
			d, err := time.ParseDuration(c.AWS.ResourceTimeout)
			if err != nil {
				return nil, nil, fmt.Errorf("[aws] resource_timeout: %w", err)
			}
			to = d
		}
		cl.EnableResources(to)
	}
	m.Register(cl)
	if k := c.Kubernetes; k.Context != "" {
		kc := kube.New()
		kc.Context, kc.Environment = k.Context, k.Environment
		if k.Kubeconfig != "" {
			kc.Kubeconfig = c.Abs(k.Kubeconfig)
		}
		if k.Kubectl != "" {
			kc.Kubectl = k.Kubectl
		}
		if k.Namespace != "" {
			kc.Namespace = k.Namespace
		}
		m.Register(kc)
	}
	return m, fs, nil
}
