// Package config is the bouncer policy object and the optional folder layout
// used to load it.
//
// The object layer is Config after Init. Callers can fill it from any source
// (agentcon YAML, a database) and pass it to serve.
//
// The folder layer is one directory with config.yaml plus a ts/ tree.
// LoadDir reads that layout. WriteLayout writes it. Agentcon materializes
// that layout from its own multi-dir config. A small CLI can LoadDir
// without knowing about agentcon.
package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultListen    = "127.0.0.1:8228"
	DefaultSSHListen = "127.0.0.1:8229"
)

// Actions a rule (or a service default) can take.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
	ActionAsk   = "ask"
)

// Unmatched-traffic modes for a profile.
const (
	UnmatchedTunnel = "tunnel"
	UnmatchedDeny   = "deny"
)

// SSH capability kinds.
const (
	SSHKindGit     = "git"
	SSHKindExec    = "exec"
	SSHKindShell   = "shell"
	SSHKindSFTP    = "sftp"
	SSHKindForward = "forward"
	// SSHKindSubsystem is a subsystem other than sftp. It is never allowed.
	SSHKindSubsystem = "subsystem"
)

// Credential slot names. A credential is a composite of these sources.
const (
	SlotUsername    = "username"
	SlotPassword    = "password"
	SlotToken       = "token"
	SlotPrivateKey  = "private_key"
	SlotCertificate = "certificate"
)

type Config struct {
	Listen    string `yaml:"listen"`
	SSHListen string `yaml:"ssh_listen"`
	// DefaultProfile is used when a session is created with no profile name.
	DefaultProfile string `yaml:"default_profile"`
	// AnonymousProfile, if set, applies to proxy clients that don't present a
	// session token. Empty means such clients are rejected.
	AnonymousProfile string                 `yaml:"anonymous_profile"`
	Prompts          Prompts                `yaml:"prompts"`
	Credentials      map[string]*Credential `yaml:"credentials"`
	Profiles         map[string]*Profile    `yaml:"profiles"`

	// Dir is the directory containing the config file; relative paths resolve against it.
	Dir string `yaml:"-"`
	// Path is the config file that was loaded.
	Path string `yaml:"-"`
}

// Prompts configure how the bouncer asks a human: filter approvals and
// values such as a Bitwarden master password.
type Prompts struct {
	// Timeout after which an unanswered prompt expires. An expired approval
	// is a deny. Default 2m.
	Timeout Duration `yaml:"timeout"`
	// Notify sends a desktop notification when a prompt is pending. Default true.
	Notify *bool `yaml:"notify"`
	// Terminal prompts on the `bouncer serve` terminal when it is interactive. Default true.
	Terminal *bool `yaml:"terminal"`
	// CLI allows answering through the control API, as `agentcon run` and
	// `bouncer answer`/`approve`/`deny`/`decline` do. Default true.
	CLI *bool `yaml:"cli"`
}

func (a Prompts) NotifyEnabled() bool   { return a.Notify == nil || *a.Notify }
func (a Prompts) TerminalEnabled() bool { return a.Terminal == nil || *a.Terminal }
func (a Prompts) CLIEnabled() bool      { return a.CLI == nil || *a.CLI }
func (a Prompts) TimeoutOrDefault() time.Duration {
	if a.Timeout.D <= 0 {
		return 2 * time.Minute
	}
	return a.Timeout.D
}

// Credential is a composite of named slots. The agent never sees slot
// values; it only sees the placeholder.
type Credential struct {
	Username    *ValueSource `yaml:"username"`
	Password    *ValueSource `yaml:"password"`
	Token       *ValueSource `yaml:"token"`
	PrivateKey  *ValueSource `yaml:"private_key"`
	Certificate *ValueSource `yaml:"certificate"`
	// Cache controls how long a fetched slot is kept in memory. Default 5m; 0s disables.
	Cache *Duration `yaml:"cache"`
	// ExportEnv lists environment variables set on the agent to this
	// credential's placeholder so agent tooling believes it has a token.
	ExportEnv []string `yaml:"export_env"`

	Name string `yaml:"-"`
}

// ValueSource locates one string. Fetch the source payload, then if Path is
// set, take that JSONPath (must be exactly one string).
type ValueSource struct {
	// Source is one of: keyring, command, env, file, ssh-agent, bitwarden, provided.
	Source string `yaml:"source"`
	// Path is a JSONPath evaluated against the source payload.
	// Empty means the payload is the value. Bitwarden payloads are the
	// decrypted cipher JSON, so Path is required there.
	Path string `yaml:"path"`
	// Command (source: command) is an argv run to fetch the secret.
	// Stdout, minus trailing newlines, is the payload.
	// agentcon run evaluates this on the host and PUTs the value.
	Command []string `yaml:"command"`
	// Env (source: env) names an environment variable.
	// The daemon reads it from an overlay set by PUT /_bouncer/credentials/sources/env, then from os.LookupEnv.
	Env string `yaml:"env"`
	// File (source: file) is a file containing the payload (e.g. an SSH private key).
	// agentcon run reads this path on the host and PUTs the value.
	File string `yaml:"file"`
	// Account (source: keyring) overrides the keyring account name (default: credential name).
	// agentcon run reads the host keyring and PUTs the value.
	Account string `yaml:"account"`
	// Fingerprint (source: ssh-agent) selects a key from the agent by SHA256 fingerprint.
	// agentcon run bind-mounts SSH_AUTH_SOCK into the sidecar.
	Fingerprint string `yaml:"fingerprint"`
	// Email, Server, Item, Folder, PasswordEnv (source: bitwarden) select
	// an item. The vault is synced and unlocked once per email and server.
	Email       string `yaml:"email"`
	Server      string `yaml:"server"`
	Item        string `yaml:"item"`
	Folder      string `yaml:"folder"`
	PasswordEnv string `yaml:"password_env"`
}

// Slot is one named ValueSource on a credential.
type Slot struct {
	Name   string
	Source *ValueSource
}

// Placeholder is the stand-in value the agent uses in place of the secret.
func (c *Credential) Placeholder() string { return Placeholder(c.Name) }

// Placeholder is the stand-in value for the named credential.
func Placeholder(name string) string { return "bouncer-placeholder-" + name }

func (c *Credential) CacheTTL() time.Duration {
	if c.Cache == nil {
		return 5 * time.Minute
	}
	return c.Cache.D
}

// Slots returns the configured sources in a stable order.
func (c *Credential) Slots() []Slot {
	if c == nil {
		return nil
	}
	var out []Slot
	if c.Username != nil {
		out = append(out, Slot{Name: SlotUsername, Source: c.Username})
	}
	if c.Password != nil {
		out = append(out, Slot{Name: SlotPassword, Source: c.Password})
	}
	if c.Token != nil {
		out = append(out, Slot{Name: SlotToken, Source: c.Token})
	}
	if c.PrivateKey != nil {
		out = append(out, Slot{Name: SlotPrivateKey, Source: c.PrivateKey})
	}
	if c.Certificate != nil {
		out = append(out, Slot{Name: SlotCertificate, Source: c.Certificate})
	}
	return out
}

// Slot returns the named source, or nil.
func (c *Credential) Slot(name string) *ValueSource {
	for _, s := range c.Slots() {
		if s.Name == name {
			return s.Source
		}
	}
	return nil
}

// ProvidedKey is the PUT / provided-map key for a credential slot.
func ProvidedKey(cred, slot string) string {
	return cred + "." + slot
}

type Profile struct {
	// Extends names a parent profile whose filters, http, and ssh are inherited.
	Extends string `yaml:"extends"`
	// Unmatched controls HTTPS traffic to hosts with no http entry: tunnel (default) or deny.
	Unmatched string `yaml:"unmatched"`
	// Tunnel lists hosts passed through uninspected even when unmatched is
	// deny (e.g. the agent's own LLM API).
	Tunnel []string `yaml:"tunnel"`
	// AllowPrivate lets tunneled (unmatched) traffic reach loopback, private,
	// link-local, CGNAT and other reserved addresses. Off by default: otherwise the proxy
	// would be a way out of the network sandbox it's meant to enforce.
	// Configured http and ssh entries are not affected.
	AllowPrivate *bool `yaml:"allow_private"`
	// Filters run on every intercepted request in this profile, before
	// http/ssh filters and before rules.
	Filters []FilterRef   `yaml:"filters"`
	HTTP    []*Service    `yaml:"http"`
	SSH     []*SSHService `yaml:"ssh"`

	Name string `yaml:"-"`
}

// Service is an upstream HTTP(S) API the bouncer intercepts.
type Service struct {
	Name  string   `yaml:"name"`
	Hosts []string `yaml:"hosts"`
	// Credential to inject (optional; a service with no credential is still filtered).
	Credential string `yaml:"credential"`
	// AllowUpgrade permits protocol upgrades (WebSockets) on a credentialed
	// service. After the upgrade, traffic is a raw stream that filters never
	// see, authenticated by the injected credential.
	AllowUpgrade bool `yaml:"allow_upgrade"`
	// Insecure allows injecting the credential into plain-HTTP requests.
	// Only for local development; never set it for a remote host.
	Insecure bool    `yaml:"insecure"`
	Inject   *Inject `yaml:"inject"`
	// Default action when no rule matches. If omitted: allow when there are
	// no rules. When rules exist, the profile unmatched mode decides:
	// deny refuses leftover paths, tunnel forwards them without the credential.
	// An explicit default: allow still attaches the credential.
	Default string `yaml:"default"`
	Rules   []Rule `yaml:"rules"`
	// Filters run on every request to this service, before rules.
	// Attach a filter to a rule instead when it should run only on that match.
	Filters []FilterRef `yaml:"filters"`
}

func (s *Service) DefaultAction() string {
	if s.Default != "" {
		return s.Default
	}
	if len(s.Rules) > 0 {
		return ActionDeny
	}
	return ActionAllow
}

// Inject describes how the credential is attached to upstream requests.
// Bouncer always replaces the credential's placeholder where it appears in
// Authorization (including inside Basic), Private-Token, the inject header,
// and any placeholder_headers; then it applies the inject spec, if any.
type Inject struct {
	// Header and Value set a header; "{{secret}}" in Value is replaced. Value defaults to "{{secret}}".
	Header string `yaml:"header"`
	Value  string `yaml:"value"`
	// Bearer sets "Authorization: Bearer <secret>".
	Bearer bool `yaml:"bearer"`
	// Basic sets HTTP Basic auth with the secret as password.
	Basic *BasicInject `yaml:"basic"`
	// Query sets a query parameter to the secret, for APIs that require it.
	Query string `yaml:"query"`
	// PlaceholderHeaders adds headers (beyond Authorization, Private-Token and
	// Header) in which the agent's placeholder is replaced with the secret.
	PlaceholderHeaders []string `yaml:"placeholder_headers"`
	// Git overrides injection for git smart-HTTP requests, which usually
	// need Basic auth even where the API takes a token header.
	Git *Inject `yaml:"git"`
}

// For returns the inject spec that applies to a request.
func (i *Inject) For(isGit bool) *Inject {
	if i != nil && isGit && i.Git != nil {
		return i.Git
	}
	return i
}

type BasicInject struct {
	Username string `yaml:"username"`
}

// SSHService is an upstream SSH host the bouncer terminates and re-originates.
type SSHService struct {
	Name  string   `yaml:"name"`
	Hosts []string `yaml:"hosts"`
	// User, if set, restricts (and defaults) the upstream username.
	User string `yaml:"user"`
	Port int    `yaml:"port"`
	// Credential must have a private_key slot (a secret, or source: ssh-agent).
	Credential string `yaml:"credential"`
	// Allow lists permitted capabilities: git, exec, shell, sftp, forward. Default [git].
	Allow []string `yaml:"allow"`
	// KnownHosts files used to verify the upstream host key. Default ~/.ssh/known_hosts.
	KnownHosts []string `yaml:"known_hosts"`
	// Env lists environment variables the agent may set on the upstream
	// session (a trailing * matches a prefix). Default: GIT_PROTOCOL, LANG, LC_*.
	Env []string `yaml:"env"`
	// HostKey optionally pins the upstream host key (authorized_keys format).
	HostKey string `yaml:"host_key"`
	Default string `yaml:"default"`
	Rules   []Rule `yaml:"rules"`
	// Filters run on every request to this SSH service, before rules.
	Filters []FilterRef `yaml:"filters"`
}

func (s *SSHService) DefaultAction() string {
	if s.Default != "" {
		return s.Default
	}
	if len(s.Rules) > 0 {
		return ActionDeny
	}
	return ActionAllow
}

// EnvAllowed reports whether the agent may set an environment variable.
func (s *SSHService) EnvAllowed(name string) bool {
	allow := s.Env
	if allow == nil {
		allow = []string{"GIT_PROTOCOL", "LANG", "LC_*"}
	}
	for _, a := range allow {
		if a == name || (strings.HasSuffix(a, "*") && strings.HasPrefix(name, a[:len(a)-1])) {
			return true
		}
	}
	return false
}

func (s *SSHService) Allows(kind string) bool {
	allow := s.Allow
	if len(allow) == 0 {
		allow = []string{SSHKindGit}
	}
	for _, a := range allow {
		if a == kind {
			return true
		}
	}
	return false
}

// Rule is a declarative policy rule. All present matchers must match; the
// first matching rule decides.
type Rule struct {
	Action string `yaml:"action"`
	Reason string `yaml:"reason"`
	// Prompt is shown for action: ask. Defaults to a description of the request.
	Prompt string `yaml:"prompt"`

	Methods   []string `yaml:"methods"`
	Path      string   `yaml:"path"`       // glob over the decoded path; * = one segment, ** = any
	PathRegex string   `yaml:"path_regex"` // regex over the decoded path

	GitLabProject *ProjectRef `yaml:"gitlab_project"`
	// GitHubRepo is owner/repo names. Always a YAML list, even for one repo.
	GitHubRepo []string `yaml:"github_repo"`
	// GitHubSubpaths are globs relative to /repos/owner/repo/ ("" is the
	// repo itself). Git requests never match a rule with subpaths.
	GitHubSubpaths []string     `yaml:"github_subpaths"`
	Git            *GitMatch    `yaml:"git"`
	GraphQL        *GraphQLRule `yaml:"graphql"`
	SSH            *SSHMatch    `yaml:"ssh"`

	// Filters run after this rule matches with allow, or an approved ask.
	// They are not run on deny, on other rules, or on the service default.
	// Same path with a different config is a different instance.
	Filters []FilterRef `yaml:"filters"`

	PathRegexp *regexp.Regexp `yaml:"-"`
}

// ProjectRef identifies a GitLab project by path and optionally numeric ID.
// It accepts a scalar ("group/project") or a mapping ({path, id, subpaths}).
type ProjectRef struct {
	Path string `yaml:"path"`
	ID   int64  `yaml:"id"`
	// Subpaths restricts the match to REST API endpoints under the project,
	// as globs relative to /api/v4/projects/:id/ ("" is the project itself,
	// "variables/**" its CI variables). Git requests never match a rule
	// with subpaths.
	Subpaths []string `yaml:"subpaths"`
}

func (p *ProjectRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		p.Path = n.Value
		return nil
	}
	type plain ProjectRef
	err := n.Decode((*plain)(p))
	if err != nil {
		return fmt.Errorf("decode project ref: %w", err)
	}
	return nil
}

type GitMatch struct {
	// Service is receive-pack (push), upload-pack (fetch), or upload-archive.
	Service string `yaml:"service"`
	// Refs are globs (refs/heads/main, refs/heads/release/*) matched against pushed refs.
	Refs []string `yaml:"refs"`
	// Updates restricts to update kinds: create, update, delete.
	Updates []string `yaml:"updates"`
}

type GraphQLRule struct {
	// Operations restricts to operation types: query, mutation, subscription.
	Operations []string `yaml:"operations"`
	// Fields matches top-level fields (after expanding fragments).
	Fields []string `yaml:"fields"`
}

type SSHMatch struct {
	Kinds   []string `yaml:"kinds"`
	Command string   `yaml:"command"` // regex over the exec command

	CommandRegexp *regexp.Regexp `yaml:"-"`
}

// FilterRef points at a TypeScript/JavaScript filter. It accepts a scalar
// path or a mapping with per-filter config.
type FilterRef struct {
	Path    string         `yaml:"path"`
	Config  map[string]any `yaml:"config"`
	Timeout Duration       `yaml:"timeout"`
}

func (f *FilterRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		f.Path = n.Value
		return nil
	}
	type plain FilterRef
	err := n.Decode((*plain)(f))
	if err != nil {
		return fmt.Errorf("decode filter ref: %w", err)
	}
	return nil
}

// Duration is a time.Duration that unmarshals from strings like "5m".
type Duration struct{ D time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q: %w", n.Line, n.Value, err)
	}
	d.D = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.D.String(), nil }

// Init fills derived fields and validates a service config.
func (c *Config) Init() error {
	return c.normalize()
}

// Load reads a standalone policy file into a service config.
// Agentcon YAML goes through pkg/config, which unmarshals into these types.
func Load(path string) (*Config, error) {
	//nolint:gosec // policy path is supplied by the caller
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data, path)
}

// Decode unmarshals policy YAML without resolving paths or filling defaults.
func Decode(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(&c)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return &c, nil
}

// Parse parses config YAML. path is used to resolve relative filter paths.
func Parse(data []byte, path string) (*Config, error) {
	c, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	c.Path = path
	c.Dir = filepath.Dir(path)
	err = c.Init()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c *Config) normalize() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.SSHListen == "" {
		c.SSHListen = DefaultSSHListen
	}
	if c.Credentials == nil {
		c.Credentials = map[string]*Credential{}
	}
	if c.Profiles == nil {
		c.Profiles = map[string]*Profile{}
	}
	for name, cr := range c.Credentials {
		if cr == nil {
			return fmt.Errorf("credential %q: empty", name)
		}
		cr.Name = name
		slots := cr.Slots()
		if len(slots) == 0 {
			return fmt.Errorf("credential %q: need username, password, token, private_key, or certificate", name)
		}
		for _, slot := range slots {
			err := slot.Source.init(name, slot.Name, c.Dir)
			if err != nil {
				return err
			}
		}
	}
	for name, p := range c.Profiles {
		if p == nil {
			p = &Profile{}
			c.Profiles[name] = p
		}
		p.Name = name
		if p.Extends != "" {
			if _, ok := c.Profiles[p.Extends]; !ok {
				return fmt.Errorf("profile %q extends unknown profile %q", name, p.Extends)
			}
		}
	}
	// Detect extends cycles before resolving.
	for name := range c.Profiles {
		seen := map[string]bool{}
		for cur := name; cur != ""; cur = c.Profiles[cur].Extends {
			if seen[cur] {
				return fmt.Errorf("profile %q: extends cycle", name)
			}
			seen[cur] = true
		}
	}
	for name, p := range c.Profiles {
		if err := c.validateProfile(p); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
	}
	if c.DefaultProfile != "" {
		if _, ok := c.Profiles[c.DefaultProfile]; !ok {
			return fmt.Errorf("default_profile %q does not exist", c.DefaultProfile)
		}
	}
	if c.AnonymousProfile != "" {
		if _, ok := c.Profiles[c.AnonymousProfile]; !ok {
			return fmt.Errorf("anonymous_profile %q does not exist", c.AnonymousProfile)
		}
		// Tokenless access is only tolerable when only this machine can connect.
		if !loopback(c.Listen) {
			return fmt.Errorf("anonymous_profile requires a loopback listen address, got %q: anyone who can reach the proxy would get that profile's credentials", c.Listen)
		}
	}
	return nil
}

func (c *Config) validateProfile(p *Profile) error {
	switch p.Unmatched {
	case "", UnmatchedTunnel, UnmatchedDeny:
	default:
		return fmt.Errorf("unmatched must be tunnel or deny, got %q", p.Unmatched)
	}
	if err := c.normalizeFilters(p.Filters); err != nil {
		return err
	}
	for i, h := range p.Tunnel {
		p.Tunnel[i] = strings.ToLower(h)
	}
	for i, s := range p.HTTP {
		if s == nil {
			return fmt.Errorf("http[%d]: empty", i)
		}
		if s.Name == "" {
			return fmt.Errorf("http[%d]: name is required", i)
		}
		if len(s.Hosts) == 0 {
			return fmt.Errorf("http %q: hosts is required", s.Name)
		}
		for j, h := range s.Hosts {
			s.Hosts[j] = strings.ToLower(h)
		}
		if s.Credential != "" {
			if _, ok := c.Credentials[s.Credential]; !ok {
				return fmt.Errorf("http %q: unknown credential %q", s.Name, s.Credential)
			}
		}
		if s.Inject != nil && s.Credential == "" {
			return fmt.Errorf("http %q: inject requires credential", s.Name)
		}
		if err := validateAction(s.Default, true); err != nil {
			return fmt.Errorf("http %q default: %w", s.Name, err)
		}
		if err := normalizeRules(s.Rules); err != nil {
			return fmt.Errorf("http %q: %w", s.Name, err)
		}
		if err := c.normalizeFilters(s.Filters); err != nil {
			return fmt.Errorf("http %q: %w", s.Name, err)
		}
		if err := c.normalizeRuleFilters(s.Rules); err != nil {
			return fmt.Errorf("http %q: %w", s.Name, err)
		}
	}
	for i, s := range p.SSH {
		if s == nil {
			return fmt.Errorf("ssh[%d]: empty", i)
		}
		if s.Name == "" {
			return fmt.Errorf("ssh[%d]: name is required", i)
		}
		if len(s.Hosts) == 0 {
			return fmt.Errorf("ssh %q: hosts is required", s.Name)
		}
		for j, h := range s.Hosts {
			s.Hosts[j] = strings.ToLower(h)
		}
		if s.Credential == "" {
			return fmt.Errorf("ssh %q: credential is required", s.Name)
		}
		if _, ok := c.Credentials[s.Credential]; !ok {
			return fmt.Errorf("ssh %q: unknown credential %q", s.Name, s.Credential)
		}
		for _, k := range s.Allow {
			switch k {
			case SSHKindGit, SSHKindExec, SSHKindShell, SSHKindSFTP, SSHKindForward:
			default:
				return fmt.Errorf("ssh %q: unknown allow kind %q", s.Name, k)
			}
		}
		for j, kh := range s.KnownHosts {
			s.KnownHosts[j] = expandPath(kh, c.Dir)
		}
		if err := validateAction(s.Default, true); err != nil {
			return fmt.Errorf("ssh %q default: %w", s.Name, err)
		}
		if err := normalizeRules(s.Rules); err != nil {
			return fmt.Errorf("ssh %q: %w", s.Name, err)
		}
		if err := c.normalizeFilters(s.Filters); err != nil {
			return fmt.Errorf("ssh %q: %w", s.Name, err)
		}
		if err := c.normalizeRuleFilters(s.Rules); err != nil {
			return fmt.Errorf("ssh %q: %w", s.Name, err)
		}
	}
	return nil
}

func (c *Config) normalizeFilters(fs []FilterRef) error {
	for i := range fs {
		if fs[i].Path == "" {
			return fmt.Errorf("filters[%d]: path is required", i)
		}
		fs[i].Path = expandPath(fs[i].Path, c.Dir)
	}
	return nil
}

func (c *Config) normalizeRuleFilters(rules []Rule) error {
	for i := range rules {
		err := c.normalizeFilters(rules[i].Filters)
		if err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

func validateAction(a string, allowEmpty bool) error {
	switch a {
	case ActionAllow, ActionDeny, ActionAsk:
		return nil
	case "":
		if allowEmpty {
			return nil
		}
	}
	return fmt.Errorf("action must be allow, deny or ask, got %q", a)
}

func normalizeRules(rules []Rule) error {
	for i := range rules {
		r := &rules[i]
		if err := validateAction(r.Action, false); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
		if r.Action == ActionDeny && len(r.Filters) > 0 {
			return fmt.Errorf("rules[%d]: filters are not run on action deny", i)
		}
		for j, m := range r.Methods {
			r.Methods[j] = strings.ToUpper(m)
		}
		if r.PathRegex != "" {
			re, err := regexp.Compile(r.PathRegex)
			if err != nil {
				return fmt.Errorf("rules[%d]: path_regex: %w", i, err)
			}
			r.PathRegexp = re
		}
		if r.GitLabProject != nil {
			r.GitLabProject.Path = strings.Trim(strings.ToLower(r.GitLabProject.Path), "/")
			if r.GitLabProject.Path == "" && r.GitLabProject.ID == 0 {
				return fmt.Errorf("rules[%d]: gitlab_project needs path or id", i)
			}
		}
		if len(r.GitHubSubpaths) > 0 && len(r.GitHubRepo) == 0 {
			return fmt.Errorf("rules[%d]: github_subpaths requires github_repo", i)
		}
		for j, repo := range r.GitHubRepo {
			repo = strings.Trim(strings.ToLower(repo), "/")
			if repo == "" || strings.Count(repo, "/") != 1 {
				return fmt.Errorf("rules[%d]: github_repo[%d] must be owner/repo", i, j)
			}
			r.GitHubRepo[j] = repo
		}
		for j, sp := range r.GitHubSubpaths {
			r.GitHubSubpaths[j] = strings.Trim(sp, "/")
		}
		if r.Git != nil {
			switch r.Git.Service {
			case "", "receive-pack", "upload-pack", "upload-archive":
			default:
				return fmt.Errorf("rules[%d]: git.service must be receive-pack, upload-pack or upload-archive", i)
			}
			for _, u := range r.Git.Updates {
				switch u {
				case "create", "update", "delete":
				default:
					return fmt.Errorf("rules[%d]: git.updates must be create, update or delete", i)
				}
			}
		}
		if r.GraphQL != nil {
			for _, o := range r.GraphQL.Operations {
				switch o {
				case "query", "mutation", "subscription":
				default:
					return fmt.Errorf("rules[%d]: graphql.operations must be query, mutation or subscription", i)
				}
			}
		}
		if r.SSH != nil && r.SSH.Command != "" {
			re, err := regexp.Compile(r.SSH.Command)
			if err != nil {
				return fmt.Errorf("rules[%d]: ssh.command: %w", i, err)
			}
			r.SSH.CommandRegexp = re
		}
	}
	return nil
}

func loopback(addr string) bool {
	host, _ := SplitHostPort(addr)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ResolvedProfile returns a profile with its extends chain flattened: parent
// filters first, and http/ssh entries overridden by name in the child.
func (c *Config) ResolvedProfile(name string) (*Profile, error) {
	p, ok := c.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", name)
	}
	if p.Extends == "" {
		return p, nil
	}
	parent, err := c.ResolvedProfile(p.Extends)
	if err != nil {
		return nil, err
	}
	out := &Profile{Name: p.Name, Unmatched: p.Unmatched, Tunnel: append(append([]string{}, parent.Tunnel...), p.Tunnel...)}
	if out.Unmatched == "" {
		out.Unmatched = parent.Unmatched
	}
	out.AllowPrivate = p.AllowPrivate
	if out.AllowPrivate == nil {
		out.AllowPrivate = parent.AllowPrivate
	}
	out.Filters = append(append([]FilterRef{}, parent.Filters...), p.Filters...)
	out.HTTP = mergeByName(parent.HTTP, p.HTTP, func(s *Service) string { return s.Name })
	out.SSH = mergeByName(parent.SSH, p.SSH, func(s *SSHService) string { return s.Name })
	return out, nil
}

// mergeByName puts child entries first (so they win host matching), followed
// by parent entries the child didn't override.
func mergeByName[T any](parent, child []T, name func(T) string) []T {
	seen := map[string]bool{}
	var out []T
	for _, c := range child {
		seen[name(c)] = true
		out = append(out, c)
	}
	for _, p := range parent {
		if !seen[name(p)] {
			out = append(out, p)
		}
	}
	return out
}

// UnmatchedMode returns the effective unmatched mode.
func (p *Profile) UnmatchedMode() string {
	if p.Unmatched == "" {
		return UnmatchedTunnel
	}
	return p.Unmatched
}

func (s *ValueSource) init(cred, slot, dir string) error {
	if s == nil {
		return fmt.Errorf("credential %q %s: empty", cred, slot)
	}
	if s.Source == "ssh-agent" && slot != SlotPrivateKey {
		return fmt.Errorf("credential %q %s: source ssh-agent is only valid on private_key", cred, slot)
	}
	switch s.Source {
	case "keyring", "provided":
	case "ssh-agent":
	case "command":
		if len(s.Command) == 0 {
			return fmt.Errorf("credential %q %s: source command requires command", cred, slot)
		}
	case "env":
		if s.Env == "" {
			return fmt.Errorf("credential %q %s: source env requires env", cred, slot)
		}
	case "file":
		if s.File == "" {
			return fmt.Errorf("credential %q %s: source file requires file", cred, slot)
		}
		s.File = expandPath(s.File, dir)
	case "bitwarden":
		if strings.TrimSpace(s.Email) == "" || strings.TrimSpace(s.Item) == "" {
			return fmt.Errorf("credential %q %s: source bitwarden requires email and item", cred, slot)
		}
		if strings.TrimSpace(s.Path) == "" {
			return fmt.Errorf("credential %q %s: source bitwarden requires path", cred, slot)
		}
	default:
		return fmt.Errorf("credential %q %s: unknown source %q (want keyring, command, env, file, ssh-agent, bitwarden, provided)", cred, slot, s.Source)
	}
	return nil
}

// KeyringAccount is the OS keyring account this slot is stored under.
func (s *ValueSource) KeyringAccount(credName string) string {
	if s != nil && s.Account != "" {
		return s.Account
	}
	return credName
}

func expandPath(p, base string) string {
	if p == "" {
		return p
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err == nil {
			p = filepath.Join(home, p[1:])
		}
	}
	if !filepath.IsAbs(p) && base != "" {
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}
