// Package daemon wires bouncer's components into the long-running process
// behind `bouncer serve`.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/internal/bouncer/audit"
	"github.com/pastdev/agentcon/internal/bouncer/ca"
	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/internal/bouncer/kv"
	"github.com/pastdev/agentcon/internal/bouncer/notify"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/pastdev/agentcon/internal/bouncer/proxy"
	"github.com/pastdev/agentcon/internal/bouncer/sshproxy"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// Options configure a daemon.
type Options struct {
	ConfigPath string
	StateDir   string
	// Load returns the service config. When nil, ConfigPath is read with config.Load.
	Load func() (*config.Config, error)
	// Log receives operational messages. Each component logs through a
	// child that names it.
	Log zerolog.Logger
	// Audit receives one event per decision.
	Audit zerolog.Logger
	// Provided are secrets supplied at daemon start. They override
	// configured sources and are held only in memory.
	Provided map[string]string
}

func (o Options) loadConfig() (*config.Config, error) {
	if o.Load != nil {
		return o.Load()
	}
	if o.ConfigPath == "" {
		return nil, fmt.Errorf("bouncer policy is required")
	}
	cfg, err := config.Load(o.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	return cfg, nil
}

// Daemon is a running bouncer.
type Daemon struct {
	opts      Options
	log       zerolog.Logger
	CA        *ca.Authority
	Approvals *approval.Manager
	Prompts   *prompt.Broker
	creds     *creds.Store
	kv        *kv.Store
	audit     *audit.Log
	env       *chain.Env
	transport *http.Transport
	admin     string

	mu       sync.RWMutex
	cfg      *config.Config
	set      *policy.Set
	sessions map[string]*SessionRecord // by token

	resolved sync.Map // resolver cache key -> resolvedID

	proxyAddr, sshAddr, mgmtAddr string

	// startup records the credential preparation started by New.
	startupMu   sync.Mutex
	startupDone bool
	startupErr  error
}

// SessionRecord is a registered agent session.
type SessionRecord struct {
	chain.Session
	Token   string    `json:"token"`
	Created time.Time `json:"created"`
	// Expires is zero for sessions that last until revoked.
	Expires time.Time `json:"expires,omitzero"`
}

func (s *SessionRecord) expired() bool { return !s.Expires.IsZero() && time.Now().After(s.Expires) }

// NewSession is the control API's reply to session creation: everything a
// client needs to build the agent's environment without parsing the config.
type NewSession struct {
	SessionRecord
	ProxyAddr string `json:"proxy_addr"`
	SSHAddr   string `json:"ssh_addr"`
	// Placeholders maps environment variable names to placeholder values.
	Placeholders map[string]string `json:"placeholders"`
	// SSHHosts lists every configured SSH service host pattern, the only
	// hosts the generated known_hosts trusts the bouncer SSH CA for.
	SSHHosts []string `json:"ssh_hosts"`
}

// Runtime describes a running daemon; written to the state dir so clients
// can find it even when the config file is mid-edit.
type Runtime struct {
	ProxyAddr string `json:"proxy_addr"`
	SSHAddr   string `json:"ssh_addr"`
	MgmtAddr  string `json:"mgmt_addr,omitempty"`
	PID       int    `json:"pid"`
	Config    string `json:"config"`
}

// RuntimePath is the runtime file in a state dir.
func RuntimePath(stateDir string) string { return filepath.Join(stateDir, "daemon.json") }

type resolvedID struct {
	id      int64
	expires time.Time
}

// New loads config and state. It does not start listening.
func New(opts Options) (*Daemon, error) {
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	d := &Daemon{
		opts:      opts,
		log:       component(opts.Log, "daemon"),
		sessions:  map[string]*SessionRecord{},
		transport: proxy.NewTransport(),
	}
	var err error
	if d.CA, err = ca.LoadOrCreate(opts.StateDir); err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	if err := d.CA.WriteBundle(); err != nil {
		d.log.Error().Err(err).Msg("write CA bundle")
	}
	if d.admin, err = LoadOrCreateAdminToken(opts.StateDir); err != nil {
		return nil, err
	}
	if d.kv, err = kv.Open(filepath.Join(opts.StateDir, "kv.json")); err != nil {
		return nil, fmt.Errorf("kv store: %w", err)
	}
	d.audit = audit.New(opts.Audit)
	cfg, err := opts.loadConfig()
	if err != nil {
		return nil, err
	}
	d.Prompts = prompt.NewBroker(cfg.Prompts.TimeoutOrDefault())
	d.Approvals = approval.NewManager(d.Prompts)
	d.env = &chain.Env{
		Approver: d.Approvals,
		Resolver: d.resolveGitLabProject,
		Log: func(filter, msg string, fields map[string]any) {
			flog := component(opts.Log, "filter")
			flog.Info().Str("filter", filter).Fields(fields).Msg(msg)
		},
	}
	creds.ConfigureBitwarden(opts.StateDir, component(opts.Log, "bitwarden"), d.Prompts)
	d.creds = creds.NewStore(cfg.Credentials)
	d.creds.SetProvided(opts.Provided)
	d.env.Credential = func(ctx context.Context, name string) (string, error) {
		sec, err := d.creds.Get(ctx, name)
		if err != nil {
			return "", fmt.Errorf("credential %s: %w", name, err)
		}
		return sec.HTTP(), nil
	}
	if err := d.apply(cfg); err != nil {
		return nil, err
	}
	d.loadSessions()
	go d.prepare(cfg.Credentials, true)
	return d, nil
}

// prepare unlocks the credential sources a config uses, asking a human
// through d.Prompts when needed. It runs in the background so the control
// API is up to answer. startup records the result for status.
func (d *Daemon) prepare(set map[string]*config.Credential, startup bool) {
	err := d.creds.Prepare(context.Background(), set)
	if err != nil {
		d.log.Warn().Err(err).Msg("prepare credentials")
	}
	if !startup {
		return
	}
	d.startupMu.Lock()
	d.startupDone, d.startupErr = true, err
	d.startupMu.Unlock()
}

// Startup reports whether the credential preparation started by New has
// finished, and its error.
func (d *Daemon) Startup() (bool, error) {
	d.startupMu.Lock()
	defer d.startupMu.Unlock()
	return d.startupDone, d.startupErr
}

// Config returns the active config.
func (d *Daemon) Config() *config.Config {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cfg
}

// checkProvided ensures startup-provided secrets and the config agree:
// every provided name is a configured credential. When opts.Provided is
// non-nil, every source: provided credential must also have a value.
// A nil map (the sidecar) skips that check so host values can be PUT after
// serve is up.
func (d *Daemon) checkProvided(cfg *config.Config) error {
	var unknown, missing []string
	for key := range d.opts.Provided {
		cred, slot, ok := strings.Cut(key, ".")
		c, have := cfg.Credentials[cred]
		if !ok || !have || c.Slot(slot) == nil {
			unknown = append(unknown, key)
		}
	}
	if d.opts.Provided != nil {
		for name, c := range cfg.Credentials {
			if c == nil {
				continue
			}
			for _, slot := range c.Slots() {
				if slot.Source.Source != "provided" {
					continue
				}
				key := config.ProvidedKey(name, slot.Name)
				if _, ok := d.opts.Provided[key]; !ok {
					missing = append(missing, key)
				}
			}
		}
	}
	// "a: x" + "b: y" printed without a newline between them parses as a
	// single value for a; catch it when b is a configured name.
	for name, v := range d.opts.Provided {
		for other := range cfg.Credentials {
			if other != name && strings.Contains(v, other+": ") {
				return fmt.Errorf("provided value for %s contains %q; is a newline missing between entries?", name, other+": ")
			}
		}
	}
	sort.Strings(unknown)
	sort.Strings(missing)
	switch {
	case len(unknown) > 0:
		return fmt.Errorf("provided names credentials not in the config: %s", strings.Join(unknown, ", "))
	case len(missing) > 0:
		return fmt.Errorf("credentials with source: provided have no value: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (d *Daemon) apply(cfg *config.Config) error {
	if err := d.checkProvided(cfg); err != nil {
		return err
	}
	set, err := policy.Compile(cfg, d.env, d.kv)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}
	d.creds.Update(cfg.Credentials)
	d.Prompts.SetTimeout(cfg.Prompts.TimeoutOrDefault())
	if cfg.Prompts.NotifyEnabled() {
		d.Prompts.SetNotify(func(p prompt.Pending) {
			title := "agent-bouncer: input needed"
			if p.Kind == prompt.KindConfirm {
				title = "agent-bouncer: approval needed"
			}
			notify.Send(title, approval.Display(p.Message, 150)+"\n"+approval.Display(p.Detail, 150))
		})
	} else {
		d.Prompts.SetNotify(nil)
	}
	d.mu.Lock()
	d.cfg, d.set = cfg, set
	d.mu.Unlock()
	return nil
}

// Reload re-reads the config, keeping the old one if the new one is invalid.
func (d *Daemon) Reload() error {
	old := d.Config()
	cfg, err := d.opts.loadConfig()
	if err == nil {
		err = d.apply(cfg)
	}
	if err != nil {
		d.log.Warn().Err(err).Msg("reload failed, keeping previous config")
		return err
	}
	go d.prepare(cfg.Credentials, false)
	if old != nil && (old.Listen != cfg.Listen || old.SSHListen != cfg.SSHListen) {
		d.log.Warn().Msg("listen address changes take effect after restart")
	}
	d.log.Info().Msg("config reloaded")
	return nil
}

// Session implements proxy.Backend and sshproxy.Backend.
func (d *Daemon) Session(token string) (*chain.Session, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if token == "" {
		if d.cfg.AnonymousProfile == "" {
			return nil, false
		}
		return &chain.Session{ID: "anonymous", Label: "anonymous", Profile: d.cfg.AnonymousProfile, Shared: true}, true
	}
	s, ok := d.sessions[token]
	if !ok || s.expired() {
		return nil, false
	}
	sess := s.Session
	return &sess, true
}

// Profile implements proxy.Backend and sshproxy.Backend.
func (d *Daemon) Profile(name string) (*policy.Profile, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.set.Profiles[name]
	return p, ok
}

// SessionIDLength is the hex length of a session id (slug).
const SessionIDLength = 8

// NewSessionID returns an 8-character hex session id.
func NewSessionID() string {
	return randHex(SessionIDLength / 2)
}

// CreateSession registers a new agent session.
// A ttl of 0 means the session lasts until revoked.
// An empty id mints a new session id.
func (d *Daemon) CreateSession(id, profile, label string, ttl time.Duration) (*SessionRecord, error) {
	d.mu.Lock()
	if profile == "" {
		profile = d.cfg.DefaultProfile
	}
	if profile == "" {
		d.mu.Unlock()
		return nil, errors.New("no profile given and no default_profile configured")
	}
	if _, ok := d.cfg.Profiles[profile]; !ok {
		d.mu.Unlock()
		return nil, fmt.Errorf("unknown profile %q", profile)
	}
	if id == "" {
		id = NewSessionID()
	} else {
		if len(id) != SessionIDLength {
			d.mu.Unlock()
			return nil, fmt.Errorf("session id %q must be %d hex characters", id, SessionIDLength)
		}
		if _, err := hex.DecodeString(id); err != nil {
			d.mu.Unlock()
			return nil, fmt.Errorf("session id %q must be %d hex characters", id, SessionIDLength)
		}
		id = strings.ToLower(id)
		for _, s := range d.sessions {
			if s.ID == id && !s.expired() {
				d.mu.Unlock()
				return nil, fmt.Errorf("session %q already exists", id)
			}
		}
	}
	rec := &SessionRecord{Session: chain.Session{ID: id, Label: label, Profile: profile}, Token: randHex(24), Created: time.Now()}
	if ttl > 0 {
		rec.Expires = rec.Created.Add(ttl)
	}
	for tok, s := range d.sessions {
		if s.expired() {
			delete(d.sessions, tok)
		}
	}
	if rec.Label == "" {
		rec.Label = rec.ID
	}
	d.sessions[rec.Token] = rec
	d.mu.Unlock()
	d.saveSessions()
	return rec, nil
}

// Placeholders lists the export_env variables of every credential.
func (d *Daemon) Placeholders() map[string]string {
	out := map[string]string{}
	for _, c := range d.Config().Credentials {
		for _, k := range c.ExportEnv {
			out[k] = c.Placeholder()
		}
	}
	return out
}

// SSHHosts lists the host patterns of every configured SSH service.
func (d *Daemon) SSHHosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range d.Config().Profiles {
		for _, s := range p.SSH {
			for _, h := range s.Hosts {
				if !seen[h] {
					seen[h] = true
					out = append(out, h)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// EndSession removes a session by ID.
func (d *Daemon) EndSession(id string) bool {
	d.mu.Lock()
	found := false
	for tok, s := range d.sessions {
		if s.ID == id {
			delete(d.sessions, tok)
			found = true
		}
	}
	d.mu.Unlock()
	if found {
		d.Approvals.ForgetSession(id)
		d.saveSessions()
	}
	return found
}

func (d *Daemon) listSessions() []SessionRecord {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]SessionRecord, 0, len(d.sessions))
	for _, s := range d.sessions {
		if s.expired() {
			continue
		}
		r := *s
		r.Token = ""
		out = append(out, r)
	}
	return out
}

func (d *Daemon) sessionsFile() string { return filepath.Join(d.opts.StateDir, "sessions.json") }

// Sessions survive daemon restarts so running agents keep working.
func (d *Daemon) loadSessions() {
	b, err := os.ReadFile(d.sessionsFile())
	if err != nil {
		return
	}
	var recs []*SessionRecord
	if json.Unmarshal(b, &recs) != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range recs {
		if _, ok := d.cfg.Profiles[r.Profile]; ok {
			d.sessions[r.Token] = r
		}
	}
}

func (d *Daemon) saveSessions() {
	d.mu.RLock()
	recs := make([]*SessionRecord, 0, len(d.sessions))
	for _, s := range d.sessions {
		recs = append(recs, s)
	}
	d.mu.RUnlock()
	b, _ := json.MarshalIndent(recs, "", "  ")
	tmp := d.sessionsFile() + ".tmp"
	err := os.WriteFile(tmp, b, 0o600)
	if err == nil {
		err = os.Rename(tmp, d.sessionsFile())
	}
	if err != nil {
		d.log.Error().Err(err).Msg("save sessions")
	}
}

// resolveGitLabProject looks up a project's numeric ID using the service's credential.
func (d *Daemon) resolveGitLabProject(ctx context.Context, service, host, project string) (int64, error) {
	key := service + "\x00" + host + "\x00" + project
	if v, ok := d.resolved.Load(key); ok {
		if r := v.(resolvedID); time.Now().Before(r.expires) {
			return r.id, nil
		}
	}
	var svc *config.Service
	d.mu.RLock()
	for _, p := range d.set.Profiles {
		for _, s := range p.HTTP {
			if s.Config.Name == service && config.HostMatches(s.Config.Hosts, host) {
				svc = s.Config
			}
		}
	}
	d.mu.RUnlock()
	if svc == nil {
		return 0, fmt.Errorf("unknown service %q", service)
	}
	u, _ := url.Parse("https://" + host + "/api/v4/projects/" + url.PathEscape(project))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("gitlab request: %w", err)
	}
	if svc.Credential != "" {
		secret, err := d.creds.Get(ctx, svc.Credential)
		if err != nil {
			return 0, fmt.Errorf("credential %s: %w", svc.Credential, err)
		}
		spec := svc.Inject
		if spec == nil {
			spec = &config.Inject{Bearer: true}
		}
		proxy.Inject(req.Header, req.URL, svc.Credential, spec, secret)
	}
	resp, err := d.transport.RoundTrip(req)
	if err != nil {
		return 0, fmt.Errorf("gitlab project %s: %w", project, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode gitlab project %s: %w", project, err)
	}
	d.resolved.Store(key, resolvedID{id: body.ID, expires: time.Now().Add(time.Hour)})
	return body.ID, nil
}

// Run serves until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	cfg := d.Config()
	plan, err := planListen(cfg)
	if err != nil {
		return fmt.Errorf("listen plan: %w", err)
	}

	httpL, err := net.Listen("tcp", plan.proxy)
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	sshL, err := net.Listen("tcp", plan.ssh)
	if err != nil {
		_ = httpL.Close()
		return fmt.Errorf("ssh listen: %w", err)
	}
	var mgmtL net.Listener
	if plan.split {
		mgmtL, err = net.Listen("tcp", plan.mgmt)
		if err != nil {
			_ = httpL.Close()
			_ = sshL.Close()
			return fmt.Errorf("management listen: %w", err)
		}
	}

	px := &proxy.Server{Backend: d, CA: d.CA, Creds: d.creds, Audit: d.audit, Transport: d.transport,
		Dialer: &net.Dialer{Timeout: 30 * time.Second}, Log: component(d.opts.Log, "proxy"), DisableControl: plan.split}
	httpSrv := &http.Server{Handler: px, ReadHeaderTimeout: 30 * time.Second}
	sshSrv := &sshproxy.Server{Backend: d, CA: d.CA, Creds: d.creds, Audit: d.audit, Log: component(d.opts.Log, "ssh")}
	mgmtSrv := &http.Server{Handler: d.Control(), ReadHeaderTimeout: 30 * time.Second}

	stopWatch, err := d.watch()
	if err != nil {
		d.log.Warn().Err(err).Msg("config watching disabled")
	} else {
		defer stopWatch()
	}

	errc := make(chan error, 3)
	go func() { errc <- httpSrv.Serve(httpL) }()
	go func() { errc <- sshSrv.Serve(sshL) }()
	if mgmtL != nil {
		go func() { errc <- mgmtSrv.Serve(mgmtL) }()
	}
	d.proxyAddr, d.sshAddr = httpL.Addr().String(), sshL.Addr().String()
	d.mgmtAddr = d.proxyAddr
	if mgmtL != nil {
		d.mgmtAddr = mgmtL.Addr().String()
	}
	rt, _ := json.Marshal(Runtime{
		ProxyAddr: d.proxyAddr, SSHAddr: d.sshAddr, MgmtAddr: d.mgmtAddr,
		PID: os.Getpid(), Config: cfg.Path,
	})
	if err := os.WriteFile(RuntimePath(d.opts.StateDir), rt, 0o600); err != nil {
		d.log.Error().Err(err).Msg("write runtime file")
	}
	defer func() { _ = os.Remove(RuntimePath(d.opts.StateDir)) }()
	d.log.Info().Str("proxy", d.proxyAddr).Str("ssh", d.sshAddr).Str("management", d.mgmtAddr).Msg("listening")
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	_ = httpL.Close()
	_ = sshL.Close()
	if mgmtL != nil {
		_ = mgmtL.Close()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	_ = mgmtSrv.Shutdown(shutdownCtx)
	kvErr := d.kv.Close()
	if kvErr != nil {
		d.log.Error().Err(kvErr).Msg("save kv store")
	}
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// AdminTokenPath is where the control API token lives.
func AdminTokenPath(stateDir string) string { return filepath.Join(stateDir, "admin-token") }

// LoadOrCreateAdminToken returns the control API token, creating it if needed.
func LoadOrCreateAdminToken(stateDir string) (string, error) {
	p := AdminTokenPath(stateDir)
	if b, err := os.ReadFile(p); err == nil { //nolint:gosec // path from operator config or the state dir, not the agent
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
	}
	t := NewAdminToken()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", fmt.Errorf("state dir: %w", err)
	}
	err := os.WriteFile(p, []byte(t+"\n"), 0o600)
	if err != nil {
		return "", fmt.Errorf("write admin token: %w", err)
	}
	return t, nil
}

// NewAdminToken returns a random control API token.
func NewAdminToken() string { return randHex(32) }

// component returns a child of log that names the component logging.
func component(log zerolog.Logger, name string) zerolog.Logger {
	return log.With().Str("component", name).Logger()
}
