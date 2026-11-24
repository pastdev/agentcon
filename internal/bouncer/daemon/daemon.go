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
	"github.com/pastdev/agentcon/internal/bouncer/proxy"
	"github.com/pastdev/agentcon/internal/bouncer/signer"
	"github.com/pastdev/agentcon/internal/bouncer/sshproxy"
	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
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
	claims    *approval.Claims
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
	// saveMu serializes writes of the sessions file.
	saveMu sync.Mutex

	resolved sync.Map // resolver cache key -> resolvedID

	proxyAddr, sshAddr, mgmtAddr string

	// startup records the credential preparation started by New.
	startupMu   sync.Mutex
	startupDone bool
	startupErr  error
	// startupRerun asks a running startup preparation to try again if it
	// fails, because values it may need arrived while it ran.
	startupRerun bool
}

// SessionRecord is a registered agent session.
type SessionRecord struct {
	chain.Session
	// InstanceID persists Session.Instance, which never reaches JSON
	// itself so filters cannot see it.
	InstanceID string    `json:"instance"`
	Token      string    `json:"token"`
	Created    time.Time `json:"created"`
	// Expires is zero for sessions that last until revoked.
	Expires time.Time `json:"expires,omitzero"`
}

// newInstance returns a session instance id.
func newInstance() string { return randHex(8) }

func (s *SessionRecord) expired() bool { return !s.Expires.IsZero() && time.Now().After(s.Expires) }

// wire is the record as the control API sends it.
func (s *SessionRecord) wire() mgmt.SessionRecord {
	return mgmt.SessionRecord{
		ID:      s.ID,
		Label:   s.Label,
		Profile: s.Profile,
		Claims:  s.Claims.Clone(),
		Token:   s.Token,
		Created: s.Created,
		Expires: s.Expires,
	}
}

// clone copies the record, claims included.
func (s *SessionRecord) clone() *SessionRecord {
	c := *s
	c.Claims = s.Claims.Clone()
	return &c
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
	d.claims = approval.NewClaims(d.Prompts, d)
	d.env = &chain.Env{
		Approver: d.Approvals,
		Claims:   d.claims,
		Resolver: d.resolveGitLabProject,
		Log:      component(opts.Log, "filter"),
	}
	creds.ConfigureBitwarden(opts.StateDir, component(opts.Log, "bitwarden"), d.Prompts)
	d.creds = creds.NewStore(cfg.Credentials)
	d.creds.SetProvided(opts.Provided)
	d.env.Credential = func(ctx context.Context, name string) (string, error) {
		if c, ok := d.Config().Credentials[name]; ok && c.Internal {
			d.log.Warn().Str("credential", name).Msg("filter asked for an internal credential")
			return "", creds.Unavailable(name)
		}
		sec, err := d.creds.Get(ctx, name)
		if err != nil {
			creds.LogError(d.log.Warn(), err).Str("credential", name).Msg("credential unavailable to a filter")
			return "", creds.Unavailable(name)
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
	for {
		err := d.creds.Prepare(context.Background(), set)
		if err != nil {
			creds.LogError(d.log.Warn(), err).Msg("prepare credentials")
		}
		if !startup {
			return
		}
		d.startupMu.Lock()
		rerun := err != nil && d.startupRerun
		d.startupRerun = false
		if !rerun {
			d.startupDone, d.startupErr = true, err
		}
		d.startupMu.Unlock()
		if !rerun {
			return
		}
	}
}

// retryStartup gives a failed startup preparation another try after new
// env or provided values arrive, such as a Bitwarden account password.
// A preparation still running retries once if it fails. Status reports
// not ready until the retry finishes.
func (d *Daemon) retryStartup() {
	d.startupMu.Lock()
	defer d.startupMu.Unlock()
	if !d.startupDone {
		d.startupRerun = true
		return
	}
	if d.startupErr == nil {
		return
	}
	d.startupDone, d.startupErr = false, nil
	go d.prepare(d.Config().Credentials, true)
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
// every provided name is a configured credential slot or Bitwarden account.
// When opts.Provided is non-nil, every source: provided credential and
// account password must also have a value.
// A nil map (the sidecar) skips that check so host values can be PUT after
// serve is up.
func (d *Daemon) checkProvided(cfg *config.Config) error {
	var unknown, missing []string
	for key := range d.opts.Provided {
		cred, slot, ok := strings.Cut(key, ".")
		if c, have := cfg.Credentials[cred]; ok && have && c.Slot(slot) != nil {
			continue
		}
		if _, have := cfg.Bitwarden[slot]; ok && have && key == config.BitwardenKey(slot) {
			continue
		}
		unknown = append(unknown, key)
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
		for _, a := range config.BitwardenAccounts(cfg.Credentials) {
			if a.Password == nil || a.Password.Source != "provided" {
				continue
			}
			key := config.BitwardenKey(a.Name)
			if _, ok := d.opts.Provided[key]; !ok {
				missing = append(missing, key)
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
			switch p.Kind {
			case prompt.KindConfirm:
				title = "agent-bouncer: approval needed"
			case prompt.KindClaim:
				title = "agent-bouncer: claim requested"
			case prompt.KindText, prompt.KindSecret:
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
		return &chain.Session{ID: "anonymous", Label: "anonymous", Profile: d.cfg.AnonymousProfile, Claims: claims.Set{}, Shared: true}, true
	}
	s, ok := d.sessions[token]
	if !ok || s.expired() {
		return nil, false
	}
	// A request gets its own copy of the claims, fixed when it arrives.
	return s.Clone(), true
}

// liveSession returns the unexpired record for sess, matching its id and
// instance, so a session that reuses an ended session's id is never
// mistaken for it. Caller holds mu.
func (d *Daemon) liveSession(sess *chain.Session) *SessionRecord {
	for _, s := range d.sessions {
		if s.ID == sess.ID && s.InstanceID == sess.Instance && !s.expired() {
			return s
		}
	}
	return nil
}

// SessionClaims implements approval.ClaimStore.
func (d *Daemon) SessionClaims(sess *chain.Session) (claims.Set, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	s := d.liveSession(sess)
	if s == nil {
		return nil, false
	}
	return s.Claims.Clone(), true
}

// AddClaim implements approval.ClaimStore. It adds a claim an operator
// approved. The claim is saved first, and only then becomes visible to
// requests and audited, so a claim that fails to save is never granted.
func (d *Daemon) AddClaim(sess *chain.Session, c claims.Claim, filter, promptID string) error {
	// Holding saveMu keeps other saves out until this one commits. Claims
	// change only here, so the set cannot change underneath it either.
	d.saveMu.Lock()
	defer d.saveMu.Unlock()
	d.mu.RLock()
	s := d.liveSession(sess)
	if s == nil {
		d.mu.RUnlock()
		return approval.ErrSessionGone
	}
	next := s.Claims.Clone()
	added, err := next.Add(c.Type, c.Value)
	label := s.Label
	recs := d.snapshotLocked()
	d.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("add claim: %w", err)
	}
	if !added {
		return nil
	}
	for _, r := range recs {
		if r.Token == s.Token {
			r.Claims = next
		}
	}
	err = d.writeSessions(recs)
	if err != nil {
		return fmt.Errorf("save claim: %w", err)
	}
	d.mu.Lock()
	s = d.liveSession(sess)
	if s != nil {
		s.Claims = next
	}
	d.mu.Unlock()
	if s == nil {
		// Ended while saving. Its own save, waiting on saveMu, drops it.
		return approval.ErrSessionGone
	}
	d.audit.ClaimAdded(audit.ClaimEvent{Session: sess.ID, Label: label, Claim: c, AddedBy: claims.AddedOperator, Filter: filter, Prompt: promptID})
	return nil
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

// CreateSession registers a new agent session with seed as its initial
// claims, which the caller has validated with claims.FromMap.
// A ttl of 0 means the session lasts until revoked.
// An empty id mints a new session id.
func (d *Daemon) CreateSession(id, profile, label string, ttl time.Duration, seed claims.Set) (*SessionRecord, error) {
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
	rec := &SessionRecord{
		Session:    chain.Session{ID: id, Label: label, Profile: profile, Claims: seed.Clone()},
		InstanceID: newInstance(),
		Token:      randHex(24),
		Created:    time.Now(),
	}
	rec.Instance = rec.InstanceID
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
	out := rec.clone()
	d.mu.Unlock()
	d.saveSessions()
	d.audit.SessionCreated(out.ID, out.Label, out.Profile, out.Claims)
	for _, c := range out.Claims.List() {
		d.audit.ClaimAdded(audit.ClaimEvent{Session: out.ID, Label: out.Label, Claim: c, AddedBy: claims.AddedSeeded})
	}
	return out, nil
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

// SignerURL is the signer URL for a profile, or "" when it has no signer
// service.
func (d *Daemon) SignerURL(profile string) string {
	rp, err := d.Config().ResolvedProfile(profile)
	if err != nil {
		return ""
	}
	return rp.SignerService().SignerURL()
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
	var ended []string
	for tok, s := range d.sessions {
		if s.ID == id {
			delete(d.sessions, tok)
			ended = append(ended, s.InstanceID)
		}
	}
	d.mu.Unlock()
	if len(ended) == 0 {
		return false
	}
	d.Approvals.ForgetSession(id)
	for _, instance := range ended {
		d.claims.EndSession(instance)
	}
	d.saveSessions()
	return true
}

func (d *Daemon) listSessions() []SessionRecord {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]SessionRecord, 0, len(d.sessions))
	for _, s := range d.sessions {
		if s.expired() {
			continue
		}
		r := s.clone()
		r.Token = ""
		out = append(out, *r)
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
		if _, ok := d.cfg.Profiles[r.Profile]; !ok {
			continue
		}
		// Records from before claims existed have none. A record whose
		// claims no longer validate is dropped rather than trusted.
		set, err := claims.FromMap(r.Claims)
		if err != nil {
			d.log.Error().Err(err).Str("session", r.ID).Msg("drop saved session with invalid claims")
			continue
		}
		r.Claims = set
		// Records from before instances existed get one now.
		if r.InstanceID == "" {
			r.InstanceID = newInstance()
		}
		r.Instance = r.InstanceID
		d.sessions[r.Token] = r
	}
}

// saveSessions writes the sessions file, logging a failure.
func (d *Daemon) saveSessions() {
	d.saveMu.Lock()
	defer d.saveMu.Unlock()
	d.mu.RLock()
	recs := d.snapshotLocked()
	d.mu.RUnlock()
	err := d.writeSessions(recs)
	if err != nil {
		d.log.Error().Err(err).Msg("save sessions")
	}
}

// snapshotLocked copies every session record. Caller holds mu.
func (d *Daemon) snapshotLocked() []*SessionRecord {
	recs := make([]*SessionRecord, 0, len(d.sessions))
	for _, s := range d.sessions {
		recs = append(recs, s.clone())
	}
	return recs
}

// writeSessions replaces the sessions file. Caller holds saveMu.
func (d *Daemon) writeSessions(recs []*SessionRecord) error {
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sessions: %w", err)
	}
	tmp := d.sessionsFile() + ".tmp"
	err = os.WriteFile(tmp, b, 0o600)
	if err != nil {
		return fmt.Errorf("write sessions: %w", err)
	}
	err = os.Rename(tmp, d.sessionsFile())
	if err != nil {
		return fmt.Errorf("replace sessions: %w", err)
	}
	return nil
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
			creds.LogError(d.log.Warn(), err).Str("service", service).Msg("credential unavailable for gitlab project lookup")
			return 0, fmt.Errorf("gitlab api: %w", creds.Unavailable(service))
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
		Signer: &signer.OpenPGP{Creds: d.creds},
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
