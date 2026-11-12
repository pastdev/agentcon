// Package testrunner runs *.test.yaml specs against filters or whole
// profiles, with a mocked upstream, so policies can be tested offline.
package testrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/gitproto"
	"github.com/pastdev/agentcon/internal/bouncer/jsfilter"
	"github.com/pastdev/agentcon/internal/bouncer/kv"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// Spec is one test file. It targets either a single filter (Filter +
// FilterConfig) or a profile in a config file (Config + Profile).
type Spec struct {
	Filter       string         `yaml:"filter"`
	FilterConfig map[string]any `yaml:"filter_config"`
	Config       string         `yaml:"config"`
	Profile      string         `yaml:"profile"`
	// GitLabProjectIDs stubs numeric project ID resolution for config tests.
	GitLabProjectIDs map[string]int64 `yaml:"gitlab_project_ids"`
	Cases            []Case           `yaml:"cases"`
}

// Case is isolated: it gets a fresh KV store and a freshly loaded filter or
// compiled policy. Its steps run in order and share that state.
type Case struct {
	Name string `yaml:"name"`
	// FilterConfig replaces the spec's FilterConfig when set, even to {}.
	FilterConfig map[string]any `yaml:"filter_config"`
	// Profile replaces the spec's Profile when not empty.
	Profile string `yaml:"profile"`
	Steps   []Step `yaml:"steps"`
}

type Step struct {
	Name     string       `yaml:"name"`
	Request  *HTTPRequest `yaml:"request"`
	SSH      *SSHRequest  `yaml:"ssh"`
	Upstream *Upstream    `yaml:"upstream"`
	// Approve answers every ask() in this step. Unset means asks are denied.
	Approve *bool `yaml:"approve"`

	Expect               string            `yaml:"expect"` // allow or deny
	ExpectReason         string            `yaml:"expect_reason"`
	ExpectStatus         int               `yaml:"expect_status"`
	ExpectBodyContains   []string          `yaml:"expect_body_contains"`
	ExpectBodyExcludes   []string          `yaml:"expect_body_excludes"`
	ExpectAsked          *bool             `yaml:"expect_asked"`
	ExpectUpstreamHeader map[string]string `yaml:"expect_upstream_header"`
}

type HTTPRequest struct {
	Method  string            `yaml:"method"`
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	GitPush []PushRef         `yaml:"git_push"`
}

type SSHRequest struct {
	Host      string    `yaml:"host"`
	User      string    `yaml:"user"`
	Kind      string    `yaml:"kind"` // inferred from command if empty
	Command   string    `yaml:"command"`
	Subsystem string    `yaml:"subsystem"`
	Target    string    `yaml:"target"`
	GitPush   []PushRef `yaml:"git_push"`
}

// PushRef describes one ref update; Type create/delete sets the zero OID.
type PushRef struct {
	Ref  string `yaml:"ref"`
	Type string `yaml:"type"`
}

type Upstream struct {
	Status  int               `yaml:"status"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
}

// Result of one case. A failed case names its first failing step.
type Result struct {
	Name   string
	Passed bool
	// Step is the 1-based index of the failing step, 0 when passed.
	Step     int
	StepName string
	Message  string
	// FilterLog is the filter console output of the failed case.
	FilterLog string
}

// Find expands paths (files or directories) into *.test.yaml files.
func Find(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("test path: %w", err)
		}
		if !st.IsDir() {
			out = append(out, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			if !d.IsDir() && (strings.HasSuffix(path, ".test.yaml") || strings.HasSuffix(path, ".test.yml")) {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", p, err)
		}
	}
	sort.Strings(out)
	return out, nil
}

// harnessName names the session and service the test harness supplies.
const harnessName = "test"

type chainFunc func(host string) ([]chain.Filter, string, error)

// RunFile runs every case in a spec file. An error means the spec, or a
// case's filter or policy, could not be loaded.
func RunFile(path string) ([]Result, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from operator config or the state dir, not the agent
	if err != nil {
		return nil, fmt.Errorf("read test file: %w", err)
	}
	var spec Spec
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&spec); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if spec.Filter == "" && spec.Config == "" {
		return nil, fmt.Errorf("%s: spec needs a filter or config key", path)
	}
	dir := filepath.Dir(path)

	results := make([]Result, 0, len(spec.Cases))
	for i := range spec.Cases {
		c := &spec.Cases[i]
		name := c.Name
		if name == "" {
			name = fmt.Sprintf("case %d", i+1)
		}
		result, err := runCase(&spec, c, dir)
		if err != nil {
			return nil, fmt.Errorf("%s: case %q: %w", path, name, err)
		}
		result.Name = name
		results = append(results, result)
	}
	return results, nil
}

func runCase(spec *Spec, c *Case, dir string) (Result, error) {
	if len(c.Steps) == 0 {
		return Result{}, errors.New("case has no steps")
	}
	store, _ := kv.Open("")
	defer func() { _ = store.Close() }()
	approver := &scriptedApprover{}
	logs := &bytes.Buffer{}
	env := &chain.Env{
		Approver: approver,
		Log: zerolog.New(zerolog.ConsoleWriter{
			Out:        logs,
			NoColor:    true,
			PartsOrder: []string{zerolog.LevelFieldName, zerolog.MessageFieldName},
		}),
		Resolver: func(_ context.Context, _, _, p string) (int64, error) {
			if id, ok := spec.GitLabProjectIDs[p]; ok {
				return id, nil
			}
			return 0, fmt.Errorf("no gitlab_project_ids entry for %q", p)
		},
	}
	profile := spec.Profile
	if c.Profile != "" {
		profile = c.Profile
	}
	httpChain, sshChain, err := chains(spec, c, dir, profile, env, store)
	if err != nil {
		return Result{}, err
	}

	for i := range c.Steps {
		s := &c.Steps[i]
		approver.answer, approver.asked = s.Approve != nil && *s.Approve, false
		msg, err := runStep(s, httpChain, sshChain, profile, approver)
		if err != nil {
			msg = err.Error()
		}
		if msg == "" {
			continue
		}
		name := s.Name
		if name == "" {
			name = strconv.Itoa(i + 1)
		}
		return Result{
			Step:      i + 1,
			StepName:  name,
			Message:   msg,
			FilterLog: strings.TrimSpace(logs.String()),
		}, nil
	}
	return Result{Passed: true}, nil
}

// chains loads the case's filter, or compiles its policy and picks its
// profile, and returns the filter chain lookups for HTTP and SSH.
func chains(spec *Spec, c *Case, dir, profile string, env *chain.Env, store *kv.Store) (chainFunc, chainFunc, error) {
	if spec.Filter != "" {
		cfg := spec.FilterConfig
		if c.FilterConfig != nil {
			cfg = c.FilterConfig
		}
		f, err := jsfilter.Load(jsfilter.Options{Path: filepath.Join(dir, spec.Filter), Config: cfg, Env: env, KV: store})
		if err != nil {
			return nil, nil, fmt.Errorf("load filter: %w", err)
		}
		one := func(string) ([]chain.Filter, string, error) { return []chain.Filter{f}, harnessName, nil }
		return one, one, nil
	}

	if profile == "" {
		return nil, nil, errors.New("no profile")
	}
	cfg, err := config.Load(filepath.Join(dir, spec.Config))
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	set, err := policy.Compile(cfg, env, store)
	if err != nil {
		return nil, nil, fmt.Errorf("compile policy: %w", err)
	}
	prof, ok := set.Profiles[profile]
	if !ok {
		return nil, nil, fmt.Errorf("profile %q not found", profile)
	}
	httpChain := func(host string) ([]chain.Filter, string, error) {
		svc := prof.MatchHTTP(host)
		if svc == nil {
			return nil, "", fmt.Errorf("no service in profile %s matches %s (it would be %sed)", prof.Name, host, prof.Unmatched)
		}
		return svc.Filters, svc.Config.Name, nil
	}
	sshChain := func(host string) ([]chain.Filter, string, error) {
		svc := prof.MatchSSH(host)
		if svc == nil {
			return nil, "", fmt.Errorf("no ssh service in profile %s matches %s", prof.Name, host)
		}
		return svc.Filters, svc.Config.Name, nil
	}
	return httpChain, sshChain, nil
}

func runStep(c *Step, httpChain, sshChain chainFunc, profile string, ap *scriptedApprover) (string, error) {
	sess := &chain.Session{ID: harnessName, Label: harnessName, Profile: profile}
	var req *chain.Request
	var filters []chain.Filter
	var upstreamHeader http.Header
	terminal := func(r *chain.Request) (*chain.Response, error) {
		upstreamHeader = r.Header
		if r.Transport == chain.TransportSSH {
			return chain.Allowed(), nil
		}
		up := c.Upstream
		if up == nil {
			up = &Upstream{Status: 200, Body: "upstream ok"}
		}
		h := http.Header{}
		for k, v := range up.Headers {
			h.Set(k, v)
		}
		status := up.Status
		if status == 0 {
			status = 200
		}
		return &chain.Response{Status: status, Header: h, Body: chain.BytesBody([]byte(up.Body))}, nil
	}

	switch {
	case c.Request != nil:
		u, err := url.Parse(c.Request.URL)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("bad request url %q", c.Request.URL)
		}
		hostport := u.Host
		if u.Port() == "" {
			port := "443"
			if u.Scheme == "http" {
				port = "80"
			}
			hostport += ":" + port
		}
		var service string
		filters, service, err = httpChain(hostport)
		if err != nil {
			return "", err
		}
		method := c.Request.Method
		if method == "" {
			method = http.MethodGet
		}
		body := []byte(c.Request.Body)
		if len(c.Request.GitPush) > 0 {
			body = buildPush(c.Request.GitPush)
		}
		h := http.Header{}
		for k, v := range c.Request.Headers {
			h.Set(k, v)
		}
		req = &chain.Request{Ctx: context.Background(), Transport: chain.TransportHTTP, Session: sess, Profile: profile,
			Service: service, Method: method, URL: u, Header: h, Body: chain.BytesBody(body)}
		err = chain.CheckMethod(method)
		if err == nil {
			err = chain.CheckPath(u.Path)
		}
		if err == nil {
			err = chain.CheckMethodOverride(req)
		}
		if err != nil {
			return check(c, chain.Deny("bouncer", err.Error()), ap, nil)
		}
	case c.SSH != nil:
		var service string
		var err error
		filters, service, err = sshChain(c.SSH.Host)
		if err != nil {
			return "", err
		}
		info := &chain.SSHInfo{Host: c.SSH.Host, User: c.SSH.User, Kind: c.SSH.Kind, Command: c.SSH.Command, Subsystem: c.SSH.Subsystem, Target: c.SSH.Target}
		req = &chain.Request{Ctx: context.Background(), Transport: chain.TransportSSH, Session: sess, Profile: profile, Service: service, SSH: info}
		if info.Kind == "" {
			switch {
			case info.Command != "" && req.Git() != nil:
				info.Kind = config.SSHKindGit
			case info.Command != "":
				info.Kind = config.SSHKindExec
			case info.Subsystem == "sftp":
				info.Kind = config.SSHKindSFTP
			case info.Target != "":
				info.Kind = config.SSHKindForward
			default:
				info.Kind = config.SSHKindShell
			}
		}
		if len(c.SSH.GitPush) > 0 {
			req.Body = chain.BytesBody(buildPush(c.SSH.GitPush))
		}
	default:
		return "", errors.New("step needs a request or ssh key")
	}

	resp, _ := chain.Build(filters, terminal)(req)
	return check(c, resp, ap, upstreamHeader)
}

func check(c *Step, resp *chain.Response, ap *scriptedApprover, upstreamHeader http.Header) (string, error) {
	var problems []string
	got := "allow"
	if resp.Denial != nil {
		got = "deny"
	}
	if c.Expect != "" && c.Expect != got {
		detail := ""
		if resp.Denial != nil {
			detail = fmt.Sprintf(" (by %s: %s)", resp.Denial.By, resp.Denial.Reason)
		}
		problems = append(problems, fmt.Sprintf("expected %s, got %s%s", c.Expect, got, detail))
	}
	if c.ExpectReason != "" && (resp.Denial == nil || !strings.Contains(resp.Denial.Reason, c.ExpectReason)) {
		reason := "<none>"
		if resp.Denial != nil {
			reason = resp.Denial.Reason
		}
		problems = append(problems, fmt.Sprintf("expected reason containing %q, got %q", c.ExpectReason, reason))
	}
	if c.ExpectStatus != 0 && resp.Status != c.ExpectStatus {
		problems = append(problems, fmt.Sprintf("expected status %d, got %d", c.ExpectStatus, resp.Status))
	}
	if len(c.ExpectBodyContains) > 0 || len(c.ExpectBodyExcludes) > 0 {
		var body []byte
		if resp.Body != nil {
			body, _ = io.ReadAll(resp.Body.Reader())
		}
		for _, s := range c.ExpectBodyContains {
			if !bytes.Contains(body, []byte(s)) {
				problems = append(problems, fmt.Sprintf("body does not contain %q: %q", s, body))
			}
		}
		for _, s := range c.ExpectBodyExcludes {
			if bytes.Contains(body, []byte(s)) {
				problems = append(problems, fmt.Sprintf("body contains %q: %q", s, body))
			}
		}
	}
	if c.ExpectAsked != nil && *c.ExpectAsked != ap.asked {
		problems = append(problems, fmt.Sprintf("expected asked=%v, got %v", *c.ExpectAsked, ap.asked))
	}
	for k, v := range c.ExpectUpstreamHeader {
		if upstreamHeader == nil || upstreamHeader.Get(k) != v {
			got := ""
			if upstreamHeader != nil {
				got = upstreamHeader.Get(k)
			}
			problems = append(problems, fmt.Sprintf("expected upstream header %s=%q, got %q", k, v, got))
		}
	}
	return strings.Join(problems, "; "), nil
}

const (
	oidA = "1111111111111111111111111111111111111111"
	oidB = "2222222222222222222222222222222222222222"
)

func buildPush(refs []PushRef) []byte {
	var ups []gitproto.RefUpdate
	for _, r := range refs {
		u := gitproto.RefUpdate{Ref: r.Ref, OldOID: oidA, NewOID: oidB}
		switch r.Type {
		case "create":
			u.OldOID = gitproto.ZeroOID
		case "delete":
			u.NewOID = gitproto.ZeroOID
		}
		ups = append(ups, u)
	}
	return gitproto.BuildPush(ups, []string{"report-status", "side-band-64k"}, nil)
}

type scriptedApprover struct {
	answer bool
	asked  bool
}

func (a *scriptedApprover) Ask(context.Context, chain.AskRequest) (bool, error) {
	a.asked = true
	return a.answer, nil
}
