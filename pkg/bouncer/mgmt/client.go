// Package mgmt is the HTTP client for a running bouncer's control API.
package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

// DefaultTimeout bounds each call when New is given no WithTimeout.
const DefaultTimeout = 5 * time.Second

// Client talks to /_bouncer/ on a running daemon.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout bounds each call. The call's context can end it sooner.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.http.Timeout = d }
}

// New talks to the control API at baseURL, such as http://127.0.0.1:8228.
// token is the daemon's admin token. It may be empty and set later with
// SetToken.
func New(baseURL, token string, opts ...Option) *Client {
	c := &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		http: &http.Client{
			Timeout:   DefaultTimeout,
			Transport: &http.Transport{Proxy: nil},
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// SetToken replaces the admin token used for subsequent calls.
func (c *Client) SetToken(token string) {
	c.token = token
}

// Status is the daemon's GET /_bouncer/status payload.
type Status struct {
	Config         string   `json:"config"`
	Profiles       []string `json:"profiles"`
	DefaultProfile string   `json:"default_profile"`
	Sessions       int      `json:"sessions"`
	PendingPrompts int      `json:"pending_prompts"`
	CA             string   `json:"ca"`
	CABundle       string   `json:"ca_bundle"`
	// Ready means the startup credential preparation finished. Error holds
	// its failure, and Ready is false when Error is set.
	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`
}

// Trust is the daemon's GET /_bouncer/ca payload.
type Trust struct {
	// CertPEM is the bouncer CA alone.
	CertPEM string `json:"cert_pem"`
	// BundlePEM is the system roots plus the bouncer CA.
	BundlePEM string `json:"bundle_pem"`
	// SSHKnownHosts trusts the bouncer SSH CA for the configured SSH hosts.
	SSHKnownHosts string `json:"ssh_known_hosts"`
}

// SessionRecord is a registered agent session.
type SessionRecord struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Profile string `json:"profile"`
	// Token is the session's proxy credential. Treat it as a secret.
	// Only CreateSession returns it. Sessions leaves it empty.
	Token   string    `json:"token"`
	Created time.Time `json:"created"`
	// Expires is zero for sessions that last until revoked.
	Expires time.Time `json:"expires,omitzero"`
}

// NewSession is the reply to session creation: everything needed to build
// the agent's environment without parsing the policy.
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

// Status reports the daemon's policy, sessions, and startup state.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.do(ctx, http.MethodGet, "/_bouncer/status", nil, &st)
	return st, err
}

// Trust returns the CA material the agent needs to trust the bouncer.
func (c *Client) Trust(ctx context.Context) (Trust, error) {
	var t Trust
	err := c.do(ctx, http.MethodGet, "/_bouncer/ca", nil, &t)
	return t, err
}

// Sessions lists the registered sessions.
func (c *Client) Sessions(ctx context.Context) ([]SessionRecord, error) {
	var list []SessionRecord
	err := c.do(ctx, http.MethodGet, "/_bouncer/sessions", nil, &list)
	return list, err
}

// CreateSession registers a session. Empty profile means the default
// profile, and empty ttl means until revoked.
func (c *Client) CreateSession(ctx context.Context, id, profile, label, ttl string) (NewSession, error) {
	var rec NewSession
	err := c.do(ctx, http.MethodPost, "/_bouncer/sessions", map[string]string{
		"id":      id,
		"profile": profile,
		"label":   label,
		"ttl":     ttl,
	}, &rec)
	return rec, err
}

// EndSession revokes a session.
func (c *Client) EndSession(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/_bouncer/sessions/"+url.PathEscape(id), nil, nil)
}

// PutEnv replaces the daemon's source: env overlay. An empty map clears it.
func (c *Client) PutEnv(ctx context.Context, vars map[string]string) error {
	return c.do(ctx, http.MethodPut, "/_bouncer/credentials/sources/env", nonNil(vars), nil)
}

// PutProvided replaces host-resolved secrets (file, keyring, command,
// provided) keyed by credential name. An empty map clears them.
func (c *Client) PutProvided(ctx context.Context, values map[string]string) error {
	return c.do(ctx, http.MethodPut, "/_bouncer/credentials/provided", nonNil(values), nil)
}

// nonNil sends a nil map as {} rather than null.
func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// Reload reloads the daemon's policy.
func (c *Client) Reload(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/_bouncer/reload", nil, nil)
}

// Prompts lists the questions waiting on a human answer.
func (c *Client) Prompts(ctx context.Context) ([]prompt.Pending, error) {
	var list []prompt.Pending
	err := c.do(ctx, http.MethodGet, "/_bouncer/prompts", nil, &list)
	return list, err
}

// AnswerPrompt settles a pending prompt.
func (c *Client) AnswerPrompt(ctx context.Context, id string, a prompt.Answer) error {
	return c.do(ctx, http.MethodPost, "/_bouncer/prompts/"+url.PathEscape(id), struct {
		Allow    bool   `json:"allow"`
		Remember bool   `json:"remember"`
		Value    string `json:"value,omitempty"`
	}{a.Allow, a.Remember, a.Value}, nil)
}

// DeclinePrompt settles a pending prompt without an answer.
func (c *Client) DeclinePrompt(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/_bouncer/prompts/"+url.PathEscape(id), nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("contacting bouncer at %s: %w", c.base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s", strings.TrimSpace(string(msg)))
	}
	if out != nil {
		err = json.NewDecoder(resp.Body).Decode(out)
		if err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
