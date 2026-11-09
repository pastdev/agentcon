// Package mgmt is the HTTP client for a running bouncer's control API.
package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/pastdev/agentcon/internal/bouncer/running"
)

const (
	sidecarTimeout = 5 * time.Second
	cliTimeout     = 30 * time.Second
)

// Client talks to /_bouncer/ on a running daemon.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New talks to an already-known control address.
// token may be empty and filled later with SetToken or ReloadToken.
func New(baseURL, token string) *Client {
	return newClient(baseURL, token, sidecarTimeout)
}

func newClient(baseURL, token string, timeout time.Duration) *Client {
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{Proxy: nil},
		},
	}
}

// LoadToken reads the admin token from the state directory.
func LoadToken(stateDir string) string {
	b, err := os.ReadFile(daemon.AdminTokenPath(stateDir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SetToken replaces the bearer token used for subsequent calls.
func (c *Client) SetToken(token string) {
	c.token = token
}

// ReloadToken reads the admin token from stateDir, ignoring read errors.
func (c *Client) ReloadToken(stateDir string) {
	c.token = LoadToken(stateDir)
}

// DialContext prefers a matching running record, then Dial(stateDir, configPath).
func DialContext(home string, q running.Query, stateDir, configPath string) (*Client, error) {
	if home != "" {
		rec, err := running.Find(home, q)
		if err == nil {
			return newClient("http://"+rec.ControlAddr, rec.Token, cliTimeout), nil
		}
		var amb *running.AmbiguousError
		if errors.As(err, &amb) || (stateDir == "" && configPath == "") {
			return nil, fmt.Errorf("find session: %w", err)
		}
	}
	return Dial(stateDir, configPath)
}

// Dial locates a running daemon from stateDir (host.json, daemon.json) or
// the policy file's listen address, and requires an admin token on disk.
func Dial(stateDir, _ string) (*Client, error) {
	addr, err := locate(stateDir)
	if err != nil {
		return nil, err
	}
	tok, err := os.ReadFile(daemon.AdminTokenPath(stateDir))
	if err != nil {
		return nil, fmt.Errorf("reading admin token (has `agentcon bouncer serve` run yet?): %w", err)
	}
	return newClient("http://"+addr, strings.TrimSpace(string(tok)), cliTimeout), nil
}

func locate(stateDir string) (string, error) {
	if b, err := os.ReadFile(filepath.Join(stateDir, "host.json")); err == nil { //nolint:gosec // path from operator config or the state dir, not the agent
		var host struct {
			ControlAddr string `json:"control_addr"`
		}
		if json.Unmarshal(b, &host) == nil && host.ControlAddr != "" {
			return host.ControlAddr, nil
		}
	}
	var rt daemon.Runtime
	if b, err := os.ReadFile(daemon.RuntimePath(stateDir)); err == nil && json.Unmarshal(b, &rt) == nil {
		if rt.MgmtAddr != "" {
			return rt.MgmtAddr, nil
		}
		if rt.ProxyAddr != "" {
			return rt.ProxyAddr, nil
		}
	}
	return "", fmt.Errorf("bouncer doesn't appear to be running (no %s)", daemon.RuntimePath(stateDir))
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
	// its failure.
	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`
}

func (c *Client) Status() (Status, error) {
	var st Status
	err := c.do(http.MethodGet, "/_bouncer/status", nil, &st)
	return st, err
}

// Prompts lists the questions waiting on a human answer.
func (c *Client) Prompts() ([]prompt.Pending, error) {
	var list []prompt.Pending
	err := c.do(http.MethodGet, "/_bouncer/prompts", nil, &list)
	return list, err
}

// AnswerPrompt settles a pending prompt.
func (c *Client) AnswerPrompt(id string, a prompt.Answer) error {
	return c.do(http.MethodPost, "/_bouncer/prompts/"+url.PathEscape(id), struct {
		Allow    bool   `json:"allow"`
		Remember bool   `json:"remember"`
		Value    string `json:"value,omitempty"`
	}{a.Allow, a.Remember, a.Value}, nil)
}

// DeclinePrompt settles a pending prompt without an answer.
func (c *Client) DeclinePrompt(id string) error {
	return c.do(http.MethodDelete, "/_bouncer/prompts/"+url.PathEscape(id), nil, nil)
}

func (c *Client) Sessions() ([]daemon.SessionRecord, error) {
	var list []daemon.SessionRecord
	err := c.do(http.MethodGet, "/_bouncer/sessions", nil, &list)
	return list, err
}

func (c *Client) EndSession(id string) error {
	return c.do(http.MethodDelete, "/_bouncer/sessions/"+id, nil, nil)
}

func (c *Client) CreateSession(id, profile, label, ttl string) (daemon.NewSession, error) {
	var rec daemon.NewSession
	err := c.do(http.MethodPost, "/_bouncer/sessions", map[string]string{
		"id":      id,
		"profile": profile,
		"label":   label,
		"ttl":     ttl,
	}, &rec)
	return rec, err
}

func (c *Client) Reload() error {
	return c.do(http.MethodPost, "/_bouncer/reload", nil, nil)
}

// PutEnv replaces the daemon's source: env overlay.
func (c *Client) PutEnv(vars map[string]string) error {
	if len(vars) == 0 {
		return nil
	}
	return c.do(http.MethodPut, "/_bouncer/credentials/sources/env", vars, nil)
}

// PutProvided replaces host-resolved secrets (file, keyring, command,
// provided) keyed by credential name.
func (c *Client) PutProvided(values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	return c.do(http.MethodPut, "/_bouncer/credentials/provided", values, nil)
}

// Trust is GET /_bouncer/ca.
type Trust struct {
	CertPEM       string `json:"cert_pem"`
	BundlePEM     string `json:"bundle_pem"`
	SSHKnownHosts string `json:"ssh_known_hosts"`
}

func (c *Client) Trust() (Trust, error) {
	var t Trust
	err := c.do(http.MethodGet, "/_bouncer/ca", nil, &t)
	return t, err
}

func (c *Client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("contacting bouncer at %s (is `agentcon bouncer serve` running?): %w", c.base, err)
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
