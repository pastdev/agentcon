// Package creds fetches secrets from their configured sources.
package creds

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/pastdev/agentcon/internal/bouncer/creds/bitwarden"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// KeyringService is the service name under which secrets are stored in the OS keyring.
const KeyringService = "agent-bouncer"

const commandTimeout = 60 * time.Second

// Store resolves credentials by name, caching per each credential's TTL.
type Store struct {
	mu    sync.Mutex
	creds map[string]*config.Credential
	cache map[string]cached
	// fetch serializes concurrent fetches per credential so an interactive
	// command (e.g. a password manager unlock) only runs once.
	fetch map[string]*sync.Mutex
	// provided holds values given at daemon start. They take
	// precedence over each credential's configured source and survive reloads.
	provided map[string]string
	// env is an overlay for source: env lookups. agentcon run PUTs host
	// values here so the sidecar does not need those variables in its
	// process environment. An empty overlay falls through to os.LookupEnv.
	env map[string]string
}

type cached struct {
	value   string
	expires time.Time
}

// Secret is the resolved slots of one credential.
type Secret struct {
	Username    string
	Password    string
	Token       string
	PrivateKey  string
	Certificate string
}

// HTTP is the value used for bearer, header, query, and placeholder
// substitution: Token, else Password.
func (s Secret) HTTP() string {
	if s.Token != "" {
		return s.Token
	}
	return s.Password
}

// BasicUser is inject.basic username: YAML override, else Username.
func (s Secret) BasicUser(override string) string {
	if override != "" {
		return override
	}
	return s.Username
}

// BasicPass is inject.basic password: Password, else Token.
func (s Secret) BasicPass() string {
	if s.Password != "" {
		return s.Password
	}
	return s.Token
}

func (s *Secret) set(slot, v string) {
	switch slot {
	case config.SlotUsername:
		s.Username = v
	case config.SlotPassword:
		s.Password = v
	case config.SlotToken:
		s.Token = v
	case config.SlotPrivateKey:
		s.PrivateKey = v
	case config.SlotCertificate:
		s.Certificate = v
	}
}

func NewStore(creds map[string]*config.Credential) *Store {
	return &Store{
		creds:    creds,
		cache:    map[string]cached{},
		fetch:    map[string]*sync.Mutex{},
		provided: map[string]string{},
		env:      map[string]string{},
	}
}

// SetProvided installs startup-provided secrets, replacing any set before.
// Empty keys and values are ignored. The fetch cache is cleared.
func (s *Store) SetProvided(values map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.provided = map[string]string{}
	for k, v := range values {
		if k == "" || v == "" {
			continue
		}
		s.provided[k] = v
	}
	s.cache = map[string]cached{}
}

// SetEnv replaces the source: env overlay. Keys are environment variable
// names. Empty keys and values are ignored.
func (s *Store) SetEnv(vars map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.env = map[string]string{}
	for k, v := range vars {
		if k == "" || v == "" {
			continue
		}
		s.env[k] = v
	}
	s.cache = map[string]cached{}
}

func (s *Store) lookupEnv(name string) (string, bool) {
	s.mu.Lock()
	v, ok := s.env[name]
	s.mu.Unlock()
	if ok {
		return v, true
	}
	return os.LookupEnv(name)
}

func (s *Store) providedValue(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.provided[name]
	return v, ok
}

// MissingProvided lists credential slots with source: provided that have no
// startup value. Names are credential.slot.
func (s *Store) MissingProvided() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for name, c := range s.creds {
		if c == nil {
			continue
		}
		for _, slot := range c.Slots() {
			if slot.Source.Source != "provided" {
				continue
			}
			key := config.ProvidedKey(name, slot.Name)
			if _, ok := s.provided[key]; !ok {
				out = append(out, key)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ConfigureBitwarden sets where the process stores its Bitwarden device id
// and refresh token, where unlock progress is logged, and the broker that
// asks a human for master passwords and verification codes. The decrypted
// vault is kept in memory only. Call this before the first fetch.
func ConfigureBitwarden(stateDir string, log zerolog.Logger, prompts *prompt.Broker) {
	bitwarden.Configure(bitwarden.Options{StateDir: stateDir, Log: log, Prompt: bitwarden.BrokerPrompter(prompts)})
}

// Prepare unlocks every Bitwarden vault the credential set uses, so the
// master password is asked for when the config loads rather than
// mid-request. It blocks until each vault is unlocked or fails. Vaults stay
// unlocked until the process exits.
func (s *Store) Prepare(ctx context.Context, creds map[string]*config.Credential) error {
	var accounts []bitwarden.Account
	for _, c := range creds {
		if c == nil {
			continue
		}
		for _, slot := range c.Slots() {
			src := slot.Source
			if src == nil || src.Source != "bitwarden" {
				continue
			}
			accounts = append(accounts, bitwarden.Account{
				Email:       src.Email,
				Server:      src.Server,
				PasswordEnv: src.PasswordEnv,
			})
		}
	}
	if len(accounts) == 0 {
		return nil
	}
	err := bitwarden.Unlock(ctx, accounts)
	if err != nil {
		return fmt.Errorf("bitwarden unlock: %w", err)
	}
	return nil
}

// Update swaps in a new credential set (on config reload), dropping cache
// entries whose definition changed.
func (s *Store) Update(creds map[string]*config.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, old := range s.creds {
		nw, ok := creds[name]
		if !ok || old == nil || nw == nil || fmt.Sprint(*nw) != fmt.Sprint(*old) {
			s.dropCached(name, old)
		}
	}
	s.creds = creds
}

func (s *Store) dropCached(name string, c *config.Credential) {
	if c == nil {
		return
	}
	for _, slot := range c.Slots() {
		delete(s.cache, config.ProvidedKey(name, slot.Name))
	}
}

func (s *Store) lookup(name string) (*config.Credential, *sync.Mutex, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[name]
	if !ok {
		return nil, nil, fmt.Errorf("unknown credential %q", name)
	}
	m, ok := s.fetch[name]
	if !ok {
		m = &sync.Mutex{}
		s.fetch[name] = m
	}
	return c, m, nil
}

// Get returns the resolved slots for a credential.
func (s *Store) Get(ctx context.Context, name string) (Secret, error) {
	c, m, err := s.lookup(name)
	if err != nil {
		return Secret{}, err
	}
	m.Lock()
	defer m.Unlock()
	var out Secret
	for _, slot := range c.Slots() {
		if slot.Source.Source == "ssh-agent" {
			continue
		}
		v, err := s.slotValue(ctx, c, slot)
		if err != nil {
			return Secret{}, fmt.Errorf("credential %q %s: %w", name, slot.Name, err)
		}
		out.set(slot.Name, v)
	}
	return out, nil
}

// GetSlot returns one named slot.
func (s *Store) GetSlot(ctx context.Context, name, slotName string) (string, error) {
	c, m, err := s.lookup(name)
	if err != nil {
		return "", err
	}
	src := c.Slot(slotName)
	if src == nil {
		return "", fmt.Errorf("credential %q has no %s", name, slotName)
	}
	m.Lock()
	defer m.Unlock()
	v, err := s.slotValue(ctx, c, config.Slot{Name: slotName, Source: src})
	if err != nil {
		return "", fmt.Errorf("credential %q %s: %w", name, slotName, err)
	}
	return v, nil
}

func (s *Store) slotValue(ctx context.Context, c *config.Credential, slot config.Slot) (string, error) {
	key := config.ProvidedKey(c.Name, slot.Name)
	if v, ok := s.providedValue(key); ok {
		return v, nil
	}
	cacheKey := key
	s.mu.Lock()
	if e, ok := s.cache[cacheKey]; ok && time.Now().Before(e.expires) {
		s.mu.Unlock()
		return e.value, nil
	}
	s.mu.Unlock()

	v, err := s.fetchValue(ctx, c.Name, slot.Source)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", errors.New("empty secret")
	}
	if ttl := c.CacheTTL(); ttl > 0 {
		s.mu.Lock()
		s.cache[cacheKey] = cached{value: v, expires: time.Now().Add(ttl)}
		s.mu.Unlock()
	}
	return v, nil
}

func (s *Store) fetchValue(ctx context.Context, credName string, src *config.ValueSource) (string, error) {
	raw, err := s.fetchPayload(ctx, credName, src)
	if err != nil {
		return "", err
	}
	return extractJSONPath([]byte(raw), src.Path)
}

func (s *Store) fetchPayload(ctx context.Context, credName string, src *config.ValueSource) (string, error) {
	switch src.Source {
	case "keyring":
		acct := src.KeyringAccount(credName)
		v, err := keyring.Get(KeyringService, acct)
		if errors.Is(err, keyring.ErrNotFound) {
			return "", fmt.Errorf("not in keyring (account %s)", acct)
		}
		if err != nil {
			return "", fmt.Errorf("keyring: %w", err)
		}
		return v, nil
	case "env":
		v, ok := s.lookupEnv(src.Env)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set in the bouncer daemon", src.Env)
		}
		return v, nil
	case "file":
		b, err := os.ReadFile(src.File)
		if err != nil {
			return "", fmt.Errorf("credential file: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	case "provided":
		return "", errors.New("no value provided at daemon start")
	case "command":
		ctx, cancel := context.WithTimeout(ctx, commandTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, src.Command[0], src.Command[1:]...) //nolint:gosec // command source runs what the operator configured
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return "", fmt.Errorf("%s: %w: %s", src.Command[0], err, msg)
			}
			return "", fmt.Errorf("%s: %w", src.Command[0], err)
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	case "bitwarden":
		raw, err := bitwarden.ItemJSON(ctx, bitwarden.Query{
			Account: bitwarden.Account{Email: src.Email, Server: src.Server, PasswordEnv: src.PasswordEnv},
			Item:    src.Item,
			Folder:  src.Folder,
		})
		if err != nil {
			return "", fmt.Errorf("bitwarden item: %w", err)
		}
		return string(raw), nil
	}
	return "", fmt.Errorf("unsupported source %q", src.Source)
}

// SSHSigners returns signers for an SSH credential: the parsed private key
// for secret-bearing sources, or keys from the running ssh-agent.
func (s *Store) SSHSigners(ctx context.Context, name string) ([]ssh.Signer, error) {
	c, _, err := s.lookup(name)
	if err != nil {
		return nil, err
	}
	src := c.PrivateKey
	if src == nil {
		return nil, fmt.Errorf("credential %q: no private_key", name)
	}
	if src.Source == "ssh-agent" {
		if _, ok := s.providedValue(config.ProvidedKey(name, config.SlotPrivateKey)); !ok {
			return agentSigners(c.Name, src)
		}
	}
	pem, err := s.GetSlot(ctx, name, config.SlotPrivateKey)
	if err != nil {
		return nil, err
	}
	if pem == "" {
		return nil, fmt.Errorf("credential %q: empty private_key", name)
	}
	signer, err := ssh.ParsePrivateKey([]byte(pem + "\n"))
	if err != nil {
		return nil, fmt.Errorf("credential %q: not a usable SSH private key (passphrase-protected keys must use source: ssh-agent): %w", name, err)
	}
	return []ssh.Signer{signer}, nil
}

func agentSigners(name string, src *config.ValueSource) ([]ssh.Signer, error) {
	conn, err := dialAgent()
	if err != nil {
		return nil, fmt.Errorf("credential %q: connecting to ssh-agent: %w", name, err)
	}
	// The connection must stay open while the signers are in use; it is
	// released when the process exits or the agent hangs up.
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh-agent signers: %w", err)
	}
	if src.Fingerprint == "" {
		return signers, nil
	}
	for _, sg := range signers {
		if ssh.FingerprintSHA256(sg.PublicKey()) == src.Fingerprint {
			return []ssh.Signer{sg}, nil
		}
	}
	_ = conn.Close()
	return nil, fmt.Errorf("credential %q: no agent key with fingerprint %s", name, src.Fingerprint)
}
