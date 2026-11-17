// Package host prepares a bouncer sidecar from the host: it resolves the
// credentials the sidecar cannot reach, answers its prompts, and lays out the
// files the agent container needs.
package host

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/creds"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"gopkg.in/yaml.v3"
)

// SidecarSSHAuthSock is where the sidecar expects the host ssh-agent socket
// that Credentials.SSHAuthSock names.
const SidecarSSHAuthSock = "/opt/agentcon/ssh-agent.sock"

// CredentialOptions are the inputs to PrepareCredentials.
type CredentialOptions struct {
	// Policy is the materialized policy YAML.
	Policy []byte
	// Env is NAME=value pairs that override the host environment for
	// source: env credentials.
	Env []string
	// Provided holds values the caller already has, keyed by
	// config.ProvidedKey from pkg/bouncer/config.
	Provided map[string]string
	// Stdin is read for SSH key passphrases. It must be a terminal to prompt.
	Stdin io.Reader
	// Stderr receives the passphrase prompt. Nil discards it.
	Stderr io.Writer
}

// Credentials are the host-resolved values for a sidecar.
type Credentials struct {
	// Env is sent with mgmt.Client.PutEnv.
	Env map[string]string
	// Provided is sent with mgmt.Client.PutProvided. SSH keys are decrypted.
	Provided map[string]string
	// SSHAuthSock is the host socket to bind at SidecarSSHAuthSock, or ""
	// when no credential uses source: ssh-agent.
	SSHAuthSock string
}

// PrepareCredentials resolves what the sidecar cannot: source: env values,
// file, keyring, command, and provided sources, SSH key passphrases, and the
// ssh-agent socket. It calls CheckPromptable first.
//
// It never changes o.Env or o.Provided. On error it returns a zero
// Credentials, and the error text holds no secret values. A failed
// source: command carries its stderr in a crederr.CommandError, for the
// operator only.
func PrepareCredentials(ctx context.Context, o CredentialOptions) (Credentials, error) {
	err := CheckPromptable(o.Policy)
	if err != nil {
		return Credentials{}, fmt.Errorf("bouncer policy: %w", err)
	}
	env, err := envCreds(o.Policy, o.Env)
	if err != nil {
		return Credentials{}, fmt.Errorf("host env credentials: %w", err)
	}
	provided, err := providedCreds(ctx, o.Policy, o.Provided)
	if err != nil {
		return Credentials{}, fmt.Errorf("host credentials: %w", err)
	}
	sshNames, err := sshKeyCredentialNames(o.Policy)
	if err != nil {
		return Credentials{}, fmt.Errorf("ssh credentials: %w", err)
	}
	stderr := o.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	err = unlockHostSSHKeys(provided, sshNames, func(name string) (string, error) {
		return readSSHKeyPassphrase(ctx, o.Stdin, stderr, name)
	})
	if err != nil {
		return Credentials{}, fmt.Errorf("ssh key: %w", err)
	}
	sock, err := sshAuthSock(o.Policy)
	if err != nil {
		return Credentials{}, fmt.Errorf("ssh-agent: %w", err)
	}
	return Credentials{Env: env, Provided: provided, SSHAuthSock: sock}, nil
}

// CheckPromptable refuses a policy whose Bitwarden vaults need a master
// password that nothing could supply: the sidecar has no terminal, and
// prompts.cli: false stops the host from answering. PrepareCredentials
// calls it first. Call it earlier to fail before slow setup.
func CheckPromptable(policy []byte) error {
	cfg, err := parsePolicy(policy)
	if err != nil {
		return err
	}
	if cfg.Prompts.CLIEnabled() {
		return nil
	}
	var names []string
	for name, c := range cfg.Credentials {
		if c == nil {
			continue
		}
		for _, slot := range c.Slots() {
			if slot.Source != nil && slot.Source.Source == "bitwarden" && slot.Source.PasswordEnv == "" {
				names = append(names, name)
				break
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("credentials %s use bitwarden without password_env, and prompts.cli: false leaves nothing to ask for the master password",
		strings.Join(names, ", "))
}

func providedCreds(ctx context.Context, policy []byte, extra map[string]string) (map[string]string, error) {
	cfg, err := parsePolicy(policy)
	if err != nil {
		return nil, err
	}
	store := creds.NewStore(cfg.Credentials)
	store.SetProvided(extra)
	out := map[string]string{}
	for name, c := range cfg.Credentials {
		if c == nil {
			continue
		}
		for _, slot := range c.Slots() {
			switch slot.Source.Source {
			case "file", "keyring", "command", "provided":
			default:
				continue
			}
			key := bouncercfg.ProvidedKey(name, slot.Name)
			v, err := store.GetSlot(ctx, name, slot.Name)
			if err != nil {
				return nil, fmt.Errorf("host credential %s: %w", key, err)
			}
			out[key] = v
		}
	}
	return out, nil
}

func sshAuthSock(policy []byte) (string, error) {
	cfg, err := parsePolicy(policy)
	if err != nil {
		return "", err
	}
	var need bool
	for _, c := range cfg.Credentials {
		if c == nil {
			continue
		}
		for _, slot := range c.Slots() {
			if slot.Source.Source == "ssh-agent" {
				need = true
			}
		}
	}
	if !need {
		return "", nil
	}
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("source ssh-agent is not supported when running the sidecar on windows")
	}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return "", fmt.Errorf("SSH_AUTH_SOCK is not set (required for source ssh-agent)")
	}
	//nolint:gosec // SSH_AUTH_SOCK is the host agent socket the user already trusts
	_, err = os.Stat(sock)
	if err != nil {
		return "", fmt.Errorf("SSH_AUTH_SOCK %s: %w", sock, err)
	}
	return sock, nil
}

func parsePolicy(policy []byte) (bouncercfg.Config, error) {
	var cfg bouncercfg.Config
	err := yaml.Unmarshal(policy, &cfg)
	if err != nil {
		return bouncercfg.Config{}, fmt.Errorf("parse bouncer policy: %w", err)
	}
	err = cfg.Init()
	if err != nil {
		return bouncercfg.Config{}, fmt.Errorf("init bouncer policy: %w", err)
	}
	return cfg, nil
}
