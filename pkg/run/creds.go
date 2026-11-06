package run

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/pastdev/agentcon/internal/bouncer/creds"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"gopkg.in/yaml.v3"
)

const sidecarSSHAuthSock = "/opt/agentcon/ssh-agent.sock"

func hostProvidedCreds(ctx context.Context, policy []byte, extra map[string]string) (map[string]string, error) {
	cfg, err := parsePolicyCredentials(policy)
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

func hostSSHAuthSock(policy []byte) (string, error) {
	cfg, err := parsePolicyCredentials(policy)
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

func parsePolicyCredentials(policy []byte) (bouncercfg.Config, error) {
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
