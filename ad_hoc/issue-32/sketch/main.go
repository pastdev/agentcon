//go:build issue32

// Command sketch walks the bouncer host lifecycle with public packages only.
// Creating the sidecar and agent containers is the embedder's job, so this
// talks to an already running `agentcon bouncer serve` and writes the agent
// payload and environment to files instead of into a container.
//
//	go run -tags issue32 ./ad_hoc/issue-32/sketch \
//	  -policy config.yaml -url http://127.0.0.1:8228 -token "$(cat state/admin-token)" \
//	  -binary "$(command -v agentcon)" -out /tmp/sketch
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/bouncer/crederr"
	"github.com/pastdev/agentcon/pkg/bouncer/host"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncertest"
)

func main() {
	policyPath := flag.String("policy", "", "materialized bouncer policy file")
	tests := flag.String("tests", "", "optional tests directory to run first")
	baseURL := flag.String("url", "http://127.0.0.1:8228", "management API")
	token := flag.String("token", "", "admin token")
	binary := flag.String("binary", "", "linux agentcon for the agent payload")
	out := flag.String("out", "", "directory for agent.tar and agent.env")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	err := run(ctx, *policyPath, *tests, *baseURL, *token, *binary, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sketch:", err)
		// Only the operator sees this.
		stderr := crederr.Stderr(err)
		if stderr != "" {
			fmt.Fprintf(os.Stderr, "credential command stderr:\n%s\n", stderr)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, policyPath, tests, baseURL, token, binary, out string) error {
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}

	// Compile every filter, as `agentcon bouncer check` does.
	cfg, err := bouncercfg.Parse(policy, policyPath)
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	check, err := host.Check(cfg)
	if err != nil {
		return fmt.Errorf("check: %w", err)
	}
	for _, p := range check.Profiles {
		fmt.Printf("profile %s: %d http, %d ssh, unmatched=%s\n", p.Name, p.HTTP, p.SSH, p.Unmatched)
	}

	if tests != "" {
		dir, err := os.MkdirTemp("", "sketch-tests-")
		if err != nil {
			return fmt.Errorf("temp dir: %w", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()
		report, err := bouncertest.Run(bouncertest.Suite{PolicyYAML: policy, TestsDir: tests}, dir)
		if err != nil {
			return fmt.Errorf("policy tests: %w", err)
		}
		err = bouncertest.WriteTAP(os.Stdout, report)
		if err != nil {
			return fmt.Errorf("print results: %w", err)
		}
		if failed := report.Failed(); failed > 0 {
			return fmt.Errorf("%d policy tests failed", failed)
		}
	}

	// Fail before any slow setup when nothing could answer a prompt.
	err = host.CheckPromptable(policy)
	if err != nil {
		return fmt.Errorf("bouncer policy: %w", err)
	}
	creds, err := host.PrepareCredentials(ctx, host.CredentialOptions{
		Policy: policy,
		Stdin:  os.Stdin,
		Stderr: os.Stderr,
	})
	if err != nil {
		return fmt.Errorf("prepare credentials: %w", err)
	}
	if creds.SSHAuthSock != "" {
		fmt.Printf("bind %s at %s in the sidecar\n", creds.SSHAuthSock, host.SidecarSSHAuthSock)
	}

	// The embedder creates and starts the sidecar here.

	c := mgmt.New(baseURL, token)
	err = c.PutEnv(ctx, creds.Env)
	if err != nil {
		return fmt.Errorf("put env: %w", err)
	}
	err = c.PutProvided(ctx, creds.Provided)
	if err != nil {
		return fmt.Errorf("put provided: %w", err)
	}
	prompts := host.PromptOptions{Stdin: os.Stdin, Stderr: os.Stderr}
	err = host.WaitReady(ctx, c, prompts)
	if err != nil {
		return fmt.Errorf("wait ready: %w", err)
	}

	session, err := c.CreateSession(ctx, "", "", "sketch", "1h")
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer func() { _ = c.EndSession(context.WithoutCancel(ctx), session.ID) }()
	trust, err := c.Trust(ctx)
	if err != nil {
		return fmt.Errorf("trust: %w", err)
	}

	layout := host.DefaultAgentLayout()
	err = os.MkdirAll(out, 0o700)
	if err != nil {
		return fmt.Errorf("out dir: %w", err)
	}
	tarFile, err := os.Create(filepath.Join(out, "agent.tar"))
	if err != nil {
		return fmt.Errorf("agent tar: %w", err)
	}
	err = host.WriteAgentPayload(tarFile, host.AgentPayload{Layout: layout, Binary: binary, Trust: trust, UID: os.Getuid(), GID: os.Getgid()})
	err = errors.Join(err, tarFile.Close())
	if err != nil {
		return fmt.Errorf("agent payload: %w", err)
	}
	// The agent reaches the sidecar at its address on the agent network.
	// The embedder knows it, so this reuses the management host.
	addr := strings.TrimPrefix(strings.TrimPrefix(baseURL, "http://"), "https://")
	env, err := host.AgentEnv(layout, session, addr, session.SSHAddr)
	if err != nil {
		return fmt.Errorf("agent env: %w", err)
	}
	err = os.WriteFile(filepath.Join(out, "agent.env"), []byte(strings.Join(env, "\n")+"\n"), 0o600)
	if err != nil {
		return fmt.Errorf("agent env file: %w", err)
	}

	// The embedder starts the agent here. Report prompts until it exits.
	notifyCtx, stopNotify := context.WithCancel(ctx)
	defer stopNotify()
	go host.NotifyPrompts(notifyCtx, c, host.PromptOptions{Stderr: os.Stderr, Hint: host.AgentconHint})

	fmt.Printf("session %s ready; wrote %s\n", session.ID, out)
	return nil
}
