package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/running"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/bouncertest"
	"github.com/pastdev/agentcon/pkg/run"
	"gopkg.in/yaml.v3"
)

// BouncerLayoutDir is the host folder-layer directory for a context.
func BouncerLayoutDir(home, context string) string {
	return filepath.Join(home, ".local", "state", "agentcon", running.FileName(context), "bouncer")
}

func (c *Config) MaterializeBouncer(contextName, bouncerName string, agent AgentSpec) (*run.BouncerSetup, error) {
	if bouncerName == "" {
		return nil, nil
	}
	doc, err := c.bouncerByName(bouncerName)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}

	policyDoc := withAgentTunnel(doc, agent.Tunnel)
	policy, err := yaml.Marshal(policyDoc)
	if err != nil {
		return nil, fmt.Errorf("encode bouncer config: %w", err)
	}
	overlayDirs := []string{}
	if c != nil {
		overlayDirs = c.OverlayDirs
	}
	policy = bouncercfg.RewriteTSPaths(policy, overlayDirs)
	files, err := bouncercfg.CollectTSFiles(overlayDirs)
	if err != nil {
		return nil, fmt.Errorf("collect ts files: %w", err)
	}

	return &run.BouncerSetup{
		ContextName: contextName,
		PolicyYAML:  policy,
		TSFiles:     files,
	}, nil
}

// WriteBouncer writes the folder-layer layout for a context onto dir.
// It returns the policy file path, or "" when the context has no bouncer.
func (c *Config) WriteBouncer(name, dir string) (string, error) {
	spec, ok := c.Contexts[name]
	if !ok {
		return "", nil
	}
	agent := AgentSpec{}
	if spec.Agent != "" && c.Agents != nil {
		agent = c.Agents[spec.Agent]
	}
	setup, err := c.MaterializeBouncer(name, spec.Bouncer, agent)
	if err != nil {
		return "", err
	}
	if setup == nil {
		return "", nil
	}
	err = bouncercfg.WriteLayout(bouncercfg.DirFS(dir), setup.PolicyYAML, setup.TSFiles)
	if err != nil {
		return "", fmt.Errorf("write bouncer layout: %w", err)
	}
	return filepath.Join(dir, bouncercfg.FileName), nil
}

// BouncerTests returns the test suite for a context's bouncer. The policy
// is materialized as run would ship it, without agent tunnel hosts.
func (c *Config) BouncerTests(context string) (bouncertest.Suite, error) {
	spec, ok := c.Contexts[context]
	if !ok {
		return bouncertest.Suite{}, fmt.Errorf("unknown context %q", context)
	}
	if spec.Bouncer == "" {
		return bouncertest.Suite{}, fmt.Errorf("context %q has no bouncer", context)
	}
	setup, err := c.MaterializeBouncer(context, spec.Bouncer, AgentSpec{})
	if err != nil {
		return bouncertest.Suite{}, err
	}
	tests := c.Bouncers[spec.Bouncer].Tests
	if tests == "" {
		return bouncertest.Suite{}, fmt.Errorf("bouncer %q has no tests", spec.Bouncer)
	}
	return bouncertest.Suite{
		Bouncer:    spec.Bouncer,
		PolicyYAML: setup.PolicyYAML,
		TSFiles:    setup.TSFiles,
		TestsDir:   tests,
	}, nil
}

func (c *Config) bouncerByName(name string) (*bouncercfg.Config, error) {
	if name == "" {
		return nil, nil
	}
	if c == nil || c.Bouncers == nil {
		return nil, fmt.Errorf("unknown bouncer %q", name)
	}
	spec, ok := c.Bouncers[name]
	if !ok || spec == nil {
		return nil, fmt.Errorf("unknown bouncer %q", name)
	}
	doc := &spec.Config
	err := doc.Init()
	if err != nil {
		return nil, fmt.Errorf("init bouncer config: %w", err)
	}
	return doc, nil
}

func withAgentTunnel(doc *bouncercfg.Config, hosts []string) *bouncercfg.Config {
	if doc == nil || len(hosts) == 0 || len(doc.Profiles) == 0 {
		return doc
	}
	out := *doc
	out.Profiles = make(map[string]*bouncercfg.Profile, len(doc.Profiles))
	for name, p := range doc.Profiles {
		if p == nil {
			out.Profiles[name] = nil
			continue
		}
		cp := *p
		if p.Extends == "" {
			cp.Tunnel = unionTunnel(hosts, p.Tunnel)
		}
		out.Profiles[name] = &cp
	}
	return &out
}

func unionTunnel(base, extra []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(base)+len(extra))
	for _, group := range [][]string{base, extra} {
		for _, h := range group {
			key := strings.ToLower(h)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, h)
		}
	}
	return out
}
