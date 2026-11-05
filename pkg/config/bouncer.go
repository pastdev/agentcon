package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/running"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/harness"
	"github.com/pastdev/agentcon/pkg/run"
	"gopkg.in/yaml.v3"
)

// BouncerLayoutDir is the host folder-layer directory for a context.
func BouncerLayoutDir(home, context string) string {
	return filepath.Join(home, ".local", "state", "agentcon", running.FileName(context), "bouncer")
}

func (c *Config) MaterializeBouncer(name, active string) (*run.BouncerSetup, error) {
	spec, ok := c.Contexts[name]
	if !ok || spec.Bouncer == nil {
		return nil, nil
	}

	_, err := c.bouncerService(name)
	if err != nil {
		return nil, fmt.Errorf("bouncer config: %w", err)
	}
	policyDoc := withHarnessTunnel(spec.Bouncer, c.harnessTunnel(c.activeHarness(name, active)))
	policy, err := yaml.Marshal(policyDoc)
	if err != nil {
		return nil, fmt.Errorf("encode bouncer config: %w", err)
	}
	policy = bouncercfg.RewriteTSPaths(policy, c.OverlayDirs)
	files, err := bouncercfg.CollectTSFiles(c.OverlayDirs)
	if err != nil {
		return nil, fmt.Errorf("collect ts files: %w", err)
	}

	return &run.BouncerSetup{
		ContextName: name,
		PolicyYAML:  policy,
		TSFiles:     files,
	}, nil
}

// WriteBouncer writes the folder-layer layout for a context onto dir.
// It returns the policy file path, or "" when the context has no bouncer section.
func (c *Config) WriteBouncer(name, dir string) (string, error) {
	setup, err := c.MaterializeBouncer(name, "")
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

func (c *Config) activeHarness(name, override string) string {
	if override != "" {
		return override
	}
	if spec, ok := c.Contexts[name]; ok && spec.Harness != "" {
		return spec.Harness
	}
	return harness.Cursor
}

func (c *Config) harnessTunnel(name string) []string {
	if c == nil || c.Harnesses == nil {
		return nil
	}
	return c.Harnesses[name].Tunnel
}

func withHarnessTunnel(doc *bouncercfg.Config, hosts []string) *bouncercfg.Config {
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
