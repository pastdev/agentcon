package config

import (
	"fmt"
	"path/filepath"

	"github.com/pastdev/agentcon/internal/bouncer/running"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/run"
	"gopkg.in/yaml.v3"
)

// BouncerLayoutDir is the host folder-layer directory for a context.
func BouncerLayoutDir(home, context string) string {
	return filepath.Join(home, ".local", "state", "agentcon", running.FileName(context), "bouncer")
}

func (c *Config) MaterializeBouncer(name string) (*run.BouncerSetup, error) {
	spec, ok := c.Contexts[name]
	if !ok || spec.Bouncer == nil {
		return nil, nil
	}

	_, err := c.bouncerService(name)
	if err != nil {
		return nil, fmt.Errorf("bouncer config: %w", err)
	}
	policy, err := yaml.Marshal(spec.Bouncer)
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
	setup, err := c.MaterializeBouncer(name)
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
