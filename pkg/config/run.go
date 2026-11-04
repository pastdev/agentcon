package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pastdev/agentcon/pkg/run"
)

func NewRunRequest(cfg *Config, name, cwd, home string) (run.Request, error) {
	if cfg == nil {
		return run.Request{}, fmt.Errorf("config is required")
	}
	if name == "" {
		name = cfg.DefaultContext
	}
	if name == "" {
		return run.Request{}, fmt.Errorf("default_context is not set")
	}

	image, root, err := cfg.contextByName(name)
	if err != nil {
		return run.Request{}, err
	}

	absCwd, err := filepath.Abs(cwd)
	if err != nil {
		return run.Request{}, fmt.Errorf("resolve cwd: %w", err)
	}
	if !hasPathPrefix(absCwd, root) {
		return run.Request{}, fmt.Errorf(
			"cwd %s is not under context %q root %s",
			absCwd,
			name,
			root,
		)
	}

	setup, err := cfg.MaterializeBouncer(name)
	if err != nil {
		return run.Request{}, err
	}

	return run.Request{
		Image:   image,
		Root:    root,
		Cwd:     absCwd,
		Home:    home,
		Context: name,
		Bouncer: setup,
	}, nil
}

func (c Config) contextByName(name string) (string, string, error) {
	spec, ok := c.Contexts[name]
	if !ok {
		return "", "", fmt.Errorf("unknown context %q", name)
	}
	root, err := expandRoot(spec.Root)
	if err != nil {
		return "", "", fmt.Errorf("context %q: %w", name, err)
	}
	return spec.Image, root, nil
}

func expandRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root %q: %w", root, err)
	}
	return abs, nil
}

func hasPathPrefix(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return !strings.HasPrefix(rel, "..")
}
