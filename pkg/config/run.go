package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pastdev/agentcon/pkg/run"
)

func NewRunRequest(cfg *Config, name, cwd string) (run.Request, error) {
	if cfg == nil {
		return run.Request{}, fmt.Errorf("config is required")
	}

	image, root, err := cfg.lookupContext(name, cwd)
	if err != nil {
		return run.Request{}, err
	}

	req := run.Request{
		Image: image,
		Root:  root,
		Cwd:   cwd,
	}
	if cwd == "" {
		return req, nil
	}

	absCwd, err := filepath.Abs(cwd)
	if err != nil {
		return run.Request{}, fmt.Errorf("resolve cwd: %w", err)
	}
	req.Cwd = absCwd
	return req, nil
}

func (c Config) lookupContext(name, cwd string) (string, string, error) {
	if name != "" {
		return c.contextByName(name)
	}

	absCwd, err := filepath.Abs(cwd)
	if err != nil {
		return "", "", fmt.Errorf("resolve cwd: %w", err)
	}

	var matchImage, matchRoot string
	var matchLen int
	tied := false
	for n := range c.Contexts {
		image, root, loadErr := c.contextByName(n)
		if loadErr != nil {
			return "", "", loadErr
		}
		if !hasPathPrefix(absCwd, root) {
			continue
		}
		if len(root) > matchLen {
			matchImage = image
			matchRoot = root
			matchLen = len(root)
			tied = false
			continue
		}
		if len(root) == matchLen && matchLen > 0 {
			tied = true
		}
	}
	if matchLen == 0 {
		return "", "", fmt.Errorf("no context root contains %s", absCwd)
	}
	if tied {
		return "", "", fmt.Errorf("multiple contexts match %s", absCwd)
	}
	return matchImage, matchRoot, nil
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
	if root == "~" || strings.HasPrefix(root, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand home: %w", err)
		}
		root = home + root[1:]
	}
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
