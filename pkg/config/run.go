package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pastdev/agentcon/pkg/container"
	"github.com/pastdev/agentcon/pkg/run"
)

// RunFlags are CLI selectors applied on top of a named context.
type RunFlags struct {
	Context   string
	Agent     string
	Bouncer   string
	NoBouncer bool
}

func NewRunRequest(cfg *Config, flags RunFlags, cwd, home string) (run.Request, error) {
	if cfg == nil {
		return run.Request{}, fmt.Errorf("config is required")
	}
	name := flags.Context
	if name == "" {
		name = cfg.DefaultContext
	}
	if name == "" {
		return run.Request{}, fmt.Errorf("default_context is not set")
	}

	spec, root, err := cfg.contextByName(name)
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

	agentName, agent, err := cfg.activeAgent(spec, flags.Agent)
	if err != nil {
		return run.Request{}, err
	}

	image, build, err := cfg.resolveAgentImage(agentName, agent, home)
	if err != nil {
		return run.Request{}, err
	}

	mounts, err := resolveAgentMounts(agent.Mounts, home)
	if err != nil {
		return run.Request{}, err
	}

	var setup *run.BouncerSetup
	if !flags.NoBouncer {
		bouncerName := flags.Bouncer
		if bouncerName == "" {
			bouncerName = spec.Bouncer
		}
		setup, err = cfg.MaterializeBouncer(name, bouncerName, agent)
		if err != nil {
			return run.Request{}, err
		}
	}

	return run.Request{
		Image:   image,
		Build:   build,
		Mounts:  mounts,
		Root:    root,
		Cwd:     absCwd,
		Home:    home,
		Context: name,
		Agent:   agentName,
		Bouncer: setup,
	}, nil
}

func (c Config) contextByName(name string) (ContextSpec, string, error) {
	spec, ok := c.Contexts[name]
	if !ok {
		return ContextSpec{}, "", fmt.Errorf("unknown context %q", name)
	}
	root, err := expandRoot(spec.Root)
	if err != nil {
		return ContextSpec{}, "", fmt.Errorf("context %q: %w", name, err)
	}
	return spec, root, nil
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

func (c *Config) activeAgent(spec ContextSpec, override string) (string, AgentSpec, error) {
	name := override
	if name == "" {
		name = spec.Agent
	}
	if name == "" {
		return "", AgentSpec{}, fmt.Errorf("context has no agent")
	}
	if c == nil || c.Agents == nil {
		return "", AgentSpec{}, fmt.Errorf("unknown agent %q", name)
	}
	agent, ok := c.Agents[name]
	if !ok {
		return "", AgentSpec{}, fmt.Errorf("unknown agent %q", name)
	}
	return name, agent, nil
}

func (c *Config) resolveAgentImage(name string, agent AgentSpec, home string) (string, *run.ImageBuild, error) {
	if agent.Image == "" && agent.Build == nil {
		return "", nil, fmt.Errorf("agent %q requires image or build", name)
	}
	image := agent.Image
	if image == "" {
		image = agentImagePrefix + strings.ToLower(name)
	}
	if agent.Build == nil {
		return image, nil, nil
	}
	if agent.Build.Context == "" {
		return "", nil, fmt.Errorf("agent %q build.context is required", name)
	}
	overlayDirs := []string{}
	if c != nil {
		overlayDirs = c.OverlayDirs
	}
	contextDir, err := resolveConfigDir(agent.Build.Context, home, overlayDirs)
	if err != nil {
		return "", nil, fmt.Errorf("agent %q build.context: %w", name, err)
	}
	dockerfile := agent.Build.Dockerfile
	if dockerfile == "" {
		dockerfile = defaultDockerfile
	}
	if filepath.IsAbs(dockerfile) || strings.HasPrefix(dockerfile, "~") {
		return "", nil, fmt.Errorf("agent %q build.dockerfile must be relative to the build context", name)
	}
	dockerfilePath := filepath.Join(contextDir, dockerfile)
	_, err = os.Stat(dockerfilePath)
	if err != nil {
		return "", nil, fmt.Errorf("agent %q dockerfile %s: %w", name, dockerfile, err)
	}
	return image, &run.ImageBuild{
		Context:    contextDir,
		Dockerfile: dockerfile,
		Tags:       []string{image},
	}, nil
}

func resolveAgentMounts(mounts []MountSpec, home string) ([]container.Mount, error) {
	out := make([]container.Mount, 0, len(mounts))
	for i, m := range mounts {
		if m.Source == "" {
			return nil, fmt.Errorf("mounts[%d]: source is required", i)
		}
		if m.Target == "" {
			return nil, fmt.Errorf("mounts[%d]: target is required", i)
		}
		out = append(out, container.Mount{
			Source: resolveMountSource(m.Source, home),
			Target: m.Target,
		})
	}
	return out, nil
}
