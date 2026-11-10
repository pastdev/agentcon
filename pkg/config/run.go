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
	// Pull overrides the agent pull_policy and applies to the sidecar image.
	Pull string
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

	agentPull, sidecarPull, err := pullPolicies(agentName, agent, cfg.Sidecar, flags.Pull)
	if err != nil {
		return run.Request{}, err
	}

	mounts, err := resolveAgentMounts(agent.Mounts, home)
	if err != nil {
		return run.Request{}, err
	}

	var setup *run.BouncerSetup
	var sidecarImage string
	var sidecarBuild *run.ImageBuild
	if !flags.NoBouncer {
		bouncerName := flags.Bouncer
		if bouncerName == "" {
			bouncerName = spec.Bouncer
		}
		setup, err = cfg.MaterializeBouncer(name, bouncerName, agent)
		if err != nil {
			return run.Request{}, err
		}
		sidecarImage, sidecarBuild, err = cfg.resolveSidecarImage(home)
		if err != nil {
			return run.Request{}, err
		}
	}

	return run.Request{
		Image:             image,
		Build:             build,
		PullPolicy:        agentPull,
		SidecarImage:      sidecarImage,
		SidecarBuild:      sidecarBuild,
		SidecarPullPolicy: sidecarPull,
		Mounts:            mounts,
		Root:              root,
		Cwd:               absCwd,
		Home:              home,
		Context:           name,
		Agent:             agentName,
		Bouncer:           setup,
	}, nil
}

// pullPolicies resolves the agent and sidecar pull policies. The --pull
// flag overrides both pull_policy settings.
func pullPolicies(agentName string, agent AgentSpec, sidecar SidecarSpec, flag string) (run.PullPolicy, run.PullPolicy, error) {
	agentPull, err := run.ParsePullPolicy(agent.PullPolicy)
	if err != nil {
		return "", "", fmt.Errorf("agent %q pull_policy: %w", agentName, err)
	}
	sidecarPull, err := run.ParsePullPolicy(sidecar.PullPolicy)
	if err != nil {
		return "", "", fmt.Errorf("sidecar pull_policy: %w", err)
	}
	if flag == "" {
		return agentPull, sidecarPull, nil
	}
	p, err := run.ParsePullPolicy(flag)
	if err != nil {
		return "", "", fmt.Errorf("--pull: %w", err)
	}
	return p, p, nil
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
	return c.resolveImage(fmt.Sprintf("agent %q", name), agent.Image, agent.Build, agentImagePrefix+strings.ToLower(name), home)
}

// resolveSidecarImage returns an empty image and no build when the sidecar
// is not configured, so run uses its stock image.
func (c *Config) resolveSidecarImage(home string) (string, *run.ImageBuild, error) {
	if c.Sidecar.Image == "" && c.Sidecar.Build == nil {
		return "", nil, nil
	}
	return c.resolveImage("sidecar", c.Sidecar.Image, c.Sidecar.Build, sidecarImageTag, home)
}

// resolveImage resolves an image and its optional build. A build without an
// image is tagged defaultTag. owner prefixes errors.
func (c *Config) resolveImage(owner, image string, build *BuildSpec, defaultTag, home string) (string, *run.ImageBuild, error) {
	if image == "" {
		image = defaultTag
	}
	if build == nil {
		return image, nil, nil
	}
	if build.Context == "" {
		return "", nil, fmt.Errorf("%s build.context is required", owner)
	}
	overlayDirs := []string{}
	if c != nil {
		overlayDirs = c.OverlayDirs
	}
	contextDir, err := resolveConfigDir(build.Context, home, overlayDirs)
	if err != nil {
		return "", nil, fmt.Errorf("%s build.context: %w", owner, err)
	}
	dockerfile := build.Dockerfile
	if dockerfile == "" {
		dockerfile = defaultDockerfile
	}
	if filepath.IsAbs(dockerfile) || strings.HasPrefix(dockerfile, "~") {
		return "", nil, fmt.Errorf("%s build.dockerfile must be relative to the build context", owner)
	}
	dockerfilePath := filepath.Join(contextDir, dockerfile)
	_, err = os.Stat(dockerfilePath)
	if err != nil {
		return "", nil, fmt.Errorf("%s dockerfile %s: %w", owner, dockerfile, err)
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
