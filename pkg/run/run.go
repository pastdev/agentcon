package run

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/running"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/pastdev/agentcon/pkg/log"
	"github.com/pastdev/agentcon/pkg/term"
)

// ErrInterrupted is returned when Ctrl-C is typed at a prompt.
var ErrInterrupted = term.ErrInterrupted

const (
	groupRoot           = "0"
	hostRootEnv         = "AGENTCON_HOST_ROOT"
	xtraceEnv           = "AGENTCON_XTRACE"
	workspaceMountPoint = "/workspace"
	labelContext        = "agentcon.context"
	labelProject        = "agentcon.project"
	labelSlug           = "agentcon.slug"
	labelRole           = "agentcon.role"
	roleAgent           = "agent"
	roleBouncer         = "bouncer"
	roleExt             = "ext"
)

func sessionLabels(contextName, project, slug, role string) map[string]string {
	return map[string]string{
		labelContext: contextName,
		labelProject: project,
		labelSlug:    slug,
		labelRole:    role,
	}
}

type BouncerSetup struct {
	ContextName string
	PolicyYAML  []byte
	TSFiles     map[string]string
}

type ImageBuild struct {
	Context    string
	Dockerfile string
	Tags       []string
}

type Request struct {
	Image   string
	Build   *ImageBuild
	Mounts  []container.Mount
	Root    string
	Cwd     string
	Home    string
	User    string
	Agent   string
	Args    []string
	TTY     bool
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Runtime container.Runtime
	Context string
	// Project is relative to Root. Empty is the context root. Derived from Cwd when unset.
	Project string
	// Slug is the 8-character session id. Minted when unset.
	Slug              string
	Bouncer           *BouncerSetup
	LinuxBinary       string
	Entrypoint        []string
	ExtraHosts        []string
	SidecarExtraHosts []string
	// DooD describes a Docker-outside-of-Docker environment. Nil means
	// agentcon shares a host with the Docker daemon.
	DooD *DooD
	// PullPolicy governs the agent image. Empty is PullMissing.
	PullPolicy PullPolicy
	// SidecarPullPolicy governs the bouncer sidecar image. Empty is PullMissing.
	SidecarPullPolicy PullPolicy
	// SidecarEnv is extra NAME=value pairs for source: env credentials.
	// They overlay the host environment and are PUT to the sidecar after serve is up.
	// They are not passed as container environment variables.
	SidecarEnv []string
	// Provided is extra credential.slot to secret for source: provided.
	// Host-resolved file, keyring, and command secrets are collected automatically.
	Provided map[string]string
}

func Run(ctx context.Context, req Request) error {
	if req.Runtime == nil {
		return fmt.Errorf("container runtime is required")
	}

	ctx, stop := notifyRunSignals(ctx)
	defer stop()

	err := fillSessionIdentity(&req)
	if err != nil {
		return err
	}

	if req.Build != nil {
		out := log.InfoWriter()
		err = req.Runtime.Build(ctx, container.Build{
			Context:    req.Build.Context,
			Dockerfile: req.Build.Dockerfile,
			Tags:       req.Build.Tags,
			Output:     out,
			PullParent: req.PullPolicy == PullAlways,
		})
		out.Flush()
		if err != nil {
			return fmt.Errorf("build image: %w", err)
		}
	} else {
		out := log.InfoWriter()
		err = ensureImage(ctx, req.Runtime, req.Image, req.PullPolicy, out)
		out.Flush()
		if err != nil {
			return fmt.Errorf("agent image: %w", err)
		}
	}

	spec, err := specFrom(req)
	if err != nil {
		return fmt.Errorf("container spec: %w", err)
	}

	err = prepareHost(spec)
	if err != nil {
		return fmt.Errorf("prepare host: %w", err)
	}
	spec.Mounts, err = translateMounts(spec.Mounts, req.DooD)
	if err != nil {
		return fmt.Errorf("agent mounts: %w", err)
	}

	if req.Bouncer != nil {
		err = runWithBouncer(ctx, req, spec)
		if err != nil {
			return fmt.Errorf("run with bouncer: %w", err)
		}
		return nil
	}

	err = req.Runtime.Run(ctx, spec)
	if err != nil {
		return fmt.Errorf("run container: %w", err)
	}
	return nil
}

func prepareHost(spec container.Spec) error {
	for _, m := range spec.Mounts {
		if m.Source == "" || m.Target == workspaceMountPoint {
			continue
		}
		err := os.MkdirAll(m.Source, 0o700)
		if err != nil {
			return fmt.Errorf("create mount dir %s: %w", m.Source, err)
		}
	}
	return nil
}

func specFrom(req Request) (container.Spec, error) {
	rel, err := filepath.Rel(req.Root, req.Cwd)
	if err != nil {
		return container.Spec{}, fmt.Errorf("workspace relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		rel = "."
	}

	spec := container.Spec{
		Image:      req.Image,
		User:       req.User,
		GroupAdd:   []string{groupRoot},
		WorkDir:    filepath.ToSlash(filepath.Join(workspaceMountPoint, rel)),
		Env:        agentEnv(req),
		Args:       req.Args,
		Entrypoint: req.Entrypoint,
		Stdin:      req.Stdin,
		Stdout:     req.Stdout,
		Stderr:     req.Stderr,
		TTY:        req.TTY,
		ExtraHosts: req.ExtraHosts,
		Mounts: []container.Mount{
			{Source: req.Root, Target: workspaceMountPoint},
		},
	}
	if req.Slug != "" {
		spec.Name = running.ResourceName(req.Project, req.Slug, roleAgent)
		spec.Labels = sessionLabels(req.Context, req.Project, req.Slug, roleAgent)
	}
	spec.Mounts = append(spec.Mounts, req.Mounts...)

	return spec, nil
}

func agentEnv(req Request) []string {
	env := []string{hostRootEnv + "=" + req.Root}
	if v := os.Getenv(xtraceEnv); v != "" {
		env = append(env, xtraceEnv+"="+v)
	}
	return env
}

func fillSessionIdentity(req *Request) error {
	if req.Slug == "" {
		req.Slug = running.NewSlug()
	} else {
		req.Slug = strings.ToLower(req.Slug)
	}
	if !running.ValidSlug(req.Slug) {
		return fmt.Errorf("slug %q must be %d hex characters", req.Slug, running.SlugLength)
	}
	if req.Project == "" {
		req.Project = running.ProjectPath(req.Root, req.Cwd)
	}
	req.Project = strings.Trim(strings.ReplaceAll(req.Project, "\\", "/"), "/")
	return nil
}
