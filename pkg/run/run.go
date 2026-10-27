package run

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pastdev/agentcon/pkg/container"
)

const (
	groupRoot           = "0"
	harnessCursor       = "cursor"
	harnessCursorMount  = "/agent/cursor"
	hostRootEnv         = "AGENTCON_HOST_ROOT"
	workspaceMountPoint = "/workspace"
)

type Request struct {
	Image   string
	Root    string
	Cwd     string
	Home    string
	User    string
	Harness string
	Args    []string
	TTY     bool
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Runtime container.Runtime
}

func Run(ctx context.Context, req Request) error {
	if req.Runtime == nil {
		return fmt.Errorf("container runtime is required")
	}

	spec, err := specFrom(req)
	if err != nil {
		return fmt.Errorf("container spec: %w", err)
	}

	err = prepareHost(spec)
	if err != nil {
		return err
	}

	err = req.Runtime.Run(ctx, spec)
	if err != nil {
		return fmt.Errorf("run container: %w", err)
	}
	return nil
}

func prepareHost(spec container.Spec) error {
	for _, m := range spec.Mounts {
		if m.Target != harnessCursorMount {
			continue
		}
		err := os.MkdirAll(m.Source, 0o700)
		if err != nil {
			return fmt.Errorf("create harness dir: %w", err)
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

	harness := req.Harness
	if harness == "" {
		harness = harnessCursor
	}

	spec := container.Spec{
		Image:    req.Image,
		User:     req.User,
		GroupAdd: []string{groupRoot},
		WorkDir:  filepath.ToSlash(filepath.Join(workspaceMountPoint, rel)),
		Env:      []string{hostRootEnv + "=" + req.Root},
		Args:     req.Args,
		Stdin:    req.Stdin,
		Stdout:   req.Stdout,
		Stderr:   req.Stderr,
		TTY:      req.TTY,
		Mounts: []container.Mount{
			{Source: req.Root, Target: workspaceMountPoint},
		},
	}

	switch harness {
	case harnessCursor:
		spec.Mounts = append(spec.Mounts, container.Mount{
			Source: filepath.Join(req.Home, ".cursor"),
			Target: harnessCursorMount,
		})
	default:
		return container.Spec{}, fmt.Errorf("unsupported harness %q", harness)
	}

	return spec, nil
}
