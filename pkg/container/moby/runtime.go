package moby

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	"github.com/pastdev/agentcon/pkg/container"
	"golang.org/x/term"
)

type Runtime struct {
	api apiClient
}

type apiClient interface {
	ContainerAttach(
		ctx context.Context,
		id string,
		options client.ContainerAttachOptions,
	) (client.ContainerAttachResult, error)
	ContainerCreate(
		ctx context.Context,
		options client.ContainerCreateOptions,
	) (client.ContainerCreateResult, error)
	ContainerInspect(
		ctx context.Context,
		id string,
		options client.ContainerInspectOptions,
	) (client.ContainerInspectResult, error)
	ContainerRemove(
		ctx context.Context,
		id string,
		options client.ContainerRemoveOptions,
	) (client.ContainerRemoveResult, error)
	ContainerResize(
		ctx context.Context,
		id string,
		options client.ContainerResizeOptions,
	) (client.ContainerResizeResult, error)
	ContainerStart(
		ctx context.Context,
		id string,
		options client.ContainerStartOptions,
	) (client.ContainerStartResult, error)
	ContainerWait(
		ctx context.Context,
		id string,
		options client.ContainerWaitOptions,
	) client.ContainerWaitResult
	CopyToContainer(
		ctx context.Context,
		id string,
		options client.CopyToContainerOptions,
	) (client.CopyToContainerResult, error)
	ExecCreate(
		ctx context.Context,
		id string,
		options client.ExecCreateOptions,
	) (client.ExecCreateResult, error)
	ExecStart(
		ctx context.Context,
		id string,
		options client.ExecStartOptions,
	) (client.ExecStartResult, error)
	NetworkConnect(
		ctx context.Context,
		networkID string,
		options client.NetworkConnectOptions,
	) (client.NetworkConnectResult, error)
	NetworkCreate(
		ctx context.Context,
		name string,
		options client.NetworkCreateOptions,
	) (client.NetworkCreateResult, error)
	NetworkInspect(
		ctx context.Context,
		networkID string,
		options client.NetworkInspectOptions,
	) (client.NetworkInspectResult, error)
	NetworkRemove(
		ctx context.Context,
		networkID string,
		options client.NetworkRemoveOptions,
	) (client.NetworkRemoveResult, error)
	DialHijack(
		ctx context.Context,
		url string,
		proto string,
		meta map[string][]string,
	) (net.Conn, error)
	ImageBuild(
		ctx context.Context,
		buildContext io.Reader,
		options client.ImageBuildOptions,
	) (client.ImageBuildResult, error)
	ImageInspect(
		ctx context.Context,
		imageID string,
		inspectOpts ...client.ImageInspectOption,
	) (client.ImageInspectResult, error)
	ImagePull(
		ctx context.Context,
		refStr string,
		options client.ImagePullOptions,
	) (client.ImagePullResponse, error)
	Close() error
}

func (r *Runtime) Close() error {
	if r.api == nil {
		return nil
	}
	err := r.api.Close()
	if err != nil {
		return fmt.Errorf("close container engine: %w", err)
	}
	return nil
}

func (r *Runtime) Run(ctx context.Context, spec container.Spec) error {
	spec.AutoRemove = true
	id, err := r.Create(ctx, spec)
	if err != nil {
		return fmt.Errorf("run create: %w", err)
	}
	started := false
	cleanup := context.WithoutCancel(ctx)
	defer func() {
		if started {
			return
		}
		_ = r.Remove(cleanup, id, true)
	}()
	err = r.AttachStartWait(ctx, id, spec)
	if err != nil {
		return fmt.Errorf("run attach: %w", err)
	}
	started = true
	return nil
}

func New() (*Runtime, error) {
	api, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("container engine client: %w", err)
	}
	return &Runtime{api: api}, nil
}

func mounts(in []container.Mount) []mount.Mount {
	out := make([]mount.Mount, 0, len(in))
	for _, m := range in {
		if m.Volume != "" {
			// A volume stands in for a bind, so it must not take the image's
			// files, owner, or mode when the source directory is empty.
			out = append(out, mount.Mount{
				Type:          mount.TypeVolume,
				Source:        m.Volume,
				Target:        m.Target,
				VolumeOptions: &mount.VolumeOptions{Subpath: m.Subpath, NoCopy: true},
			})
			continue
		}
		out = append(out, mount.Mount{
			Type:   mount.TypeBind,
			Source: m.Source,
			Target: m.Target,
		})
	}
	return out
}

func (r *Runtime) resizeTty(ctx context.Context, id string, spec container.Spec) {
	height, width, ok := consoleSize(spec)
	if !ok {
		return
	}
	_, _ = r.api.ContainerResize(ctx, id, client.ContainerResizeOptions{
		Height: height,
		Width:  width,
	})
}

func consoleSize(spec container.Spec) (uint, uint, bool) {
	fd, ok := stdinTerminalFD(spec)
	if !ok {
		return 0, 0, false
	}
	width, height, err := term.GetSize(fd)
	if err != nil {
		return 0, 0, false
	}
	if width <= 0 || height <= 0 {
		return 0, 0, false
	}
	return uint(height), uint(width), true
}

func stdinTerminalFD(spec container.Spec) (int, bool) {
	if !spec.TTY {
		return 0, false
	}
	file, ok := spec.Stdin.(*os.File)
	if !ok {
		return 0, false
	}
	fd := int(file.Fd())
	if !term.IsTerminal(fd) {
		return 0, false
	}
	return fd, true
}

func prepareTTY(spec container.Spec) (func(), error) {
	noop := func() {}
	fd, ok := stdinTerminalFD(spec)
	if !ok {
		return noop, nil
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("set raw terminal: %w", err)
	}
	return func() {
		_ = term.Restore(fd, state)
	}, nil
}

func streamAttach(spec container.Spec, attach client.ContainerAttachResult) error {
	outErr := make(chan error, 1)
	go func() {
		var err error
		if spec.TTY {
			_, err = io.Copy(spec.Stdout, attach.Reader)
		} else {
			_, err = stdcopy.StdCopy(spec.Stdout, spec.Stderr, attach.Reader)
		}
		outErr <- err
	}()

	go func() {
		_, _ = io.Copy(attach.Conn, spec.Stdin)
		_ = attach.CloseWrite()
	}()

	err := <-outErr
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("copy container output: %w", err)
	}
	return nil
}
