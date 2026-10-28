package moby

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/moby/moby/api/pkg/stdcopy"
	apictn "github.com/moby/moby/api/types/container"
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
	hostConfig := &apictn.HostConfig{
		AutoRemove: true,
		GroupAdd:   spec.GroupAdd,
		Mounts:     mounts(spec.Mounts),
	}
	if height, width, ok := consoleSize(spec); ok {
		hostConfig.ConsoleSize = [2]uint{height, width}
	}

	created, err := r.api.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &apictn.Config{
			User:         spec.User,
			AttachStdin:  true,
			AttachStdout: true,
			AttachStderr: true,
			Tty:          spec.TTY,
			OpenStdin:    true,
			StdinOnce:    true,
			Env:          spec.Env,
			Cmd:          spec.Args,
			Image:        spec.Image,
			WorkingDir:   spec.WorkDir,
		},
		HostConfig: hostConfig,
	})
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}

	started := false
	defer func() {
		if started {
			return
		}
		_, _ = r.api.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{
			Force: true,
		})
	}()

	attach, err := r.api.ContainerAttach(ctx, created.ID, client.ContainerAttachOptions{
		Stream: true,
		Stdin:  true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return fmt.Errorf("attach container: %w", err)
	}
	defer attach.Close()

	restoreTTY, err := prepareTTY(spec)
	if err != nil {
		return err
	}
	defer restoreTTY()

	_, err = r.api.ContainerStart(ctx, created.ID, client.ContainerStartOptions{})
	if err != nil {
		return fmt.Errorf("start container: %w", err)
	}
	started = true
	stopResize := r.monitorTtySize(ctx, created.ID, spec)
	defer stopResize()

	wait := r.api.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{
		Condition: apictn.WaitConditionNotRunning,
	})
	err = streamAttach(spec, attach)
	if err != nil {
		return err
	}
	var status apictn.WaitResponse
	select {
	case waitErr := <-wait.Error:
		if waitErr != nil {
			return fmt.Errorf("wait container: %w", waitErr)
		}
		status = <-wait.Result
	case status = <-wait.Result:
	}
	if status.Error != nil && status.Error.Message != "" {
		return fmt.Errorf("wait container: %s", status.Error.Message)
	}
	if status.StatusCode != 0 {
		return &container.ExitError{Code: int(status.StatusCode)}
	}
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
