package moby

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strconv"

	apictn "github.com/moby/moby/api/types/container"
	apinet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/pastdev/agentcon/pkg/container"
)

func (r *Runtime) Create(ctx context.Context, spec container.Spec) (string, error) {
	hostConfig := &apictn.HostConfig{
		AutoRemove:   spec.AutoRemove,
		GroupAdd:     spec.GroupAdd,
		Mounts:       mounts(spec.Mounts),
		PortBindings: portBindings(spec.Ports),
		ExtraHosts:   spec.ExtraHosts,
	}
	if height, width, ok := consoleSize(spec); ok {
		hostConfig.ConsoleSize = [2]uint{height, width}
	}
	if len(spec.Networks) > 0 {
		hostConfig.NetworkMode = apictn.NetworkMode(spec.Networks[0])
	}

	attach := spec.TTY || spec.Stdin != nil
	cfg := &apictn.Config{
		User:         spec.User,
		AttachStdin:  attach,
		AttachStdout: attach,
		AttachStderr: attach,
		Tty:          spec.TTY,
		OpenStdin:    attach,
		StdinOnce:    attach,
		Env:          spec.Env,
		Cmd:          spec.Args,
		Image:        spec.Image,
		WorkingDir:   spec.WorkDir,
		Labels:       spec.Labels,
		ExposedPorts: exposedPorts(spec.Ports),
	}
	if len(spec.Entrypoint) > 0 {
		cfg.Entrypoint = spec.Entrypoint
	}

	created, err := r.api.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:             spec.Name,
		Config:           cfg,
		HostConfig:       hostConfig,
		NetworkingConfig: networkingConfig(spec.Networks),
	})
	if err != nil {
		return "", fmt.Errorf("create container: %w", err)
	}
	return created.ID, nil
}

func (r *Runtime) Start(ctx context.Context, id string) error {
	_, err := r.api.ContainerStart(ctx, id, client.ContainerStartOptions{})
	if err != nil {
		return fmt.Errorf("start container: %w", err)
	}
	return nil
}

func (r *Runtime) AttachStartWait(ctx context.Context, id string, spec container.Spec) error {
	attach, err := r.api.ContainerAttach(ctx, id, client.ContainerAttachOptions{
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
		return fmt.Errorf("prepare tty: %w", err)
	}
	defer restoreTTY()

	err = r.Start(ctx, id)
	if err != nil {
		return fmt.Errorf("start attached container: %w", err)
	}
	stopResize := r.monitorTtySize(ctx, id, spec)
	defer stopResize()

	wait := r.api.ContainerWait(ctx, id, client.ContainerWaitOptions{
		Condition: apictn.WaitConditionNotRunning,
	})
	err = streamAttach(spec, attach)
	if err != nil {
		return fmt.Errorf("stream attach: %w", err)
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

func (r *Runtime) CopyTo(ctx context.Context, id, dest string, tar io.Reader) error {
	_, err := r.api.CopyToContainer(ctx, id, client.CopyToContainerOptions{
		DestinationPath: dest,
		Content:         tar,
	})
	if err != nil {
		return fmt.Errorf("copy into container: %w", err)
	}
	return nil
}

func (r *Runtime) Exec(ctx context.Context, id string, spec container.Exec) error {
	created, err := r.api.ExecCreate(ctx, id, client.ExecCreateOptions{
		User:         spec.User,
		AttachStdin:  false,
		AttachStdout: !spec.Detach,
		AttachStderr: !spec.Detach,
		Env:          spec.Env,
		Cmd:          spec.Cmd,
	})
	if err != nil {
		return fmt.Errorf("create exec: %w", err)
	}
	_, err = r.api.ExecStart(ctx, created.ID, client.ExecStartOptions{
		Detach: spec.Detach,
	})
	if err != nil {
		return fmt.Errorf("start exec: %w", err)
	}
	return nil
}

func (r *Runtime) Inspect(ctx context.Context, id string) (container.Info, error) {
	inspected, err := r.api.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return container.Info{}, fmt.Errorf("inspect container: %w", err)
	}
	info := container.Info{
		ID:       inspected.Container.ID,
		Networks: map[string]container.Endpoint{},
	}
	if inspected.Container.NetworkSettings == nil {
		return info, nil
	}
	for name, ep := range inspected.Container.NetworkSettings.Networks {
		if ep == nil {
			continue
		}
		ip := ""
		if ep.IPAddress.IsValid() {
			ip = ep.IPAddress.String()
		}
		info.Networks[name] = container.Endpoint{IP: ip}
	}
	return info, nil
}

func (r *Runtime) Remove(ctx context.Context, id string, force bool) error {
	_, err := r.api.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: force})
	if err != nil {
		return fmt.Errorf("remove container: %w", err)
	}
	return nil
}

func (r *Runtime) CreateNetwork(ctx context.Context, spec container.NetworkSpec) (string, error) {
	created, err := r.api.NetworkCreate(ctx, spec.Name, client.NetworkCreateOptions{
		Driver:   "bridge",
		Internal: spec.Internal,
		Labels:   spec.Labels,
	})
	if err != nil {
		return "", fmt.Errorf("create network: %w", err)
	}
	return created.ID, nil
}

func (r *Runtime) InspectNetwork(ctx context.Context, id string) (container.NetworkInfo, error) {
	inspected, err := r.api.NetworkInspect(ctx, id, client.NetworkInspectOptions{})
	if err != nil {
		return container.NetworkInfo{}, fmt.Errorf("inspect network: %w", err)
	}
	info := container.NetworkInfo{
		ID:       inspected.Network.ID,
		Name:     inspected.Network.Name,
		Internal: inspected.Network.Internal,
	}
	if len(inspected.Network.IPAM.Config) > 0 && inspected.Network.IPAM.Config[0].Subnet.IsValid() {
		info.Subnet = inspected.Network.IPAM.Config[0].Subnet.String()
	}
	return info, nil
}

func (r *Runtime) ConnectNetwork(ctx context.Context, networkID, containerID string) error {
	_, err := r.api.NetworkConnect(ctx, networkID, client.NetworkConnectOptions{
		Container: containerID,
	})
	if err != nil {
		return fmt.Errorf("connect network: %w", err)
	}
	return nil
}

func (r *Runtime) RemoveNetwork(ctx context.Context, id string) error {
	_, err := r.api.NetworkRemove(ctx, id, client.NetworkRemoveOptions{})
	if err != nil {
		return fmt.Errorf("remove network: %w", err)
	}
	return nil
}

func networkingConfig(networks []string) *apinet.NetworkingConfig {
	if len(networks) == 0 {
		return nil
	}
	cfg := &apinet.NetworkingConfig{
		EndpointsConfig: map[string]*apinet.EndpointSettings{},
	}
	for _, name := range networks {
		cfg.EndpointsConfig[name] = &apinet.EndpointSettings{}
	}
	return cfg
}

func exposedPorts(ports []container.Port) apinet.PortSet {
	if len(ports) == 0 {
		return nil
	}
	out := apinet.PortSet{}
	for _, p := range ports {
		port, ok := parsePort(p)
		if !ok {
			continue
		}
		out[port] = struct{}{}
	}
	return out
}

func portBindings(ports []container.Port) apinet.PortMap {
	if len(ports) == 0 {
		return nil
	}
	out := apinet.PortMap{}
	for _, p := range ports {
		port, ok := parsePort(p)
		if !ok {
			continue
		}
		binding := apinet.PortBinding{HostPort: p.HostPort}
		if p.HostIP != "" {
			ip, err := netip.ParseAddr(p.HostIP)
			if err == nil {
				binding.HostIP = ip
			}
		}
		out[port] = append(out[port], binding)
	}
	return out
}

func parsePort(p container.Port) (apinet.Port, bool) {
	proto := apinet.TCP
	if p.Protocol == "udp" {
		proto = apinet.UDP
	}
	n, err := strconv.ParseUint(p.ContainerPort, 10, 16)
	if err != nil {
		return apinet.Port{}, false
	}
	port, ok := apinet.PortFrom(uint16(n), proto)
	return port, ok
}
