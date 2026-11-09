package run

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/envexport"
	"github.com/pastdev/agentcon/internal/bouncer/mgmt"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/pastdev/agentcon/internal/bouncer/running"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/pastdev/agentcon/pkg/version"
)

const (
	optDir            = "/opt/agentcon"
	sidecarHome       = optDir
	sidecarConfigPath = optDir + "/config.yaml"
	sidecarBinPath    = optDir + "/bin/agentcon"
	sidecarImage      = "registry.access.redhat.com/ubi10/ubi-minimal:10.2"
	sidecarStatePath  = optDir + "/state"
	agentBinPath      = sidecarBinPath
	agentCACertPath   = optDir + "/ca.pem"
	agentCABundlePath = optDir + "/ca-bundle.pem"
	agentSSHConfig    = optDir + "/ssh/config"
	agentKnownHosts   = optDir + "/ssh/known_hosts"
	agentSSHClient    = "/usr/bin/ssh"
	defaultProxyPort  = "8228"
	defaultSSHPort    = "8229"
)

func runWithBouncer(ctx context.Context, req Request, agentSpec container.Spec) error {
	setup := req.Bouncer
	envVars, err := hostEnvCreds(setup.PolicyYAML, req.SidecarEnv)
	if err != nil {
		return fmt.Errorf("host env credentials: %w", err)
	}
	provided, err := hostProvidedCreds(ctx, setup.PolicyYAML, req.Provided)
	if err != nil {
		return fmt.Errorf("host credentials: %w", err)
	}
	sshNames, err := sshKeyCredentialNames(setup.PolicyYAML)
	if err != nil {
		return fmt.Errorf("ssh credentials: %w", err)
	}
	err = unlockHostSSHKeys(provided, sshNames, func(name string) (string, error) {
		return readSSHKeyPassphrase(ctx, req, name)
	})
	if err != nil {
		return fmt.Errorf("ssh key: %w", err)
	}
	sshSock, err := hostSSHAuthSock(setup.PolicyYAML)
	if err != nil {
		return fmt.Errorf("ssh-agent: %w", err)
	}

	hostPort, err := freeLocalPort()
	if err != nil {
		return fmt.Errorf("management port: %w", err)
	}

	labels := sessionLabels(setup.ContextName, req.Project, req.Slug, roleBouncer)
	agentNetName := running.ResourceName(req.Project, req.Slug, roleAgent)
	extNetName := running.ResourceName(req.Project, req.Slug, roleExt)

	cleanup := context.WithoutCancel(ctx)

	agentNetID, err := req.Runtime.CreateNetwork(ctx, container.NetworkSpec{
		Name:     agentNetName,
		Internal: true,
		Labels:   labels,
	})
	if err != nil {
		return fmt.Errorf("create agent network: %w", err)
	}
	defer func() { _ = req.Runtime.RemoveNetwork(cleanup, agentNetID) }()

	extNetID, err := req.Runtime.CreateNetwork(ctx, container.NetworkSpec{
		Name:   extNetName,
		Labels: labels,
	})
	if err != nil {
		return fmt.Errorf("create external network: %w", err)
	}
	defer func() { _ = req.Runtime.RemoveNetwork(cleanup, extNetID) }()

	agentNet, err := req.Runtime.InspectNetwork(ctx, agentNetID)
	if err != nil {
		return fmt.Errorf("inspect agent network: %w", err)
	}
	extNet, err := req.Runtime.InspectNetwork(ctx, extNetID)
	if err != nil {
		return fmt.Errorf("inspect external network: %w", err)
	}

	sidecarSpec := withSSHAuthSock(bouncerSidecarSpec(
		req, labels, extNetName, agentNetName, agentNet.Subnet, extNet.Subnet, hostPort,
	), sshSock)
	sidecarID, err := req.Runtime.Create(ctx, sidecarSpec)
	if err != nil {
		return fmt.Errorf("create bouncer sidecar: %w", err)
	}
	defer func() { _ = req.Runtime.Remove(cleanup, sidecarID, true) }()

	token := daemon.NewAdminToken()
	err = copySidecarPayload(ctx, req, sidecarID, token)
	if err != nil {
		return fmt.Errorf("copy sidecar payload: %w", err)
	}

	err = req.Runtime.Start(ctx, sidecarID)
	if err != nil {
		return fmt.Errorf("start bouncer sidecar: %w", err)
	}

	client := mgmt.New(fmt.Sprintf("http://127.0.0.1:%d", hostPort), token)
	err = waitUntilServing(ctx, client)
	if err != nil {
		return fmt.Errorf("wait for bouncer: %w", err)
	}
	err = client.PutEnv(envVars)
	if err != nil {
		return fmt.Errorf("put env credentials: %w", err)
	}
	err = client.PutProvided(provided)
	if err != nil {
		return fmt.Errorf("put host credentials: %w", err)
	}
	err = waitReady(ctx, client)
	if err != nil {
		return fmt.Errorf("wait for bouncer: %w", err)
	}

	err = running.Write(req.Home, running.Record{
		Context:     setup.ContextName,
		Project:     req.Project,
		Slug:        req.Slug,
		Cwd:         req.Cwd,
		ControlAddr: fmt.Sprintf("127.0.0.1:%d", hostPort),
		Token:       token,
		ContainerID: sidecarID,
		PID:         os.Getpid(),
		Started:     time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		return fmt.Errorf("write running record: %w", err)
	}
	defer func() { _ = running.Remove(req.Home, req.Slug) }()

	session, err := client.CreateSession(req.Slug, "", "agentcon", "")
	if err != nil {
		return fmt.Errorf("bouncer session: %w", err)
	}

	info, err := req.Runtime.Inspect(ctx, sidecarID)
	if err != nil {
		return fmt.Errorf("inspect sidecar: %w", err)
	}
	agentIP := info.Networks[agentNetName].IP
	if agentIP == "" {
		return fmt.Errorf("bouncer sidecar has no IP on the agent network")
	}

	agentSpec.Name = running.ResourceName(req.Project, req.Slug, roleAgent)
	agentSpec.Labels = sessionLabels(setup.ContextName, req.Project, req.Slug, roleAgent)
	agentSpec.Networks = []string{agentNetName}
	agentSpec.Env = append(agentSpec.Env, bouncerAgentEnv(session, agentIP)...)

	if req.Stderr != nil {
		project := req.Project
		if project == "" {
			project = "."
		}
		_, _ = fmt.Fprintf(req.Stderr, "agentcon session %s project %s\n", req.Slug, project)
	}

	go notifyPrompts(ctx, client, req.Stderr)

	id, err := req.Runtime.Create(ctx, agentSpec)
	if err != nil {
		return fmt.Errorf("create agent container: %w", err)
	}
	defer func() { _ = req.Runtime.Remove(cleanup, id, true) }()

	err = copyAgentFiles(ctx, req, id, client)
	if err != nil {
		return fmt.Errorf("copy bouncer files into agent: %w", err)
	}

	err = req.Runtime.AttachStartWait(ctx, id, agentSpec)
	if err != nil {
		return fmt.Errorf("run container: %w", err)
	}
	return nil
}

func bouncerSidecarSpec(
	req Request,
	labels map[string]string,
	extNetName, agentNetName, agentSubnet, extSubnet string,
	hostPort int,
) container.Spec {
	return container.Spec{
		Name:       running.ResourceName(req.Project, req.Slug, roleBouncer),
		Image:      sidecarImage,
		User:       req.User,
		GroupAdd:   []string{groupRoot},
		Entrypoint: []string{sidecarBinPath},
		Args: []string{
			roleBouncer, "serve",
			"--file", sidecarConfigPath,
			"--state-dir", sidecarStatePath,
			"--quiet",
		},
		Env: []string{
			"AGENT_NETWORK=" + agentSubnet,
			"MANAGEMENT_NETWORK=" + extSubnet,
			"MANAGEMENT_PORT=" + defaultProxyPort,
		},
		Networks: []string{extNetName, agentNetName},
		Ports: []container.Port{{
			HostIP:        "127.0.0.1",
			HostPort:      strconv.Itoa(hostPort),
			ContainerPort: defaultProxyPort,
			Protocol:      "tcp",
		}},
		Labels:     labels,
		ExtraHosts: req.SidecarExtraHosts,
	}
}

func withSSHAuthSock(spec container.Spec, sock string) container.Spec {
	if sock == "" {
		return spec
	}
	spec.Mounts = append(spec.Mounts, container.Mount{
		Source: sock,
		Target: sidecarSSHAuthSock,
	})
	spec.Env = append(spec.Env, "SSH_AUTH_SOCK="+sidecarSSHAuthSock)
	return spec
}

func copySidecarPayload(ctx context.Context, req Request, id, token string) error {
	setup := req.Bouncer
	bin, err := linuxAgentcon(req.LinuxBinary)
	if err != nil {
		return fmt.Errorf("linux binary: %w", err)
	}
	uid, gid := parseContainerUser(req.User)
	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		err := writeSidecarPayload(pw, setup.PolicyYAML, setup.TSFiles, bin, token, uid, gid)
		if err != nil {
			_ = pw.CloseWithError(err)
			errCh <- err
			return
		}
		errCh <- pw.Close()
	}()
	copyErr := req.Runtime.CopyTo(ctx, id, "/", pr)
	_ = pr.Close()
	writeErr := <-errCh
	if copyErr != nil {
		return fmt.Errorf("copy sidecar files: %w", copyErr)
	}
	if writeErr != nil {
		return fmt.Errorf("pack sidecar files: %w", writeErr)
	}
	return nil
}

func parseContainerUser(user string) (int, int) {
	if user == "" {
		return 0, 0
	}
	uidStr, gidStr, ok := strings.Cut(user, ":")
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return 0, 0
	}
	if !ok {
		return uid, uid
	}
	gid, err := strconv.Atoi(gidStr)
	if err != nil {
		return uid, uid
	}
	return uid, gid
}

func linuxAgentcon(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("executable: %w", err)
		}
		return exe, nil
	}
	ver := version.Version()
	if ver == "" || ver == "0.0.0" || ver == "dev" {
		return "", fmt.Errorf("host is %s/%s; build a linux amd64 agentcon or run from a released version", runtime.GOOS, runtime.GOARCH)
	}
	return "", fmt.Errorf("host is %s/%s; copy a linux amd64 agentcon into the sidecar (release %s)", runtime.GOOS, runtime.GOARCH, ver)
}

func copyAgentFiles(ctx context.Context, req Request, id string, client *mgmt.Client) error {
	bin, err := linuxAgentcon(req.LinuxBinary)
	if err != nil {
		return fmt.Errorf("linux binary: %w", err)
	}
	trust, err := client.Trust()
	if err != nil {
		return fmt.Errorf("fetch bouncer CA: %w", err)
	}
	uid, gid := parseContainerUser(req.User)
	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		err := writeAgentPayload(pw, bin, trust.CertPEM, trust.BundlePEM, trust.SSHKnownHosts, uid, gid)
		if err != nil {
			_ = pw.CloseWithError(err)
			errCh <- err
			return
		}
		errCh <- pw.Close()
	}()
	copyErr := req.Runtime.CopyTo(ctx, id, "/", pr)
	_ = pr.Close()
	writeErr := <-errCh
	if copyErr != nil {
		return fmt.Errorf("copy agent files: %w", copyErr)
	}
	if writeErr != nil {
		return fmt.Errorf("pack agent files: %w", writeErr)
	}
	return nil
}

func bouncerAgentEnv(session daemon.NewSession, agentIP string) []string {
	proxy := net.JoinHostPort(agentIP, defaultProxyPort)
	ssh := net.JoinHostPort(agentIP, defaultSSHPort)
	env := envexport.Build(envexport.Params{
		ProxyAddr:    proxy,
		SSHAddr:      ssh,
		Token:        session.Token,
		SessionID:    session.ID,
		CACert:       agentCACertPath,
		CABundle:     agentCABundlePath,
		SSHCommand:   fmt.Sprintf(`"%s" -F "%s"`, agentSSHClient, agentSSHConfig),
		Placeholders: session.Placeholders,
	})
	out := make([]string, 0, len(env.Vars))
	for _, kv := range env.Vars {
		out = append(out, kv[0]+"="+kv[1])
	}
	return out
}

func freeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocate port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitUntilServing(ctx context.Context, client *mgmt.Client) error {
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return fmt.Errorf("wait bouncer: %w", ctx.Err())
		}
		_, err := client.Status()
		if err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for bouncer management API")
}

// waitReady waits for the sidecar to finish preparing credentials. Any
// prompts it raises meanwhile can be answered with `agentcon bouncer answer`.
func waitReady(ctx context.Context, client *mgmt.Client) error {
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return fmt.Errorf("wait bouncer: %w", ctx.Err())
		}
		status, err := client.Status()
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if status.Ready {
			return nil
		}
		if status.Error != "" {
			return fmt.Errorf("bouncer startup: %s", status.Error)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the bouncer to be ready")
}

func notifyPrompts(ctx context.Context, client *mgmt.Client, stderr io.Writer) {
	seen := map[string]bool{}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			list, err := client.Prompts()
			if err != nil {
				continue
			}
			for _, p := range list {
				if seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				what, command := "prompt", "answer"
				if p.Kind == prompt.KindConfirm {
					what, command = "approval", "approve"
				}
				_, _ = fmt.Fprintf(stderr, "bouncer: pending %s %s: %s (agentcon bouncer %s %s)\n",
					what, p.ID, approval.Display(p.Message, 150), command, p.ID)
			}
		}
	}
}
