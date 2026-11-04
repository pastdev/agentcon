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

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/envexport"
	"github.com/pastdev/agentcon/internal/bouncer/mgmt"
	"github.com/pastdev/agentcon/internal/bouncer/running"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/pastdev/agentcon/pkg/version"
	"golang.org/x/term"
)

const (
	optDir            = "/opt/agentcon"
	sidecarHome       = optDir
	sidecarConfigPath = optDir + "/config.yaml"
	sidecarBinPath    = optDir + "/bin/agentcon"
	sidecarStatePath  = optDir + "/state"
	agentBinPath      = sidecarBinPath
	agentCACertPath   = optDir + "/ca.pem"
	agentCABundlePath = optDir + "/ca-bundle.pem"
	agentSSHConfig    = optDir + "/ssh/config"
	agentKnownHosts   = optDir + "/ssh/known_hosts"
	defaultProxyPort  = "8228"
	defaultSSHPort    = "8229"
)

func runWithBouncer(ctx context.Context, req Request, agentSpec container.Spec) error {
	setup := req.Bouncer
	hostPort, err := freeLocalPort()
	if err != nil {
		return fmt.Errorf("management port: %w", err)
	}

	labels := map[string]string{
		"agentcon.context": setup.ContextName,
		"agentcon.role":    "bouncer",
	}
	suffix := strconv.Itoa(os.Getpid())
	agentNetName := fmt.Sprintf("agentcon-%s-agent-%s", sanitizeName(setup.ContextName), suffix)
	extNetName := fmt.Sprintf("agentcon-%s-ext-%s", sanitizeName(setup.ContextName), suffix)

	agentNetID, err := req.Runtime.CreateNetwork(ctx, container.NetworkSpec{
		Name:     agentNetName,
		Internal: true,
		Labels:   labels,
	})
	if err != nil {
		return fmt.Errorf("create agent network: %w", err)
	}
	defer func() { _ = req.Runtime.RemoveNetwork(ctx, agentNetID) }()

	extNetID, err := req.Runtime.CreateNetwork(ctx, container.NetworkSpec{
		Name:   extNetName,
		Labels: labels,
	})
	if err != nil {
		return fmt.Errorf("create external network: %w", err)
	}
	defer func() { _ = req.Runtime.RemoveNetwork(ctx, extNetID) }()

	agentNet, err := req.Runtime.InspectNetwork(ctx, agentNetID)
	if err != nil {
		return fmt.Errorf("inspect agent network: %w", err)
	}
	extNet, err := req.Runtime.InspectNetwork(ctx, extNetID)
	if err != nil {
		return fmt.Errorf("inspect external network: %w", err)
	}

	sidecarID, err := req.Runtime.Create(ctx, container.Spec{
		Image:      req.Image,
		User:       req.User,
		GroupAdd:   []string{groupRoot},
		Entrypoint: []string{"sleep", "infinity"},
		Networks:   []string{extNetName, agentNetName},
		Ports: []container.Port{{
			HostIP:        "127.0.0.1",
			HostPort:      strconv.Itoa(hostPort),
			ContainerPort: defaultProxyPort,
			Protocol:      "tcp",
		}},
		Labels:     labels,
		ExtraHosts: req.SidecarExtraHosts,
	})
	if err != nil {
		return fmt.Errorf("create bouncer sidecar: %w", err)
	}
	defer func() { _ = req.Runtime.Remove(ctx, sidecarID, true) }()

	token := daemon.NewAdminToken()
	err = copySidecarPayload(ctx, req, sidecarID, token)
	if err != nil {
		return fmt.Errorf("copy sidecar payload: %w", err)
	}

	err = req.Runtime.Start(ctx, sidecarID)
	if err != nil {
		return fmt.Errorf("start bouncer sidecar: %w", err)
	}

	execEnv := []string{
		"AGENT_NETWORK=" + agentNet.Subnet,
		"MANAGEMENT_NETWORK=" + extNet.Subnet,
		"MANAGEMENT_PORT=" + defaultProxyPort,
	}
	execEnv = append(execEnv, req.SidecarEnv...)
	err = req.Runtime.Exec(ctx, sidecarID, container.Exec{
		Cmd:    []string{sidecarBinPath, "bouncer", "serve", "--file", sidecarConfigPath, "--state-dir", sidecarStatePath, "--quiet"},
		Env:    execEnv,
		Detach: true,
	})
	if err != nil {
		return fmt.Errorf("exec bouncer serve: %w", err)
	}

	client := mgmt.New(fmt.Sprintf("http://127.0.0.1:%d", hostPort), token)
	err = waitReady(ctx, client, req)
	if err != nil {
		return fmt.Errorf("wait for bouncer: %w", err)
	}

	err = running.Write(req.Home, running.Record{
		Context:     setup.ContextName,
		ControlAddr: fmt.Sprintf("127.0.0.1:%d", hostPort),
		Token:       token,
		ContainerID: sidecarID,
		PID:         os.Getpid(),
		Started:     time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		return fmt.Errorf("write running record: %w", err)
	}
	defer func() { _ = running.Remove(req.Home, setup.ContextName) }()

	session, err := client.CreateSession("", "agentcon", "")
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

	agentSpec.Networks = []string{agentNetName}
	agentSpec.Env = append(agentSpec.Env, bouncerAgentEnv(session, agentIP)...)

	go notifyApprovals(ctx, client, req.Stderr)

	id, err := req.Runtime.Create(ctx, agentSpec)
	if err != nil {
		return fmt.Errorf("create agent container: %w", err)
	}
	defer func() { _ = req.Runtime.Remove(ctx, id, true) }()

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
		SSHCommand:   fmt.Sprintf(`"%s" -F "%s"`, agentBinPath, agentSSHConfig),
		Placeholders: session.Placeholders,
	})
	out := make([]string, 0, len(env.Vars))
	for _, kv := range env.Vars {
		out = append(out, kv[0]+"="+kv[1])
	}
	return out
}

func sanitizeName(name string) string {
	out := strings.Builder{}
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out.WriteRune(r)
			continue
		}
		out.WriteByte('-')
	}
	s := strings.Trim(out.String(), "-")
	if s == "" {
		return "ctx"
	}
	return s
}

func freeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocate port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitReady(ctx context.Context, client *mgmt.Client, req Request) error {
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
		if len(status.BitwardenPending) > 0 {
			err = unlockBitwarden(client, req, status.BitwardenPending[0])
			if err != nil {
				return fmt.Errorf("bitwarden unlock: %w", err)
			}
			continue
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for bouncer management API")
}

func unlockBitwarden(client *mgmt.Client, req Request, label string) error {
	fd := -1
	if f, ok := req.Stdin.(*os.File); ok {
		fd = int(f.Fd())
	}
	if fd < 0 || !term.IsTerminal(fd) {
		return fmt.Errorf("bitwarden vault %s needs a master password (run from a terminal)", label)
	}
	_, _ = fmt.Fprintf(req.Stderr, "Bitwarden master password for %s: ", label)
	pw, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(req.Stderr)
	if err != nil {
		return fmt.Errorf("read bitwarden password: %w", err)
	}
	err = client.UnlockBitwarden(string(pw), "")
	if err != nil {
		return fmt.Errorf("unlock bitwarden: %w", err)
	}
	return nil
}

func notifyApprovals(ctx context.Context, client *mgmt.Client, stderr io.Writer) {
	seen := map[string]bool{}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			list, err := client.Approvals()
			if err != nil {
				continue
			}
			for _, p := range list {
				if seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				_, _ = fmt.Fprintf(stderr, "bouncer: pending approval %s: %s (agentcon bouncer approve %s)\n", p.ID, p.Prompt, p.ID)
			}
		}
	}
}
