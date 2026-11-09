//go:build issue9

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/container/moby"
	pkgrun "github.com/pastdev/agentcon/pkg/run"
)

const defaultImage = "pastdev.com/agentcon:latest"

func runDocker() error {
	image := os.Getenv("AGENTCON_IMAGE")
	if image == "" {
		image = defaultImage
	}
	root, err := repoRoot()
	if err != nil {
		return fmt.Errorf("repo root: %w", err)
	}
	rt, err := moby.New()
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer func() { _ = rt.Close() }()

	dir, err := os.MkdirTemp("", "agentcon-bouncer-docker-smoke-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	workspace := filepath.Join(dir, "workspace")
	home := filepath.Join(dir, "home")
	err = os.MkdirAll(workspace, 0o700)
	if err != nil {
		return fmt.Errorf("mkdir workspace: %w", err)
	}
	err = os.MkdirAll(home, 0o700)
	if err != nil {
		return fmt.Errorf("mkdir home: %w", err)
	}

	agentconBin := filepath.Join(dir, "agentcon")
	agentBin := filepath.Join(workspace, "agent")
	err = goBuild(root, agentconBin, "./cmd/agentcon")
	if err != nil {
		return err
	}
	err = goBuild(root, agentBin, "./ad_hoc/issue-9/smoke")
	if err != nil {
		return err
	}

	svcPort, err := freePort()
	if err != nil {
		return err
	}
	svcErr := make(chan error, 1)
	go func() {
		svcErr <- serveSecret(netJoinAll(svcPort), realSecret)
	}()
	err = waitTCP(netJoinLoopback(svcPort))
	if err != nil {
		return fmt.Errorf("secret service: %w", err)
	}

	hostSvc := "host.docker.internal:" + strconv.Itoa(svcPort)
	tsFiles, err := smokeTSFiles()
	if err != nil {
		return err
	}
	policy := smokePolicy("127.0.0.1:8228", "127.0.0.1:8229", hostSvc, fmt.Sprintf(`  %s:
    token:
      source: env
      env: SMOKE_TOKEN
    export_env: [SMOKE_TOKEN]
`, credName))

	fmt.Printf("secret service  http://%s (host)\n", netJoinLoopback(svcPort))
	fmt.Printf("  expects       Authorization: Bearer %s\n", realSecret)
	fmt.Printf("image           %s\n", image)
	fmt.Printf("agent holds     Authorization: Bearer %s\n\n", bouncercfg.Placeholder(credName))
	fmt.Println("starting sidecar + agent via pkg/run (tar payload, two networks)")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	err = pkgrun.Run(ctx, pkgrun.Request{
		Image:             image,
		Root:              workspace,
		Cwd:               workspace,
		Home:              home,
		User:              fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		Runtime:           rt,
		Context:           "smoke",
		LinuxBinary:       agentconBin,
		Entrypoint:        []string{"/workspace/agent"},
		Args:              []string{"-agent", "http://" + hostSvc},
		SidecarExtraHosts: []string{"host.docker.internal:host-gateway"},
		SidecarEnv:        []string{"SMOKE_TOKEN=" + realSecret},
		Stdin:             bytes.NewReader(nil),
		Stdout:            os.Stdout,
		Stderr:            os.Stderr,
		Bouncer: &pkgrun.BouncerSetup{
			ContextName: "smoke",
			PolicyYAML:  policy,
			TSFiles:     tsFiles,
		},
	})
	if err != nil {
		return fmt.Errorf("agentcon run: %w", err)
	}
	select {
	case err := <-svcErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	default:
	}
	return nil
}

func goBuild(root, out, pkg string) error {
	//nolint:gosec // go build of a repo-relative package path chosen by this smoke
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	outb, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, outb)
	}
	return nil
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cwd: %w", err)
	}
	dir := wd
	for {
		_, err := os.Stat(filepath.Join(dir, "go.mod"))
		if err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", wd)
		}
		dir = parent
	}
}

func netJoinAll(port int) string {
	return "0.0.0.0:" + strconv.Itoa(port)
}

func netJoinLoopback(port int) string {
	return loopback + ":" + strconv.Itoa(port)
}
