//go:build issue9

// Smoke demos bouncer.
//
// Default (no flags): one process on loopback. Secret service, bouncer, agent client.
//
//	go run ./ad_hoc/issue-9/smoke
//
// -docker: the real agentcon run path. Sidecar tar, two Docker networks, agent
// container. Needs Docker and AGENTCON_IMAGE (default pastdev.com/agentcon:latest).
//
//	go run ./ad_hoc/issue-9/smoke -docker
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/audit"
	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
)

const (
	loopback   = "127.0.0.1"
	realSecret = "real-service-token"
	credName   = "smoke"
)

func main() {
	docker := flag.Bool("docker", false, "exercise sidecar tar, two networks, and the agent container")
	agentURL := flag.String("agent", "", "in-container client against the secret service URL")
	flag.Parse()

	var err error
	switch {
	case *agentURL != "":
		err = runAgent(*agentURL)
	case *docker:
		err = runDocker()
	default:
		err = run()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	placeholder := bouncercfg.Placeholder(credName)
	svcPort, err := freePort()
	if err != nil {
		return err
	}
	proxyPort, err := freePort()
	if err != nil {
		return err
	}
	sshPort, err := freePort()
	if err != nil {
		return err
	}

	svcAddr := net.JoinHostPort(loopback, strconv.Itoa(svcPort))
	proxyAddr := net.JoinHostPort(loopback, strconv.Itoa(proxyPort))
	sshAddr := net.JoinHostPort(loopback, strconv.Itoa(sshPort))
	svcURL := "http://" + svcAddr

	svcErr := make(chan error, 1)
	go func() {
		svcErr <- serveSecret(svcAddr, realSecret)
	}()
	err = waitTCP(svcAddr)
	if err != nil {
		return fmt.Errorf("secret service: %w", err)
	}

	dir, err := os.MkdirTemp("", "agentcon-bouncer-smoke-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	tsFiles, err := smokeTSFiles()
	if err != nil {
		return err
	}
	policy := smokePolicy(proxyAddr, sshAddr, svcAddr, fmt.Sprintf(`  %s:
    token:
      source: provided
    export_env: [SMOKE_TOKEN]
`, credName))
	err = bouncercfg.WriteLayout(bouncercfg.DirFS(dir), policy, tsFiles)
	if err != nil {
		return fmt.Errorf("write layout: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, err := daemon.New(daemon.Options{
		ConfigPath: filepath.Join(dir, bouncercfg.FileName),
		StateDir:   filepath.Join(dir, "state"),
		Provided:   map[string]string{bouncercfg.ProvidedKey(credName, bouncercfg.SlotToken): realSecret},
		Logf:       func(string, ...any) {},
		Decision: func(e audit.Entry) {
			fmt.Printf("  bouncer: %s %s\n", strings.ToUpper(e.Decision), e.Request)
		},
	})
	if err != nil {
		return fmt.Errorf("bouncer: %w", err)
	}
	runErr := make(chan error, 1)
	go func() {
		runErr <- d.Run(ctx)
	}()
	err = waitTCP(proxyAddr)
	if err != nil {
		select {
		case runErr := <-runErr:
			if runErr != nil {
				return fmt.Errorf("bouncer: %w", runErr)
			}
		default:
		}
		return fmt.Errorf("bouncer listen: %w", err)
	}

	session, err := d.CreateSession("", "agent", "smoke-agent", 0)
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}

	direct := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	agent := newAgent(proxyAddr, session.Token)

	fmt.Printf("secret service  %s\n", svcURL)
	fmt.Printf("  expects       Authorization: Bearer %s\n", realSecret)
	fmt.Printf("bouncer proxy   http://%s\n", proxyAddr)
	fmt.Printf("agent holds     Authorization: Bearer %s\n\n", placeholder)

	fmt.Println("1. agent -> service directly, with the placeholder")
	err = expect(direct, svcURL+"/secret", placeholder, http.StatusUnauthorized, "")
	if err != nil {
		return err
	}
	fmt.Println("   service rejected the placeholder")

	fmt.Println("2. agent -> bouncer -> /secret, with the placeholder")
	err = expect(agent, svcURL+"/secret", placeholder, http.StatusOK, taggedBody)
	if err != nil {
		return err
	}
	fmt.Println("   bouncer injected the token, TS filter tagged the body via smoke-tag")

	fmt.Println("3. agent -> bouncer -> /secret?raw=1")
	err = expect(agent, svcURL+"/secret?raw=1", placeholder, http.StatusForbidden, filterDenied)
	if err != nil {
		return err
	}
	fmt.Println("   TS filter denied a request the path rule would allow")

	fmt.Println("4. agent -> bouncer -> /other")
	err = expect(agent, svcURL+"/other", placeholder, http.StatusForbidden, "")
	if err != nil {
		return err
	}
	fmt.Println("   bouncer denied a path with no allow rule")

	fmt.Println("5. agent -> bouncer -> http://example.com/")
	err = expect(agent, "http://example.com/", placeholder, http.StatusForbidden, "")
	if err != nil {
		return err
	}
	fmt.Println("   bouncer denied an unmatched host")

	fmt.Println("\nok")
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			return err
		}
	case <-time.After(2 * time.Second):
	}
	select {
	case err := <-svcErr:
		if err != nil && !strings.Contains(err.Error(), "Server closed") {
			return err
		}
	default:
	}
	return nil
}

func serveSecret(addr, secret string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		fmt.Printf("  service: %s %s auth=%q\n", r.Method, r.URL.Path, got)
		if got != "Bearer "+secret {
			http.Error(w, "unauthorized\n", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "pong\n")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	err = srv.Serve(l)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func newAgent(proxyAddr, token string) *http.Client {
	u := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("bouncer", token)}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
		},
	}
}

func expect(client *http.Client, rawURL, placeholder string, want int, contains string) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+placeholder)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	fmt.Printf("   HTTP %d %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode != want {
		return fmt.Errorf("got HTTP %d, want %d", resp.StatusCode, want)
	}
	if contains != "" && !strings.Contains(string(body), contains) {
		return fmt.Errorf("body %q, want %q", strings.TrimSpace(string(body)), contains)
	}
	return nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(loopback, "0"))
	if err != nil {
		return 0, fmt.Errorf("allocate port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitTCP(addr string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", addr)
}
