//go:build issue44

// Smoke runs the github-ci-safety reference filter against real GitHub
// through a real `agentcon bouncer serve` on loopback. Two tokens come from
// Bitwarden: the agent's ordinary PAT, and an elevated github-audit PAT
// that may only read the repo's Actions secrets list. The sidecar's vault
// prompts are answered at this terminal. Nothing secret is written to disk
// or printed.
//
//  1. The agent asks for the Actions secrets list, naming github-audit's
//     placeholder. Bouncer sends the agent's own token instead, so GitHub
//     refuses it (expected failure).
//  2. A new branch smoke/elevated-<random> is pushed. The filter looks up the
//     secrets list with github-audit. The push is allowed when the repo has
//     no Actions secrets, then the branch is deleted, or denied with the
//     filter's reason when it has some.
//  3. The audit log shows github-audit only on the filter's lookups, each
//     answered 200, and never on an agent request.
//
// Run it with:
//
//	go build -o /tmp/agentcon ./cmd/agentcon
//	go run -tags issue44 ./ad_hoc/issue-44/smoke -agentcon /tmp/agentcon \
//	  -bitwarden-email you@example.com -token-item pat-github-pastdev-agent \
//	  -audit-item agentcon-smoke-github-audit
//
// It ends with SMOKE PASSED or SMOKE FAILED: <reason>.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pastdev/agentcon/pkg/bouncer/host"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
)

const (
	loopback  = "127.0.0.1"
	repoSlug  = "pastdev/agentcon"
	base      = "master"
	filter    = "github-ci-safety"
	gitConfig = "config"
	audit     = "github-audit"
	ordinary  = "github"
)

func main() {
	bin := flag.String("agentcon", "", "agentcon binary to run as the bouncer")
	email := flag.String("bitwarden-email", "", "Bitwarden account that holds both tokens")
	tokenItem := flag.String("token-item", "", "Bitwarden item with the agent's GitHub PAT")
	tokenPath := flag.String("token-path", "$.notes", "JSONPath of the agent's token in its item")
	auditItem := flag.String("audit-item", "", "Bitwarden item with the github-audit PAT (Secrets: Read-only)")
	auditPath := flag.String("audit-path", "$.notes", "JSONPath of the github-audit token in its item")
	flag.Parse()
	s := &smoke{}
	err := s.run(*bin, *email, *tokenItem, *tokenPath, *auditItem, *auditPath)
	if err != nil {
		fmt.Printf("SMOKE FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("SMOKE PASSED")
}

type smoke struct {
	bin, dir, policy, state, auditPath string
	proxyAddr, sshAddr                 string
	cmd                                *exec.Cmd
	client                             *mgmt.Client
	repo                               string
	env                                []string
	created                            string
}

func (s *smoke) run(bin, email, tokenItem, tokenPath, auditItem, auditPath string) error {
	if bin == "" || email == "" || tokenItem == "" || auditItem == "" {
		return errors.New("-agentcon, -bitwarden-email, -token-item, and -audit-item are required")
	}
	bin, err := filepath.Abs(bin)
	if err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	s.bin = bin
	s.dir, err = os.MkdirTemp("", "acelev")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(s.dir) }()
	s.state = filepath.Join(s.dir, "state")
	s.auditPath = filepath.Join(s.dir, "audit.log")
	s.repo = filepath.Join(s.dir, "repo")
	ctx := context.Background()

	fmt.Println("1. start the bouncer with both tokens sourced from Bitwarden")
	err = s.writePolicy(email, tokenItem, tokenPath, auditItem, auditPath)
	if err != nil {
		return err
	}
	err = s.start()
	if err != nil {
		return err
	}
	defer s.stop()

	fmt.Println("2. the sidecar unlocks the vault; answer its prompts here")
	err = host.WaitReady(ctx, s.client, host.PromptOptions{Stdin: os.Stdin, Stderr: os.Stderr, Timeout: 5 * time.Minute})
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}

	fmt.Println("3. create a session")
	sess, err := s.client.CreateSession(ctx, "", "", "elevated-smoke", "")
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	err = s.agent(ctx, sess)
	if err != nil {
		return err
	}

	fmt.Println("4. the agent asks for the Actions secrets list with " + audit + "'s placeholder; GitHub refuses the agent's own token (expected failure)")
	status, err := s.agentSecrets(ctx)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		return errors.New("the agent read the Actions secrets list; check that the agent PAT has no Secrets permission, then see the audit check")
	}
	fmt.Printf("   expected: GitHub answered %d\n", status)

	fmt.Println("5. fetch " + base + " and commit an empty change")
	err = s.setupRepo()
	if err != nil {
		return err
	}

	suffix, err := randomHex(4)
	if err != nil {
		return err
	}
	branch := "smoke/elevated-" + suffix
	fmt.Println("6. push " + branch + "; the filter looks up Actions secrets with " + audit)
	lookups := 1
	out, err := s.git("push", "origin", "HEAD:refs/heads/"+branch)
	switch {
	case err == nil:
		s.created = branch
		defer s.cleanup()
		fmt.Println("   allowed: the repo has no repository Actions secrets: " + firstLine(out, "[new branch]"))
		fmt.Println("7. delete " + branch + "; the filter looks up again and allows it")
		out, err = s.git("push", "origin", ":refs/heads/"+branch)
		if err != nil {
			return fmt.Errorf("delete %s: %w: %s", branch, err, strings.TrimSpace(out))
		}
		s.created = ""
		lookups++
		fmt.Println("   " + firstLine(out, "[deleted]"))
	case strings.Contains(out, "denied by "+filter) && strings.Contains(out, "has repository Actions secrets"):
		fmt.Println("   denied: the repo has repository Actions secrets: " + firstLine(out, "denied by "+filter))
		fmt.Println("7. skipped: nothing to delete")
	default:
		return fmt.Errorf("push %s failed without the filter's verdict: %s", branch, strings.TrimSpace(out))
	}

	fmt.Println("8. the audit log shows " + audit + " only on the filter's lookups")
	s.stop()
	return s.checkAudit(sess.ID, lookups)
}

// agentSecrets asks for the secrets list as the agent, naming the elevated
// credential's static placeholder, and returns GitHub's status.
func (s *smoke) agentSecrets(ctx context.Context) (int, error) {
	client, err := s.httpClient()
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+repoSlug+"/actions/secrets?per_page=1", nil)
	if err != nil {
		return 0, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer bouncer-placeholder-"+audit)
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("agent secrets list: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// cleanup deletes the smoke branch when a step after its creation failed.
func (s *smoke) cleanup() {
	if s.created == "" {
		return
	}
	out, err := s.git("push", "origin", ":refs/heads/"+s.created)
	if err != nil {
		fmt.Printf("   could not delete %s; delete it by hand: %s\n", s.created, strings.TrimSpace(out))
	}
}

// copyFilter copies the reference filter next to the policy.
func (s *smoke) copyFilter() error {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("no caller")
	}
	src := filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "bouncer", "reference", "ts", "filters", filter+".ts")
	data, err := os.ReadFile(src) //nolint:gosec // repo file
	if err != nil {
		return fmt.Errorf("read filter: %w", err)
	}
	err = os.MkdirAll(filepath.Join(s.dir, "ts"), 0o700)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	err = os.WriteFile(filepath.Join(s.dir, "ts", filter+".ts"), data, 0o600) //nolint:gosec // fixed name under the smoke temp dir
	if err != nil {
		return fmt.Errorf("write filter: %w", err)
	}
	return nil
}

func (s *smoke) writePolicy(email, tokenItem, tokenPath, auditItem, auditPath string) error {
	err := s.copyFilter()
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
	s.proxyAddr = net.JoinHostPort(loopback, strconv.Itoa(proxyPort))
	s.sshAddr = net.JoinHostPort(loopback, strconv.Itoa(sshPort))
	policy := fmt.Sprintf(`
listen: %s
ssh_listen: %s
default_profile: agent
prompts: {notify: false, terminal: false, cli: true, timeout: 5m}
bitwarden:
  agent:
    email: %q
credentials:
  %s:
    allow: [agent, subrequest]
    cache: 10m
    token: {source: bitwarden, account: agent, item: %q, path: %q}
  %s:
    allow: [subrequest]
    cache: 10m
    token: {source: bitwarden, account: agent, item: %q, path: %q}
profiles:
  agent:
    unmatched: deny
    http:
      - name: github
        hosts: [github.com, api.github.com]
        credentials: [%s, %s]
        inject:
          credential: %s
          bearer: true
          git: {basic: {username: x-access-token}}
        default: deny
        rules:
          # The filter's lookup, and the only route %s can reach.
          - action: allow
            methods: [GET]
            github_repo: [%s]
            github_subpaths: ["actions/secrets"]
            subrequest:
              filters: [%s]
              credentials: [%s]
          # The agent's own access to the same path, with its own token.
          - action: allow
            methods: [GET]
            github_repo: [%s]
            github_subpaths: ["actions/secrets"]
          - action: allow
            git: {}
            github_repo: [%s]
            filters:
              - path: ts/%s.ts
                id: %s
`, s.proxyAddr, s.sshAddr, email, ordinary, tokenItem, tokenPath, audit, auditItem, auditPath,
		ordinary, audit, ordinary, audit, repoSlug, filter, audit, repoSlug, repoSlug, filter, filter)
	s.policy = filepath.Join(s.dir, "policy.yaml")
	err = os.WriteFile(s.policy, []byte(policy), 0o600)
	if err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	return nil
}

func (s *smoke) setupRepo() error {
	err := os.Mkdir(s.repo, 0o700)
	if err != nil {
		return fmt.Errorf("repo: %w", err)
	}
	steps := [][]string{
		{"init", "-q", "-b", "work"},
		{gitConfig, "user.name", "Elevated Smoke"},
		{gitConfig, "user.email", "agent@example.com"},
		{gitConfig, "commit.gpgsign", "false"},
		{gitConfig, "credential.helper", ""},
		{"remote", "add", "origin", "https://github.com/" + repoSlug + ".git"},
		{"fetch", "-q", "--depth", "1", "origin", "refs/heads/" + base},
		{"reset", "-q", "--hard", "FETCH_HEAD"},
		{"commit", "-q", "--allow-empty", "-m", "elevated smoke: throwaway branch"},
	}
	for _, args := range steps {
		out, err := s.git(args...)
		if err != nil {
			return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
		}
	}
	return nil
}

// auditLine is the part of a decision entry the smoke checks.
type auditLine struct {
	Event       string   `json:"event"`
	Session     string   `json:"session"`
	Service     string   `json:"service"`
	Request     string   `json:"request"`
	Decision    string   `json:"decision"`
	By          string   `json:"by"`
	Status      int      `json:"status"`
	Credentials []string `json:"credentials"`
	Subrequest  *struct {
		Filter string `json:"filter"`
		ID     string `json:"id"`
		Depth  int    `json:"depth"`
	} `json:"subrequest"`
}

// checkAudit wants github-audit on each of the filter's lookups, each
// answered 200, and on no agent request. The agent's secrets request must
// have carried only the ordinary token.
func (s *smoke) checkAudit(sessionID string, lookups int) error {
	data, err := os.ReadFile(s.auditPath)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	var subs, agentSecrets int
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m auditLine
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.Event != "decision" || m.Session != sessionID {
			continue
		}
		if m.Subrequest != nil {
			fmt.Printf("   %s %s -> %d [subrequest from %s as %s]\n", m.Decision, m.Request, m.Status, m.Subrequest.ID, strings.Join(m.Credentials, ","))
			if m.Subrequest.Filter != filter || m.Subrequest.ID != filter || m.Decision != "allow" || m.Service != "github" ||
				m.Status != http.StatusOK || !slices.Equal(m.Credentials, []string{audit}) ||
				!strings.Contains(m.Request, "/repos/"+repoSlug+"/actions/secrets") {
				return fmt.Errorf("unexpected subrequest entry: %s", sc.Text())
			}
			subs++
			continue
		}
		fmt.Printf("   %s %s -> %d [as %s]\n", m.Decision, m.Request, m.Status, strings.Join(m.Credentials, ","))
		if slices.Contains(m.Credentials, audit) {
			return fmt.Errorf("an agent request carried %s: %s", audit, sc.Text())
		}
		if strings.Contains(m.Request, "/actions/secrets") {
			if m.Decision != "allow" || !slices.Equal(m.Credentials, []string{ordinary}) {
				return fmt.Errorf("the agent's secrets request did not go out with only %s: %s", ordinary, sc.Text())
			}
			agentSecrets++
		}
	}
	if subs != lookups || agentSecrets != 1 {
		return fmt.Errorf("audit has %d filter lookups and %d agent secrets requests, want %d and 1", subs, agentSecrets, lookups)
	}
	return nil
}

// httpClient sends requests through the bouncer with the agent's proxy and
// CA settings.
func (s *smoke) httpClient() (*http.Client, error) {
	var proxy, caFile string
	for _, kv := range s.env {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "HTTPS_PROXY":
			proxy = v
		case "SSL_CERT_FILE":
			caFile = v
		}
	}
	proxyURL, err := url.Parse(proxy)
	if err != nil || proxy == "" {
		return nil, fmt.Errorf("agent HTTPS_PROXY %q: %w", proxy, err)
	}
	pem, err := os.ReadFile(caFile) //nolint:gosec // the agent payload's CA file
	if err != nil {
		return nil, fmt.Errorf("agent CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("agent CA: no certificates")
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}, nil
}

func (s *smoke) start() error {
	logf, err := os.OpenFile(s.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	s.cmd = exec.Command(s.bin, "bouncer", "serve", "--file", s.policy, "--state-dir", s.state, //nolint:gosec // operator-supplied binary
		"--log", "warn", "--log", "bouncer=warn", "--log", "audit=info", "--log-format", "json")
	s.cmd.Stdout, s.cmd.Stderr = logf, logf
	err = s.cmd.Start()
	if err != nil {
		return fmt.Errorf("start bouncer: %w", err)
	}
	err = waitTCP(s.proxyAddr)
	if err != nil {
		return fmt.Errorf("bouncer listen: %w", err)
	}
	token, err := os.ReadFile(filepath.Join(s.state, "admin-token"))
	if err != nil {
		return fmt.Errorf("admin token: %w", err)
	}
	s.client = mgmt.New("http://"+s.proxyAddr, strings.TrimSpace(string(token)))
	return nil
}

func (s *smoke) stop() {
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _ = s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
		<-done
	}
	s.cmd = nil
}

// agent unpacks the real agent payload under the temp dir and builds the
// real agent environment, as agentcon run does for a container.
func (s *smoke) agent(ctx context.Context, sess mgmt.NewSession) error {
	trust, err := s.client.Trust(ctx)
	if err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	root := filepath.Join(s.dir, "agent")
	sshClient, err := exec.LookPath("ssh")
	if err != nil {
		sshClient = "/usr/bin/ssh"
	}
	layout := host.AgentLayout{
		Binary:     root + "/bin/agentcon",
		CACert:     root + "/ca.pem",
		CABundle:   root + "/ca-bundle.pem",
		SSHConfig:  root + "/ssh/config",
		KnownHosts: root + "/ssh/known_hosts",
		GitSign:    root + "/bin/git-sign",
		SSHClient:  sshClient,
	}
	var buf bytes.Buffer
	err = host.WriteAgentPayload(&buf, host.AgentPayload{Layout: layout, Binary: s.bin, Trust: trust, UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		return fmt.Errorf("agent payload: %w", err)
	}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("agent payload: %w", err)
		}
		dst := "/" + hdr.Name
		if !strings.HasPrefix(dst, root+"/") {
			continue
		}
		if hdr.Typeflag == tar.TypeDir {
			err = os.MkdirAll(dst, 0o700)
			if err != nil {
				return fmt.Errorf("mkdir: %w", err)
			}
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("agent payload: %w", err)
		}
		err = os.MkdirAll(filepath.Dir(dst), 0o700)
		if err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}
		err = os.WriteFile(dst, data, os.FileMode(hdr.Mode)) //nolint:gosec // payload modes from our own tar
		if err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
	}
	agentEnv, err := host.AgentEnv(layout, sess, s.proxyAddr, s.sshAddr)
	if err != nil {
		return fmt.Errorf("agent env: %w", err)
	}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasSuffix(strings.ToLower(k), "_proxy") || k == "SSL_CERT_FILE" || strings.HasPrefix(k, "GIT_") || k == "SSH_AUTH_SOCK" {
			continue
		}
		s.env = append(s.env, kv)
	}
	s.env = append(s.env, agentEnv...)
	// A temp HOME and no system config keep the operator's git credential
	// helpers out, so only the bouncer can authenticate.
	s.env = append(s.env, "HOME="+s.dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	return nil
}

func (s *smoke) git(args ...string) (string, error) {
	cmd := exec.Command("git", args...) //nolint:gosec // smoke runs git
	cmd.Dir, cmd.Env = s.repo, s.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func firstLine(out, has string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, has) {
			return strings.TrimSpace(l)
		}
	}
	return strings.TrimSpace(out)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(loopback, "0"))
	if err != nil {
		return 0, fmt.Errorf("free port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitTCP(addr string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("%s not listening", addr)
}
