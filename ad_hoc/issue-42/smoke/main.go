//go:build issue42

// Smoke runs the github-branch-rules reference filter against real GitHub
// through a real `agentcon bouncer serve` on loopback. The token comes from
// a Bitwarden item, and the sidecar's vault prompts are answered at this
// terminal. Nothing secret is written to disk or printed.
//
// It needs a branch smoke/protected on pastdev/agentcon with a ruleset that
// restricts updates and deletions, with the token's owner on its bypass
// list. Then:
//
//  0. The token's owner can bypass that ruleset, so GitHub would accept
//     the push and only the filter stands in its way.
//  1. An empty commit pushed to smoke/protected is denied by the filter,
//     before GitHub sees it.
//  2. A new branch smoke/subrequest-<random> is pushed and allowed.
//  3. That branch is deleted and allowed.
//  4. With -ssh-item, step 1 is repeated over SSH.
//  5. The audit log has a subrequest entry for each lookup.
//
// Run it with:
//
//	go build -o /tmp/agentcon ./cmd/agentcon
//	go run -tags issue42 ./ad_hoc/issue-42/smoke -agentcon /tmp/agentcon \
//	  -bitwarden-email you@example.com -token-item pat-github-pastdev-agent
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
	"strconv"
	"strings"
	"time"

	"github.com/pastdev/agentcon/pkg/bouncer/host"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
)

const (
	loopback  = "127.0.0.1"
	repoSlug  = "pastdev/agentcon"
	protected = "smoke/protected"
	ruleset   = "smoke-protected"
	filter    = "github-branch-rules"
	gitConfig = "config"
)

func main() {
	bin := flag.String("agentcon", "", "agentcon binary to run as the bouncer")
	email := flag.String("bitwarden-email", "", "Bitwarden account that holds the token")
	tokenItem := flag.String("token-item", "", "Bitwarden item with the GitHub token")
	tokenPath := flag.String("token-path", "$.notes", "JSONPath of the token in the item")
	sshItem := flag.String("ssh-item", "", "optional Bitwarden item with an SSH key for GitHub; empty skips the SSH step")
	sshPath := flag.String("ssh-path", "$.sshKey.privateKey", "JSONPath of the SSH private key in the item")
	flag.Parse()
	s := &smoke{}
	err := s.run(*bin, *email, *tokenItem, *tokenPath, *sshItem, *sshPath)
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
	base                               string
}

func (s *smoke) run(bin, email, tokenItem, tokenPath, sshItem, sshPath string) error {
	if bin == "" || email == "" || tokenItem == "" {
		return errors.New("-agentcon, -bitwarden-email, and -token-item are required")
	}
	bin, err := filepath.Abs(bin)
	if err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	s.bin = bin
	s.dir, err = os.MkdirTemp("", "acsub")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(s.dir) }()
	s.state = filepath.Join(s.dir, "state")
	s.auditPath = filepath.Join(s.dir, "audit.log")
	s.repo = filepath.Join(s.dir, "repo")
	ctx := context.Background()

	fmt.Println("1. start the bouncer with the GitHub token sourced from Bitwarden")
	err = s.writePolicy(email, tokenItem, tokenPath, sshItem, sshPath)
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

	fmt.Println("3. create a session and fetch " + protected + " through the bouncer")
	sess, err := s.client.CreateSession(ctx, "", "", "subrequest-smoke", "")
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	err = s.agent(ctx, sess)
	if err != nil {
		return err
	}
	err = s.setupRepo()
	if err != nil {
		return err
	}

	fmt.Println("4. the token's owner can bypass the " + ruleset + " ruleset, so only the filter stops the push")
	err = s.checkBypass(ctx)
	if err != nil {
		return err
	}

	fmt.Println("5. push to " + protected + " over HTTPS; the filter denies it (expected failure)")
	err = s.wantFilterDenial("origin")
	if err != nil {
		return err
	}

	suffix, err := randomHex(4)
	if err != nil {
		return err
	}
	branch := "smoke/subrequest-" + suffix
	fmt.Println("6. create " + branch + " over HTTPS; the filter allows it")
	out, err := s.git("push", "origin", "FETCH_HEAD:refs/heads/"+branch)
	if err != nil {
		return fmt.Errorf("create %s: %w: %s", branch, err, strings.TrimSpace(out))
	}
	s.created = branch
	defer s.cleanup()
	fmt.Println("   " + firstLine(out, "[new branch]"))

	fmt.Println("7. delete " + branch + " over HTTPS; the filter allows it")
	out, err = s.git("push", "origin", ":refs/heads/"+branch)
	if err != nil {
		return fmt.Errorf("delete %s: %w: %s", branch, err, strings.TrimSpace(out))
	}
	s.created = ""
	fmt.Println("   " + firstLine(out, "[deleted]"))

	lookups := 3
	if sshItem == "" {
		fmt.Println("8. skipped: SSH push, since no -ssh-item was given")
	} else {
		fmt.Println("8. push to " + protected + " over SSH; the filter denies it (expected failure)")
		_, err = s.git("remote", "add", "ssh", "git@github.com:"+repoSlug+".git")
		if err != nil {
			return fmt.Errorf("remote add: %w", err)
		}
		err = s.wantFilterDenial("ssh")
		if err != nil {
			return fmt.Errorf("ssh: %w", err)
		}
		lookups++
	}

	fmt.Println("9. the audit log has a subrequest entry for each branch rules lookup")
	s.stop()
	return s.checkAudit(sess.ID, lookups)
}

// wantFilterDenial pushes an empty commit to the protected branch and wants
// the filter's denial, not GitHub's.
func (s *smoke) wantFilterDenial(remote string) error {
	out, err := s.git("push", remote, "HEAD:refs/heads/"+protected)
	if err == nil {
		return fmt.Errorf("push to %s succeeded, so the filter did not stop it; reset the branch with git push --force origin %s:refs/heads/%s: %s",
			protected, s.base, protected, strings.TrimSpace(out))
	}
	if strings.Contains(out, "GH013") || strings.Contains(out, "rule violations") {
		return fmt.Errorf("GitHub refused the push, so the bouncer let it through: %s", strings.TrimSpace(out))
	}
	if !strings.Contains(out, "denied by "+filter) || !strings.Contains(out, "GitHub rule 'update' protects branch '"+protected+"'") {
		return fmt.Errorf("push to %s failed without the filter's denial: %s", protected, strings.TrimSpace(out))
	}
	fmt.Println("   expected: " + firstLine(out, "denied by "+filter))
	return nil
}

// checkBypass reads the smoke ruleset through the bouncer, as the agent
// would, and wants it active with the token's owner able to bypass it.
func (s *smoke) checkBypass(ctx context.Context) error {
	client, err := s.httpClient()
	if err != nil {
		return err
	}
	var list []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	err = getJSON(ctx, client, "https://api.github.com/repos/"+repoSlug+"/rulesets?per_page=100", &list)
	if err != nil {
		return fmt.Errorf("list rulesets: %w", err)
	}
	id := 0
	for _, r := range list {
		if r.Name == ruleset {
			id = r.ID
		}
	}
	if id == 0 {
		return fmt.Errorf("no ruleset named %s on %s", ruleset, repoSlug)
	}
	var rs struct {
		Enforcement   string `json:"enforcement"`
		CurrentBypass string `json:"current_user_can_bypass"`
	}
	err = getJSON(ctx, client, fmt.Sprintf("https://api.github.com/repos/%s/rulesets/%d", repoSlug, id), &rs)
	if err != nil {
		return fmt.Errorf("read ruleset %s: %w", ruleset, err)
	}
	fmt.Printf("   bypass: enforcement=%s current_user_can_bypass=%s\n", rs.Enforcement, rs.CurrentBypass)
	if rs.Enforcement != "active" {
		return fmt.Errorf("ruleset %s is %q, want active", ruleset, rs.Enforcement)
	}
	if rs.CurrentBypass != "always" {
		return fmt.Errorf("the token's owner cannot always bypass %s (current_user_can_bypass=%q); add them to its bypass list", ruleset, rs.CurrentBypass)
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

func getJSON(ctx context.Context, client *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	err = json.Unmarshal(body, out)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
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

// copyFilter copies the reference github-branch-rules.ts filter next to
// the policy.
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

func (s *smoke) writePolicy(email, tokenItem, tokenPath, sshItem, sshPath string) error {
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
	var sshCred, sshSvc string
	if sshItem != "" {
		sshCred = fmt.Sprintf(`  github-ssh:
    private_key: {source: bitwarden, account: agent, item: %q, path: %q}
`, sshItem, sshPath)
		sshSvc = fmt.Sprintf(`    ssh:
      - name: github-ssh
        hosts: [github.com]
        user: git
        credential: github-ssh
        allow: [git]
        rules:
          - action: allow
            github_repo: [%s]
            filters: [ts/%s.ts]
`, repoSlug, filter)
	}
	policy := fmt.Sprintf(`
listen: %s
ssh_listen: %s
default_profile: agent
prompts: {notify: false, terminal: false, cli: true, timeout: 5m}
bitwarden:
  agent:
    email: %q
credentials:
  github:
    cache: 10m
    token: {source: bitwarden, account: agent, item: %q, path: %q}
%sprofiles:
  agent:
    unmatched: deny
    http:
      - name: github
        hosts: [github.com, api.github.com]
        credential: github
        inject:
          bearer: true
          git: {basic: {username: x-access-token}}
        default: deny
        rules:
          - action: allow
            git: {}
            github_repo: [%s]
            filters: [ts/%s.ts]
          # The filter's branch rules lookup.
          - action: allow
            methods: [GET]
            github_repo: [%s]
            github_subpaths: ["rules/branches/**"]
          # The smoke check's own ruleset lookup.
          - action: allow
            methods: [GET]
            github_repo: [%s]
            github_subpaths: [rulesets, "rulesets/*"]
%s`, s.proxyAddr, s.sshAddr, email, tokenItem, tokenPath, sshCred, repoSlug, filter, repoSlug, repoSlug, sshSvc)
	s.policy = filepath.Join(s.dir, "policy.yaml")
	err = os.WriteFile(s.policy, []byte(policy), 0o600)
	if err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	return nil
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

func (s *smoke) setupRepo() error {
	err := os.Mkdir(s.repo, 0o700)
	if err != nil {
		return fmt.Errorf("repo: %w", err)
	}
	steps := [][]string{
		{"init", "-q", "-b", "work"},
		{gitConfig, "user.name", "Subrequest Smoke"},
		{gitConfig, "user.email", "agent@example.com"},
		{gitConfig, "commit.gpgsign", "false"},
		{gitConfig, "credential.helper", ""},
		{"remote", "add", "origin", "https://github.com/" + repoSlug + ".git"},
		{"fetch", "-q", "--depth", "1", "origin", "refs/heads/" + protected},
		{"reset", "-q", "--hard", "FETCH_HEAD"},
		{"commit", "-q", "--allow-empty", "-m", "subrequest smoke: must never land"},
	}
	for _, args := range steps {
		out, err := s.git(args...)
		if err != nil {
			return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
		}
	}
	head, err := s.git("rev-parse", "FETCH_HEAD")
	if err != nil {
		return fmt.Errorf("rev-parse: %w", err)
	}
	s.base = strings.TrimSpace(head)
	fmt.Println("   " + protected + " is at " + s.base)
	return nil
}

func (s *smoke) git(args ...string) (string, error) {
	cmd := exec.Command("git", args...) //nolint:gosec // smoke runs git
	cmd.Dir, cmd.Env = s.repo, s.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// checkAudit wants one allowed subrequest entry from the filter per lookup,
// and the filter's denial of each protected push.
func (s *smoke) checkAudit(sessionID string, lookups int) error {
	data, err := os.ReadFile(s.auditPath)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	var subs, denials int
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m struct {
			Event      string `json:"event"`
			Session    string `json:"session"`
			Service    string `json:"service"`
			Request    string `json:"request"`
			Decision   string `json:"decision"`
			By         string `json:"by"`
			Subrequest *struct {
				Filter string `json:"filter"`
				Depth  int    `json:"depth"`
				Parent string `json:"parent"`
			} `json:"subrequest"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.Event != "decision" || m.Session != sessionID {
			continue
		}
		switch {
		case m.Subrequest != nil:
			fmt.Printf("   %s %s [subrequest from %s, depth %d, for %s]\n", m.Decision, m.Request, m.Subrequest.Filter, m.Subrequest.Depth, m.Subrequest.Parent)
			if m.Subrequest.Filter != filter || m.Subrequest.Depth != 1 || m.Decision != "allow" || m.Service != "github" ||
				!strings.Contains(m.Request, "/repos/"+repoSlug+"/rules/branches/") {
				return fmt.Errorf("unexpected subrequest entry: %s", sc.Text())
			}
			subs++
		case m.Decision == "deny":
			fmt.Printf("   deny by %s: %s\n", m.By, m.Request)
			if m.By != filter {
				return fmt.Errorf("unexpected denial: %s", sc.Text())
			}
			denials++
		}
	}
	wantDenials := lookups - 2
	if subs != lookups || denials != wantDenials {
		return fmt.Errorf("audit has %d subrequests and %d denials, want %d and %d", subs, denials, lookups, wantDenials)
	}
	return nil
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
