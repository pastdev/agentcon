//go:build issue38

// Smoke runs session claims end to end against a real `agentcon bouncer
// serve` process on loopback: seeded claims, the gitlab-issue-scope reference
// filter, claim prompts answered through the control API, a daemon restart,
// session end, and the audit log.
//
//	go build -o /tmp/agentcon ./cmd/agentcon
//	go run -tags issue38 ./ad_hoc/issue-38/smoke -agentcon /tmp/agentcon
//
// It ends with SMOKE PASSED or SMOKE FAILED: <reason>.
package main

import (
	"bufio"
	"bytes"
	"context"
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
	"sync"
	"time"

	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

const loopback = "127.0.0.1"

func main() {
	bin := flag.String("agentcon", "", "agentcon binary to run as the bouncer")
	flag.Parse()
	err := run(*bin)
	if err != nil {
		fmt.Printf("SMOKE FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("SMOKE PASSED")
}

// upstream counts the requests that got past the bouncer.
type upstream struct {
	mu   sync.Mutex
	hits []string
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.hits = append(u.hits, r.Method+" "+r.URL.EscapedPath())
	u.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"iid":1}`)
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.hits)
}

type smoke struct {
	bin, dir, policy, state, auditPath string
	proxyAddr                          string
	upAddr                             string
	up                                 *upstream
	cmd                                *exec.Cmd
	client                             *mgmt.Client
}

func run(bin string) error {
	if bin == "" {
		return errors.New("-agentcon is required")
	}
	dir, err := os.MkdirTemp("", "agentcon-claims-smoke-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	s := &smoke{bin: bin, dir: dir, state: filepath.Join(dir, "state"), auditPath: filepath.Join(dir, "audit.log"), up: &upstream{}}

	upL, err := net.Listen("tcp", net.JoinHostPort(loopback, "0"))
	if err != nil {
		return fmt.Errorf("upstream listen: %w", err)
	}
	s.upAddr = upL.Addr().String()
	go func() { _ = http.Serve(upL, s.up) }() //nolint:gosec // loopback test upstream
	defer func() { _ = upL.Close() }()

	err = s.writePolicy()
	if err != nil {
		return err
	}
	err = s.start()
	if err != nil {
		return err
	}
	defer s.stop()

	ctx := context.Background()
	repo := func(path string) string { return loopback + "/" + path }
	issues := func(project string) string {
		return "http://" + s.upAddr + "/api/v4/projects/" + url.PathEscape(project) + "/issues"
	}

	fmt.Println("1. create a session seeded with a repository claim")
	sess, err := s.client.CreateSession(ctx, "", "", "claims-smoke", "", mgmt.WithClaims(map[string][]string{"repository": {repo("group/project")}}))
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	err = want(sess.Claims, claims.Set{"repository": {repo("group/project")}}, "created claims")
	if err != nil {
		return err
	}

	fmt.Println("2. a seed with one bad value is rejected and creates nothing")
	_, err = s.client.CreateSession(ctx, "", "", "bad", "", mgmt.WithClaims(map[string][]string{"repository": {"ok", "bad\nvalue"}}))
	if err == nil {
		return errors.New("bad seed accepted")
	}
	list, err := s.client.Sessions(ctx)
	if err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	if len(list) != 1 {
		return fmt.Errorf("bad seed made a session: %d sessions", len(list))
	}

	fmt.Println("3. an issue in the seeded repository goes through without a prompt")
	err = s.expect(sess.Token, issues("group/project"), http.StatusCreated, "", nil)
	if err != nil {
		return err
	}

	fmt.Println("4. an issue elsewhere prompts with the claim and the session's claims; deny refuses it")
	var seen prompt.Pending
	err = s.expect(sess.Token, issues("group/other"), http.StatusForbidden, "not one of this session's repositories", func(p prompt.Pending) prompt.Answer {
		seen = p
		return prompt.Answer{}
	})
	if err != nil {
		return err
	}
	if seen.Kind != prompt.KindClaim || seen.Claim == nil || *seen.Claim != (claims.Claim{Type: "repository", Value: repo("group/other")}) {
		return fmt.Errorf("unexpected prompt: %+v", seen)
	}
	err = want(seen.SessionClaims, claims.Set{"repository": {repo("group/project")}}, "prompt session_claims")
	if err != nil {
		return err
	}

	fmt.Println("5. deny for session is refused for a claim prompt; the denial was not remembered")
	err = s.expect(sess.Token, issues("group/other"), http.StatusCreated, "", func(p prompt.Pending) prompt.Answer {
		bad := s.client.AnswerPrompt(ctx, p.ID, prompt.Answer{Remember: true})
		if bad == nil {
			fmt.Println("   deny for session was accepted")
			os.Exit(1)
		}
		return prompt.Answer{Allow: true, Remember: true}
	})
	if err != nil {
		return err
	}

	fmt.Println("6. the added claim lets the next issue through without a prompt")
	err = s.expect(sess.Token, issues("group/other"), http.StatusCreated, "", nil)
	if err != nil {
		return err
	}

	fmt.Println("7. a numeric project id is denied without a prompt")
	err = s.expect(sess.Token, issues("1234"), http.StatusForbidden, "numeric ID", nil)
	if err != nil {
		return err
	}

	fmt.Println("8. claims survive a daemon restart")
	s.stop()
	err = s.start()
	if err != nil {
		return err
	}
	list, err = s.client.Sessions(ctx)
	if err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	if len(list) != 1 {
		return fmt.Errorf("sessions after restart: %d", len(list))
	}
	err = want(list[0].Claims, claims.Set{"repository": {repo("group/other"), repo("group/project")}}, "claims after restart")
	if err != nil {
		return err
	}
	err = s.expect(sess.Token, issues("group/other"), http.StatusCreated, "", nil)
	if err != nil {
		return err
	}

	fmt.Println("9. ending the session discards it and its claims")
	err = s.client.EndSession(ctx, sess.ID)
	if err != nil {
		return fmt.Errorf("end session: %w", err)
	}
	before := s.up.count()
	status, _, err := s.send(sess.Token, issues("group/other"))
	if err != nil {
		return err
	}
	if status < 400 || s.up.count() != before {
		return fmt.Errorf("ended session still reached upstream: %d", status)
	}

	fmt.Println("10. the audit log records creation and each claim addition")
	s.stop()
	return s.checkAudit(sess.ID, repo)
}

func (s *smoke) writePolicy() error {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("no caller")
	}
	src := filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "bouncer", "reference", "ts", "filters", "gitlab-issue-scope.ts")
	filter, err := os.ReadFile(src) //nolint:gosec // repo file
	if err != nil {
		return fmt.Errorf("read filter: %w", err)
	}
	err = os.MkdirAll(filepath.Join(s.dir, "ts"), 0o700)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	err = os.WriteFile(filepath.Join(s.dir, "ts", "gitlab-issue-scope.ts"), filter, 0o600)
	if err != nil {
		return fmt.Errorf("write filter: %w", err)
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
	policy := fmt.Sprintf(`
listen: %s
ssh_listen: %s
default_profile: agent
prompts: {notify: false, terminal: false, cli: true, timeout: 30s}
profiles:
  agent:
    unmatched: deny
    http:
      - name: gitlab
        hosts: [%q]
        filters: [ts/gitlab-issue-scope.ts]
        rules:
          - action: allow
            path: /**
`, s.proxyAddr, net.JoinHostPort(loopback, strconv.Itoa(sshPort)), s.upAddr)
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
	s.cmd.Stdin = nil
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

// send makes one agent request through the bouncer with the session token.
func (s *smoke) send(token, target string) (int, string, error) {
	proxy := &url.URL{Scheme: "http", User: url.UserPassword("bouncer", token), Host: s.proxyAddr}
	c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	resp, err := c.Post(target, "application/json", strings.NewReader(`{"title":"smoke"}`)) //nolint:noctx // smoke
	if err != nil {
		return 0, "", fmt.Errorf("agent request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

// expect sends a request. answer, when set, answers the one claim prompt
// the request must raise. When nil, the request must raise no prompt.
func (s *smoke) expect(token, target string, status int, bodyHas string, answer func(prompt.Pending) prompt.Answer) error {
	type result struct {
		status int
		body   string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		st, body, err := s.send(token, target)
		done <- result{st, body, err}
	}()
	ctx := context.Background()
	prompted := false
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case r := <-done:
			switch {
			case r.err != nil:
				return r.err
			case answer != nil && !prompted:
				return errors.New("expected a claim prompt, none was raised")
			case r.status != status:
				return fmt.Errorf("status %d, want %d: %s", r.status, status, strings.TrimSpace(r.body))
			case !strings.Contains(r.body, bodyHas):
				return fmt.Errorf("body %q lacks %q", r.body, bodyHas)
			}
			fmt.Printf("   %d %s\n", r.status, strings.TrimSpace(r.body))
			return nil
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("request did not finish")
		}
		list, err := s.client.Prompts(ctx)
		if err != nil {
			return fmt.Errorf("prompts: %w", err)
		}
		if len(list) == 0 {
			continue
		}
		if answer == nil || prompted {
			return fmt.Errorf("unexpected prompt: %s %s", list[0].Kind, list[0].Message)
		}
		prompted = true
		p := list[0]
		fmt.Printf("   prompt %s kind=%s claim=%s=%s session_claims=%v\n", p.ID, p.Kind, p.Claim.Type, p.Claim.Value, p.SessionClaims)
		err = s.client.AnswerPrompt(ctx, p.ID, answer(p))
		if err != nil {
			return fmt.Errorf("answer prompt: %w", err)
		}
	}
}

func (s *smoke) checkAudit(sessionID string, repo func(string) string) error {
	f, err := os.Open(s.auditPath)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	defer func() { _ = f.Close() }()
	var created, added []map[string]any
	decisions := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.HasPrefix(line, []byte("{")) {
			continue
		}
		var m map[string]any
		if json.Unmarshal(line, &m) != nil || m["session"] != sessionID {
			continue
		}
		switch m["event"] {
		case "session_created":
			created = append(created, m)
		case "claim_added":
			added = append(added, m)
		case "decision":
			decisions++
		}
	}
	if len(created) != 1 {
		return fmt.Errorf("session_created events: %d", len(created))
	}
	fmt.Printf("   session_created claims=%v\n", created[0]["claims"])
	var got []string
	for _, m := range added {
		got = append(got, fmt.Sprintf("%s=%s %s %v %v", m["claim_type"], m["claim_value"], m["added_by"], m["filter"], m["prompt"] != nil))
	}
	wantAdded := []string{
		"repository=" + repo("group/project") + " seeded <nil> false",
		"repository=" + repo("group/other") + " operator gitlab-issue-scope true",
	}
	if !slices.Equal(got, wantAdded) {
		return fmt.Errorf("claim_added events %q, want %q", got, wantAdded)
	}
	for _, g := range got {
		fmt.Printf("   claim_added %s\n", g)
	}
	if decisions == 0 {
		return errors.New("no decision events carry event=decision")
	}
	fmt.Printf("   %d decision events with event=decision\n", decisions)
	return nil
}

func want(got, want claims.Set, what string) error {
	b1, _ := json.Marshal(got)
	b2, _ := json.Marshal(want)
	if !bytes.Equal(b1, b2) {
		return fmt.Errorf("%s: got %s, want %s", what, b1, b2)
	}
	return nil
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
