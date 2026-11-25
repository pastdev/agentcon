//go:build issue40

// Smoke runs OpenPGP commit signing end to end against a real `agentcon
// bouncer serve` process on loopback: a passphrase-protected key PUT as a
// provided internal credential, the signing-repository-scope reference
// filter, the agent payload's git-sign wrapper and environment, real git
// commit -S, git tag -s, git verify-commit, claim prompts answered through
// the control API, and the audit log.
//
//	go build -o /tmp/agentcon ./cmd/agentcon
//	go run -tags issue40 ./ad_hoc/issue-40/smoke -agentcon /tmp/agentcon
//
// With -bitwarden-email it instead signs with real keys held in Bitwarden
// items. See bitwarden.go.
//
// It ends with SMOKE PASSED or SMOKE FAILED: <reason>.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/pastdev/agentcon/pkg/bouncer/host"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

const (
	loopback = "127.0.0.1"
	claimed  = "github.com/pastdev/agentcon"
	other    = "github.com/pastdev/other"
)

func main() {
	bin := flag.String("agentcon", "", "agentcon binary to run as the bouncer and git-sign")
	bw := flag.String("bitwarden-email", "", "sign with real keys from this Bitwarden account instead of a generated key")
	pubs := flag.String("public-keys", "", "with -bitwarden-email: armored public keys of every -key")
	var keys keyFlags
	flag.Var(&keys, "key", "with -bitwarden-email: <item>=<fingerprint>, repeatable")
	flag.Parse()
	var err error
	if *bw != "" {
		err = runBitwarden(*bin, *bw, *pubs, keys)
	} else {
		err = run(*bin)
	}
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
	repo, gnupg                        string
	env                                []string
}

func run(bin string) error {
	if bin == "" {
		return errors.New("-agentcon is required")
	}
	bin, err := filepath.Abs(bin)
	if err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	dir, err := os.MkdirTemp("", "acsign")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	s := &smoke{bin: bin, dir: dir, state: filepath.Join(dir, "state"), auditPath: filepath.Join(dir, "audit.log"),
		repo: filepath.Join(dir, "repo"), gnupg: filepath.Join(dir, "g")}
	defer func() {
		_ = exec.Command("gpgconf", "--homedir", s.gnupg, "--kill", "all").Run() //nolint:gosec // smoke temp dir
		_ = os.RemoveAll(dir)
	}()
	ctx := context.Background()

	fmt.Println("1. generate a passphrase-protected OpenPGP key")
	key, err := pgp.PGP().KeyGeneration().AddUserId("Smoke Agent", "agent@example.com").New().GenerateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	locked, err := pgp.PGP().LockKey(key, []byte("smoke-passphrase"))
	if err != nil {
		return fmt.Errorf("lock key: %w", err)
	}
	armoredPriv, err := locked.Armor()
	if err != nil {
		return fmt.Errorf("armor key: %w", err)
	}
	armoredPub, err := key.GetArmoredPublicKey()
	if err != nil {
		return fmt.Errorf("armor public key: %w", err)
	}
	fpr := strings.ToUpper(key.GetFingerprint())
	longID := fpr[len(fpr)-16:]
	fmt.Printf("   key %s (configured by long id %s)\n", fpr, longID)

	err = s.writePolicy(longID)
	if err != nil {
		return err
	}
	err = s.start()
	if err != nil {
		return err
	}
	defer s.stop()

	fmt.Println("2. PUT the key and passphrase as provided values, then wait for ready")
	err = s.client.PutProvided(ctx, map[string]string{"signing.private_key": armoredPriv, "signing.password": "smoke-passphrase"})
	if err != nil {
		return fmt.Errorf("put provided: %w", err)
	}
	err = s.waitReady(ctx)
	if err != nil {
		return err
	}

	fmt.Println("3. create a session with a repository claim; it reports the signer url")
	sess, err := s.client.CreateSession(ctx, "", "", "sign-smoke", "", mgmt.WithClaims(map[string][]string{"repository": {claimed}}))
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	if sess.SignerURL != "https://signer.bouncer.internal/openpgp/sign" {
		return fmt.Errorf("signer url %q", sess.SignerURL)
	}
	fmt.Printf("   signer_url=%s\n", sess.SignerURL)

	fmt.Println("4. unpack the agent payload and build the agent environment")
	layout, err := s.agent(ctx, sess)
	if err != nil {
		return err
	}
	wrapper, err := os.ReadFile(layout.GitSign)
	if err != nil {
		return fmt.Errorf("read wrapper: %w", err)
	}
	fmt.Printf("   %s: %s", layout.GitSign, strings.SplitN(string(wrapper), "\n", 2)[1])

	fmt.Println("5. set up gpg (public key only) and a repository")
	err = s.setupRepo(armoredPub, fpr, layout.GitSign)
	if err != nil {
		return err
	}

	fmt.Println("6. git commit -S signs without a prompt and git verify-commit accepts it")
	err = s.stage("a.txt")
	if err != nil {
		return err
	}
	_, err = s.gitWithPrompts(ctx, nil, "commit", "-q", "-S", "-m", "smoke: signed commit")
	if err != nil {
		return err
	}
	out, err := s.git("verify-commit", "HEAD")
	if err != nil {
		return fmt.Errorf("verify-commit: %w: %s", err, out)
	}
	if !strings.Contains(out, "Good signature") {
		return fmt.Errorf("verify-commit: %s", out)
	}
	fmt.Println("   " + firstLine(out, "Good signature"))

	fmt.Println("7. git tag -s signs and git verify-tag accepts it")
	_, err = s.gitWithPrompts(ctx, nil, "tag", "-s", "v0.0.1", "-m", "smoke release")
	if err != nil {
		return err
	}
	out, err = s.git("verify-tag", "v0.0.1")
	if err != nil || !strings.Contains(out, "Good signature") {
		return fmt.Errorf("verify-tag: %v: %s", err, out)
	}
	fmt.Println("   " + firstLine(out, "Good signature"))

	fmt.Println("8. an unclaimed repository prompts; deny fails the commit and keeps the index (expected failure)")
	_, err = s.git("remote", "set-url", "origin", "git@github.com:pastdev/other.git")
	if err != nil {
		return fmt.Errorf("set-url: %w", err)
	}
	err = s.stage("b.txt")
	if err != nil {
		return err
	}
	out, err = s.gitWithPrompts(ctx, func(p prompt.Pending) prompt.Answer {
		fmt.Printf("   prompt kind=%s claim=%s=%s\n", p.Kind, p.Claim.Type, p.Claim.Value)
		return prompt.Answer{}
	}, "commit", "-q", "-S", "-m", "smoke: denied")
	if err == nil {
		return errors.New("denied commit succeeded")
	}
	if !strings.Contains(out, "not one of this session's repositories") {
		return fmt.Errorf("denied commit output: %s", out)
	}
	fmt.Println("   expected: " + firstLine(out, "bouncer:"))
	err = s.wantStaged("b.txt")
	if err != nil {
		return err
	}

	fmt.Println("9. adding the claim for the session signs, and the next commit does not prompt")
	_, err = s.gitWithPrompts(ctx, func(prompt.Pending) prompt.Answer {
		return prompt.Answer{Allow: true, Remember: true}
	}, "commit", "-q", "-S", "-m", "smoke: claim added")
	if err != nil {
		return err
	}
	err = s.stage("c.txt")
	if err != nil {
		return err
	}
	_, err = s.gitWithPrompts(ctx, nil, "commit", "-q", "-S", "-m", "smoke: no prompt")
	if err != nil {
		return err
	}
	list, err := s.client.Sessions(ctx)
	if err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	fmt.Printf("   session claims %v\n", list[0].Claims)

	fmt.Println("10. a key the signer does not hold fails the commit and keeps the index (expected failure)")
	_, err = s.git("config", "user.signingkey", "1111111111111111")
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	err = s.stage("d.txt")
	if err != nil {
		return err
	}
	out, err = s.gitWithPrompts(ctx, nil, "commit", "-q", "-S", "-m", "smoke: unknown key")
	if err == nil || !strings.Contains(out, "unknown signing key") {
		return fmt.Errorf("unknown key commit: %v: %s", err, out)
	}
	fmt.Println("   expected: " + firstLine(out, "bouncer:"))
	err = s.wantStaged("d.txt")
	if err != nil {
		return err
	}

	fmt.Println("11. git-sign --dry-run prints the request and sends nothing")
	cmd := exec.Command(layout.GitSign, "--dry-run", "--status-fd=2", "-bsau", longID) //nolint:gosec // smoke wrapper
	cmd.Dir, cmd.Env, cmd.Stdin = s.repo, s.env, strings.NewReader("tree x\n\nmsg\n")
	dry, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(dry), "repository: "+other) {
		return fmt.Errorf("dry run: %v: %s", err, dry)
	}

	fmt.Println("12. the audit log names key, digest, and type, never the message")
	s.stop()
	return s.checkAudit(sess.ID, fpr)
}

// copyFilter copies the reference signing-repository-scope.ts filter next
// to the policy.
func (s *smoke) copyFilter() error {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("no caller")
	}
	src := filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "bouncer", "reference", "ts", "filters", "signing-repository-scope.ts")
	filter, err := os.ReadFile(src) //nolint:gosec // repo file
	if err != nil {
		return fmt.Errorf("read filter: %w", err)
	}
	err = os.MkdirAll(filepath.Join(s.dir, "ts"), 0o700)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	err = os.WriteFile(filepath.Join(s.dir, "ts", "signing-repository-scope.ts"), filter, 0o600)
	if err != nil {
		return fmt.Errorf("write filter: %w", err)
	}
	return nil
}

func (s *smoke) writePolicy(keyID string) error {
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
prompts: {notify: false, terminal: false, cli: true, timeout: 30s}
credentials:
  signing:
    internal: true
    private_key: {source: provided}
    password: {source: provided}
profiles:
  agent:
    unmatched: deny
    http:
      - name: commit-signing
        hosts: [signer.bouncer.internal]
        signer:
          openpgp:
            keys: [{id: %s, credential: signing}]
        filters: [ts/signing-repository-scope.ts]
`, s.proxyAddr, s.sshAddr, keyID)
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

func (s *smoke) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.client.Status(ctx)
		if err == nil && st.Ready {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("bouncer not ready")
}

// agent unpacks the real agent payload under the temp dir and builds the
// real agent environment, as agentcon run does for a container.
func (s *smoke) agent(ctx context.Context, sess mgmt.NewSession) (host.AgentLayout, error) {
	trust, err := s.client.Trust(ctx)
	if err != nil {
		return host.AgentLayout{}, fmt.Errorf("trust: %w", err)
	}
	root := filepath.Join(s.dir, "agent")
	layout := host.AgentLayout{
		Binary:     root + "/bin/agentcon",
		CACert:     root + "/ca.pem",
		CABundle:   root + "/ca-bundle.pem",
		SSHConfig:  root + "/ssh/config",
		KnownHosts: root + "/ssh/known_hosts",
		GitSign:    root + "/bin/git-sign",
	}
	var buf bytes.Buffer
	err = host.WriteAgentPayload(&buf, host.AgentPayload{Layout: layout, Binary: s.bin, Trust: trust, UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		return host.AgentLayout{}, fmt.Errorf("agent payload: %w", err)
	}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return host.AgentLayout{}, fmt.Errorf("agent payload: %w", err)
		}
		dst := "/" + hdr.Name
		if !strings.HasPrefix(dst, root+"/") {
			continue
		}
		if hdr.Typeflag == tar.TypeDir {
			err = os.MkdirAll(dst, 0o700)
			if err != nil {
				return host.AgentLayout{}, fmt.Errorf("mkdir: %w", err)
			}
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return host.AgentLayout{}, fmt.Errorf("agent payload: %w", err)
		}
		err = os.MkdirAll(filepath.Dir(dst), 0o700)
		if err != nil {
			return host.AgentLayout{}, fmt.Errorf("mkdir: %w", err)
		}
		err = os.WriteFile(dst, data, os.FileMode(hdr.Mode)) //nolint:gosec // payload modes from our own tar
		if err != nil {
			return host.AgentLayout{}, fmt.Errorf("write %s: %w", dst, err)
		}
	}
	agentEnv, err := host.AgentEnv(layout, sess, s.proxyAddr, s.sshAddr)
	if err != nil {
		return host.AgentLayout{}, fmt.Errorf("agent env: %w", err)
	}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasSuffix(strings.ToLower(k), "_proxy") || k == "SSL_CERT_FILE" {
			continue
		}
		s.env = append(s.env, kv)
	}
	s.env = append(s.env, agentEnv...)
	s.env = append(s.env, "HOME="+s.dir, "GNUPGHOME="+s.gnupg, "GIT_CONFIG_NOSYSTEM=1")
	for _, kv := range agentEnv {
		if strings.HasPrefix(kv, "BOUNCER_SIGNER_URL=") || strings.HasPrefix(kv, "SSL_CERT_FILE=") {
			fmt.Println("   " + kv)
		}
	}
	return layout, nil
}

func (s *smoke) setupRepo(armoredPub, fpr, wrapper string) error {
	err := os.Mkdir(s.gnupg, 0o700)
	if err != nil {
		return fmt.Errorf("gnupg: %w", err)
	}
	err = os.Mkdir(s.repo, 0o700)
	if err != nil {
		return fmt.Errorf("repo: %w", err)
	}
	steps := []struct {
		stdin string
		args  []string
	}{
		{armoredPub, []string{"gpg", "--batch", "--import"}},
		{fpr + ":6:\n", []string{"gpg", "--batch", "--import-ownertrust"}},
		{"", []string{"git", "init", "-q", "-b", "main"}},
		{"", []string{"git", "config", "user.name", "Smoke Agent"}},
		{"", []string{"git", "config", "user.email", "agent@example.com"}},
		{"", []string{"git", "config", "user.signingkey", fpr}},
		{"", []string{"git", "config", "gpg.format", "openpgp"}},
		{"", []string{"git", "config", "gpg.openpgp.program", wrapper}},
		{"", []string{"git", "remote", "add", "origin", "git@github.com:pastdev/agentcon.git"}},
	}
	for _, st := range steps {
		out, err := s.exec(st.stdin, st.args...)
		if err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(st.args, " "), err, out)
		}
	}
	return nil
}

func (s *smoke) exec(stdin string, args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...) //nolint:gosec // smoke runs git and gpg
	cmd.Dir, cmd.Env, cmd.Stdin = s.repo, s.env, strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err //nolint:wrapcheck // callers add context
}

func (s *smoke) git(args ...string) (string, error) {
	return s.exec("", append([]string{"git"}, args...)...)
}

func (s *smoke) stage(name string) error {
	err := os.WriteFile(filepath.Join(s.repo, name), []byte(name+"\n"), 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	out, err := s.git("add", name)
	if err != nil {
		return fmt.Errorf("git add: %w: %s", err, out)
	}
	return nil
}

func (s *smoke) wantStaged(name string) error {
	out, err := s.git("diff", "--cached", "--name-only")
	if err != nil {
		return fmt.Errorf("diff --cached: %w", err)
	}
	if strings.TrimSpace(out) != name {
		return fmt.Errorf("staged %q, want %q", strings.TrimSpace(out), name)
	}
	fmt.Printf("   %s is still staged\n", name)
	return nil
}

// gitWithPrompts runs git. answer, when set, answers the one claim prompt
// the command must raise. When nil, it must raise none. A git failure is
// returned with its output.
func (s *smoke) gitWithPrompts(ctx context.Context, answer func(prompt.Pending) prompt.Answer, args ...string) (string, error) {
	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := s.git(args...)
		done <- result{out, err}
	}()
	prompted := false
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case r := <-done:
			if answer != nil && !prompted {
				return r.out, errors.New("expected a claim prompt, none was raised")
			}
			if r.err != nil {
				return r.out, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), r.err, strings.TrimSpace(r.out))
			}
			return r.out, nil
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return "", errors.New("git did not finish")
		}
		list, err := s.client.Prompts(ctx)
		if err != nil {
			return "", fmt.Errorf("prompts: %w", err)
		}
		if len(list) == 0 {
			continue
		}
		if answer == nil || prompted {
			return "", fmt.Errorf("unexpected prompt: %s %s", list[0].Kind, list[0].Message)
		}
		prompted = true
		err = s.client.AnswerPrompt(ctx, list[0].ID, answer(list[0]))
		if err != nil {
			return "", fmt.Errorf("answer prompt: %w", err)
		}
	}
}

// checkAudit wants keyID, the fingerprint git sends from user.signingkey.
func (s *smoke) checkAudit(sessionID, keyID string) error {
	data, err := os.ReadFile(s.auditPath)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	if bytes.Contains(data, []byte("smoke: signed commit")) || bytes.Contains(data, []byte("BEGIN PGP")) {
		return errors.New("audit log holds object or key contents")
	}
	var signs []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil || m["session"] != sessionID || m["event"] != "decision" {
			continue
		}
		req, _ := m["request"].(string)
		if !strings.Contains(req, "/openpgp/sign") {
			continue
		}
		_, detail, _ := strings.Cut(req, " key=")
		signs = append(signs, fmt.Sprintf("%v by=%v: key=%s", m["decision"], m["by"], detail))
	}
	for _, l := range signs {
		fmt.Println("   " + l)
	}
	want := map[string]int{"allow": 0, "deny": 0}
	for _, l := range signs {
		if !strings.Contains(l, "key="+keyID+" sha256=") && !strings.Contains(l, "key=1111111111111111 sha256=") {
			return fmt.Errorf("audit line lacks key and digest: %s", l)
		}
		want[strings.Fields(l)[0]]++
	}
	if want["allow"] != 4 || want["deny"] != 2 {
		return fmt.Errorf("sign decisions allow=%d deny=%d, want 4 and 2", want["allow"], want["deny"])
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
