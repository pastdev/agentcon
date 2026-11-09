package sshproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/pastdev/agentcon/internal/bouncer/audit"
	"github.com/pastdev/agentcon/internal/bouncer/ca"
	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/internal/bouncer/gitproto"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

type backend struct {
	set     *policy.Set
	revoked *bool
}

func (b backend) Session(tok string) (*chain.Session, bool) {
	if tok == "tok" && !(b.revoked != nil && *b.revoked) {
		return &chain.Session{ID: "s1", Profile: "p"}, true
	}
	return nil, false
}
func (b backend) Profile(n string) (*policy.Profile, bool) { p, ok := b.set.Profiles[n]; return p, ok }

// upstream is a fake SSH server standing in for gitlab.com.
type upstream struct {
	addr     string
	hostKey  ssh.PublicKey
	mu       sync.Mutex
	received map[string][]byte
}

func startUpstream(t *testing.T, clientKey ssh.PublicKey) *upstream {
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hk)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), clientKey.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("unauthorized")
	}}
	cfg.AddHostKey(hs)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	u := &upstream{addr: l.Addr().String(), hostKey: hs.PublicKey(), received: map[string][]byte{}}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go u.serve(ch, creqs)
				}
			}()
		}
	}()
	return u
}

func (u *upstream) serve(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	var env []string
	for r := range reqs {
		if r.Type == "env" {
			var e struct{ Name, Value string }
			_ = ssh.Unmarshal(r.Payload, &e)
			env = append(env, e.Name+"="+e.Value)
			_ = r.Reply(true, nil)
			continue
		}
		if r.Type != "exec" {
			_ = r.Reply(false, nil)
			continue
		}
		var p struct{ Command string }
		_ = ssh.Unmarshal(r.Payload, &p)
		_ = r.Reply(true, nil)
		switch {
		case p.Command == "echo hi":
			_, _ = io.WriteString(ch, "hi\n")
		case p.Command == "env":
			_, _ = io.WriteString(ch, strings.Join(env, ","))
		case strings.HasPrefix(p.Command, "git-receive-pack"):
			_, _ = ch.Write(gitproto.EncodePkt(strings.Repeat("a", 40) + " refs/heads/main\x00report-status\n"))
			_, _ = ch.Write(gitproto.Flush)
			data, _ := io.ReadAll(ch)
			u.mu.Lock()
			u.received[p.Command] = data
			u.mu.Unlock()
			_, _ = io.WriteString(ch, "pushed\n")
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

func setup(t *testing.T) (*upstream, string, *ca.Authority) { u, a, c, _ := setupR(t); return u, a, c }

func setupR(t *testing.T) (*upstream, string, *ca.Authority, *bool) {
	dir := t.TempDir()
	_, ck, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(ck, "")
	keyPath := filepath.Join(dir, "id")
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600)
	cs, _ := ssh.NewSignerFromKey(ck)
	up := startUpstream(t, cs.PublicKey())
	_, port, _ := net.SplitHostPort(up.addr)

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
credentials:
  key: {private_key: {source: file, file: %s}}
profiles:
  p:
    ssh:
      - name: up
        hosts: [127.0.0.1]
        port: %s
        user: git
        credential: key
        host_key: %q
        allow: [git, exec]
        default: allow
        rules:
          - action: deny
            reason: main is protected
            git: {service: receive-pack, refs: [refs/heads/main]}
`, keyPath, port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(up.hostKey))))), filepath.Join(dir, "c.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.Compile(cfg, &chain.Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := ca.LoadOrCreate(filepath.Join(dir, "state"))
	log, _ := audit.Open("", nil)
	revoked := new(bool)
	srv := &Server{Backend: backend{set: set, revoked: revoked}, CA: authority, Creds: creds.NewStore(cfg.Credentials), Audit: log}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = srv.Serve(l) }()
	return up, l.Addr().String(), authority, revoked
}

func client(t *testing.T, bouncer string, authority *ca.Authority, token string) (*ssh.Client, error) {
	c, err := Dial(bouncer, Preamble{Token: token, Host: "127.0.0.1", Port: 22, User: "git"})
	if err != nil {
		return nil, err
	}
	checker := &ssh.CertChecker{IsHostAuthority: func(k ssh.PublicKey, _ string) bool {
		return bytes.Equal(k.Marshal(), authority.SSHCAPublicKey().Marshal())
	}}
	cc, chans, reqs, err := ssh.NewClientConn(c, "127.0.0.1:22", &ssh.ClientConfig{User: "git", HostKeyCallback: checker.CheckHostKey})
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(cc, chans, reqs), nil
}

func run(t *testing.T, cl *ssh.Client, cmd string, stdin []byte) (string, string, error) {
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	if stdin != nil {
		s.Stdin = bytes.NewReader(stdin)
	}
	if cmd == "" {
		err = s.Shell()
		if err == nil {
			err = s.Wait()
		}
	} else {
		err = s.Run(cmd)
	}
	return out.String(), errb.String(), err
}

func TestServe(t *testing.T) {
	type testCase struct {
		token   string
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		_, addr, authority := setup(t)
		_, err := client(t, addr, authority, tc.token)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Run("applies exec git and forwarding policy", func(t *testing.T) {
		up, addr, authority := setup(t)
		cl, err := client(t, addr, authority, "tok")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cl.Close() }()

		if out, _, err := run(t, cl, "echo hi", nil); err != nil || out != "hi\n" {
			t.Fatalf("exec: %q %v", out, err)
		}
		if _, stderr, err := run(t, cl, "", nil); err == nil || !strings.Contains(stderr, "ssh shell is not in the allow list") {
			t.Fatalf("shell should be denied: %q %v", stderr, err)
		}

		a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
		ok := gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/feature"}}, []string{"report-status"}, nil)
		out, _, err := run(t, cl, "git-receive-pack 'g/feature.git'", ok)
		if err != nil || out == "" || !strings.HasSuffix(out, "pushed\n") {
			t.Fatalf("allowed push: %q %v", out, err)
		}
		up.mu.Lock()
		got := up.received["git-receive-pack 'g/feature.git'"]
		up.mu.Unlock()
		if !bytes.Equal(got, ok) {
			t.Fatalf("upstream received %q, want %q", got, ok)
		}

		bad := gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/main"}}, []string{"report-status"}, nil)
		out, _, _ = run(t, cl, "git-receive-pack 'g/main.git'", bad)
		if !strings.Contains(out, "ng refs/heads/main denied by rules:up rules[0]: main is protected") {
			t.Fatalf("push to main should be rejected with a status report: %q", out)
		}
		bare := gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/main"}}, nil, nil)
		_, stderr, err := run(t, cl, "git-receive-pack 'g/main.git'", bare)
		if err == nil || !strings.Contains(stderr, "main is protected") {
			t.Fatalf("push to main should be denied: %q %v", stderr, err)
		}
		up.mu.Lock()
		leaked := up.received["git-receive-pack 'g/main.git'"]
		up.mu.Unlock()
		if len(leaked) != 0 {
			t.Fatalf("upstream saw commands for a denied push: %q", leaked)
		}

		if _, err := cl.Dial("tcp", "10.0.0.1:80"); err == nil {
			t.Fatal("port forward should be denied")
		}
	})
	t.Run("forwards allowlisted env and rejects the rest", func(t *testing.T) {
		_, addr, authority := setup(t)
		cl, err := client(t, addr, authority, "tok")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cl.Close() }()
		s, err := cl.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		err = s.Setenv("GIT_PROTOCOL", "version=2")
		if err != nil {
			t.Fatalf("allowlisted env refused: %v", err)
		}
		err = s.Setenv("LD_PRELOAD", "/tmp/x.so")
		if err == nil {
			t.Fatal("non-allowlisted env accepted")
		}
		out, err := s.Output("env")
		if err != nil || string(out) != "GIT_PROTOCOL=version=2" {
			t.Fatalf("upstream saw env %q (%v)", out, err)
		}
	})
	t.Run("closes an oversized preamble", func(t *testing.T) {
		_, addr, _ := setup(t)
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		_, err = c.Write([]byte(preamblePrefix + strings.Repeat("x", maxPreamble+10)))
		if err != nil {
			t.Fatal(err)
		}
		err = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("oversized preamble should close the connection")
		}
	})
	t.Run("rejects an unknown session token", func(t *testing.T) {
		tester(t, testCase{token: "nope", wantErr: "unknown session token"})
	})
	t.Run("refuses new channels after revocation", func(t *testing.T) {
		_, addr, authority, revoked := setupR(t)
		cl, err := client(t, addr, authority, "tok")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cl.Close() }()
		if out, _, err := run(t, cl, "echo hi", nil); err != nil || out != "hi\n" {
			t.Fatalf("first exec: %q %v", out, err)
		}
		*revoked = true
		if _, err := cl.NewSession(); err == nil {
			t.Fatal("opened a new channel after the session was revoked")
		}
	})
}

func TestMalformedRequest(t *testing.T) {
	type testCase struct {
		kind    string
		payload []byte
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		_, addr, authority := setup(t)
		cl, err := client(t, addr, authority, "tok")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cl.Close() }()
		ch, reqs, err := cl.OpenChannel("session", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ch.Close() }()
		go ssh.DiscardRequests(reqs)
		ok, err := ch.SendRequest(tc.kind, true, tc.payload)
		if err == nil && ok {
			t.Fatalf("%s with payload %q was not refused as malformed", tc.kind, tc.payload)
		}
	}

	valid := ssh.Marshal(struct{ Command string }{"echo hi"})
	t.Run("exec with trailing data", func(t *testing.T) {
		tester(t, testCase{kind: "exec", payload: append(append([]byte{}, valid...), 'x')})
	})
	t.Run("exec with truncated command", func(t *testing.T) {
		tester(t, testCase{kind: "exec", payload: valid[:6]})
	})
	t.Run("subsystem with truncated name", func(t *testing.T) {
		tester(t, testCase{kind: "subsystem", payload: []byte{0, 0, 0, 9, 's'}})
	})
}

func TestPrepare(t *testing.T) {
	type testCase struct {
		port    int
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		cfg, err := config.Parse([]byte(`
credentials:
  key: {private_key: {source: env, env: UNUSED}}
profiles:
  p:
    ssh:
      - name: s
        hosts: [example.com]
        credential: key
`), filepath.Join(t.TempDir(), "c.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		set, err := policy.Compile(cfg, &chain.Env{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		srv := &Server{Backend: backend{set: set}, Creds: creds.NewStore(cfg.Credentials)}
		_, err = srv.prepare(context.Background(), &Preamble{Token: "tok", Host: "example.com", Port: tc.port, User: "git"})
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("err = %v", err)
		}
	}

	t.Run("rejects a port the agent chose unless pinned", func(t *testing.T) {
		tester(t, testCase{port: 2222, wantErr: "port 2222 is not allowed"})
	})
}
