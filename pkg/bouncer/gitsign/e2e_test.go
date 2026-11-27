package gitsign

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/signer"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

const helperEnv = "AGENTCON_GITSIGN_TEST_HELPER"

// TestMain lets the test binary stand in for agentcon bouncer git-sign when
// git runs it as gpg.openpgp.program.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(Main(context.Background(), os.Args[1:], OSIO()))
	}
	os.Exit(m.Run())
}

type staticCreds struct {
	cred   *config.Credential
	values map[string]string
}

func (s staticCreds) Credential(name string) (*config.Credential, bool) {
	return s.cred, name == s.cred.Name
}

func (s staticCreds) GetSlot(_ context.Context, name, slot string) (string, error) {
	v, ok := s.values[name+"."+slot]
	if !ok {
		return "", fmt.Errorf("credential %q has no %s", name, slot)
	}
	return v, nil
}

// TestGitEndToEnd runs real git commit -S, git tag -s, and git verify-commit
// through this helper and the real signer handler, with a
// passphrase-protected key.
func TestGitEndToEnd(t *testing.T) {
	for _, bin := range []string{"git", "gpg"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}

	key, err := pgp.PGP().KeyGeneration().AddUserId("Agent", "agent@example.com").New().GenerateKey()
	require.NoError(t, err)
	locked, err := pgp.PGP().LockKey(key, []byte("hunter2"))
	require.NoError(t, err)
	armoredPriv, err := locked.Armor()
	require.NoError(t, err)
	armoredPub, err := key.GetArmoredPublicKey()
	require.NoError(t, err)
	fpr := strings.ToUpper(key.GetFingerprint())

	svc := &config.Service{Name: "signing", Signer: &config.Signer{OpenPGP: &config.OpenPGPSigner{Keys: []config.OpenPGPKey{{ID: fpr, Credential: "sign"}}}}}
	sg := &signer.OpenPGP{Creds: staticCreds{
		cred:   &config.Credential{Name: "sign", Allow: []string{config.AllowInternal}, PrivateKey: &config.ValueSource{Source: "provided"}, Password: &config.ValueSource{Source: "provided"}},
		values: map[string]string{"sign.private_key": armoredPriv, "sign.password": "hunter2"},
	}}
	terminal := signer.Terminal(svc, sg, zerolog.Nop())
	const claimed = "github.com/pastdev/agentcon"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stands in for the reference filter: only the claimed repository signs.
		if r.URL.Query().Get("repository") != claimed {
			http.Error(w, "agent-bouncer: request denied by filter:signing-repository-scope: repository not claimed", http.StatusForbidden)
			return
		}
		u := *r.URL
		u.Scheme, u.Host = "https", r.Host
		resp, _ := terminal(&chain.Request{Ctx: r.Context(), Transport: chain.TransportHTTP, Method: r.Method, URL: &u, Header: r.Header, Body: chain.NewBody(r.Body)})
		if resp.Denial != nil {
			http.Error(w, resp.Denial.Reason, resp.Denial.Status)
			return
		}
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.Status)
		b, _ := resp.Body.ReadAll()
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)

	// gpg sockets live in the home directory and must fit a short path.
	home, err := os.MkdirTemp("", "gs")
	require.NoError(t, err)
	gnupg := filepath.Join(home, "g")
	require.NoError(t, os.Mkdir(gnupg, 0o700))
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", gnupg, "--kill", "all").Run() //nolint:gosec // test temp dir
		_ = os.RemoveAll(home)
	})
	caFile := filepath.Join(home, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	wrapper := filepath.Join(home, "git-sign")
	require.NoError(t, os.WriteFile(wrapper, []byte("#!/bin/sh\n"+helperEnv+"=1 exec '"+os.Args[0]+"' \"$@\"\n"), 0o700)) //nolint:gosec // test wrapper must be executable
	repo := filepath.Join(home, "r")
	require.NoError(t, os.Mkdir(repo, 0o700))

	env := append(os.Environ(),
		"HOME="+home,
		"GNUPGHOME="+gnupg,
		"GIT_CONFIG_NOSYSTEM=1",
		"SSL_CERT_FILE="+caFile,
		EnvSignerURL+"="+srv.URL+config.SignerPath,
		"HTTPS_PROXY=", "https_proxy=", "HTTP_PROXY=", "http_proxy=", "NO_PROXY=*", "no_proxy=*",
	)
	run := func(stdin string, args ...string) (string, error) {
		cmd := exec.Command(args[0], args[1:]...) //nolint:gosec // test runs git and gpg
		cmd.Dir = repo
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := run("", args...)
		require.NoError(t, err, "%v: %s", args, out)
		return out
	}
	_, err = run(armoredPub, "gpg", "--batch", "--import")
	require.NoError(t, err)
	_, err = run(fpr+":6:\n", "gpg", "--batch", "--import-ownertrust")
	require.NoError(t, err)
	must("git", "init", "-q", "-b", "main")
	must("git", "config", "user.name", "Agent")
	must("git", "config", "user.email", "agent@example.com")
	must("git", "config", "user.signingkey", fpr)
	must("git", "config", "gpg.format", "openpgp")
	must("git", "config", "gpg.openpgp.program", wrapper)
	must("git", "remote", "add", "origin", "git@github.com:pastdev/agentcon.git")

	stage := func(t *testing.T, name string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(name), 0o600))
		must("git", "add", name)
	}
	staged := func(t *testing.T) string {
		t.Helper()
		return strings.TrimSpace(must("git", "diff", "--cached", "--name-only"))
	}

	t.Run("commit -S signs and verify-commit accepts it", func(t *testing.T) {
		stage(t, "a.txt")
		out := must("git", "commit", "-q", "-S", "-m", "signed commit")
		assert.Empty(t, out)
		out = must("git", "verify-commit", "HEAD")
		assert.Contains(t, out, "Good signature")
		raw := must("git", "cat-file", "commit", "HEAD")
		assert.Contains(t, raw, "gpgsig -----BEGIN PGP SIGNATURE-----")
		assert.NotContains(t, raw, "Version:")
	})
	t.Run("tag -s signs and verify-tag accepts it", func(t *testing.T) {
		must("git", "tag", "-s", "v1.0.0", "-m", "release")
		out := must("git", "verify-tag", "v1.0.0")
		assert.Contains(t, out, "Good signature")
	})
	t.Run("a denied repository fails the commit and keeps the index", func(t *testing.T) {
		must("git", "remote", "set-url", "origin", "git@github.com:pastdev/other.git")
		t.Cleanup(func() { must("git", "remote", "set-url", "origin", "git@github.com:pastdev/agentcon.git") })
		stage(t, "b.txt")
		out, err := run("", "git", "commit", "-q", "-S", "-m", "denied")
		require.Error(t, err, out)
		assert.Contains(t, out, "signer answered 403")
		assert.Contains(t, out, "repository not claimed")
		assert.Equal(t, "b.txt", staged(t))
	})
	t.Run("an unknown key fails the commit and keeps the index", func(t *testing.T) {
		must("git", "config", "user.signingkey", "1111111111111111")
		t.Cleanup(func() { must("git", "config", "user.signingkey", fpr) })
		out, err := run("", "git", "commit", "-q", "-S", "-m", "unknown key")
		require.Error(t, err, out)
		assert.Contains(t, out, "unknown signing key")
		assert.Equal(t, "b.txt", staged(t))
	})
}
