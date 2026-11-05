package run

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/zalando/go-keyring"
)

func TestHostProvidedCredsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	err := os.WriteFile(path, []byte("from-file\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	got, err := hostProvidedCreds(context.Background(), []byte(`
credentials:
  tok:
    source: file
    path: `+path+`
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["tok"] != "from-file" {
		t.Fatalf("got %v", got)
	}
}

func TestHostProvidedCredsCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	got, err := hostProvidedCreds(context.Background(), []byte(`
credentials:
  tok:
    source: command
    command: ["sh", "-c", "printf from-cmd"]
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["tok"] != "from-cmd" {
		t.Fatalf("got %v", got)
	}
}

func TestHostProvidedCredsProvided(t *testing.T) {
	got, err := hostProvidedCreds(context.Background(), []byte(`
credentials:
  tok:
    source: provided
`), map[string]string{"tok": testFromExtra})
	if err != nil {
		t.Fatal(err)
	}
	if got["tok"] != testFromExtra {
		t.Fatalf("got %v", got)
	}
}

func TestHostProvidedCredsExtraWinsOverFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	err := os.WriteFile(path, []byte("from-file"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	got, err := hostProvidedCreds(context.Background(), []byte(`
credentials:
  tok:
    source: file
    path: `+path+`
`), map[string]string{"tok": testFromExtra})
	if err != nil {
		t.Fatal(err)
	}
	if got["tok"] != testFromExtra {
		t.Fatalf("got %v", got)
	}
}

func TestHostProvidedCredsMissingProvided(t *testing.T) {
	_, err := hostProvidedCreds(context.Background(), []byte(`
credentials:
  tok:
    source: provided
`), nil)
	if err == nil || !strings.Contains(err.Error(), "tok") {
		t.Fatalf("got %v", err)
	}
}

func TestHostProvidedCredsMissingFile(t *testing.T) {
	_, err := hostProvidedCreds(context.Background(), []byte(`
credentials:
  tok:
    source: file
    path: /no/such/agentcon-secret
`), nil)
	if err == nil || !strings.Contains(err.Error(), "tok") {
		t.Fatalf("got %v", err)
	}
}

func TestHostProvidedCredsSkipsEnvBitwardenAndSSH(t *testing.T) {
	got, err := hostProvidedCreds(context.Background(), []byte(`
credentials:
  envtok:
    source: env
    env: UNUSED
  bw:
    source: bitwarden
    bitwarden:
      email: user@example.com
      item: GitLab
  key:
    source: ssh-agent
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestHostProvidedCredsKeyring(t *testing.T) {
	keyring.MockInit()
	err := keyring.Set(creds.KeyringService, "tok", "from-keyring")
	if err != nil {
		t.Fatal(err)
	}
	got, err := hostProvidedCreds(context.Background(), []byte(`
credentials:
  tok:
    source: keyring
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["tok"] != "from-keyring" {
		t.Fatalf("got %v", got)
	}
}

func TestHostSSHAuthSockUnused(t *testing.T) {
	got, err := hostSSHAuthSock([]byte(`
credentials:
  tok:
    source: env
    env: UNUSED
`))
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestHostSSHAuthSockMissingEnv(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err := hostSSHAuthSock([]byte(`
credentials:
  key:
    source: ssh-agent
`))
	if err == nil || (!strings.Contains(err.Error(), "SSH_AUTH_SOCK") && !strings.Contains(err.Error(), "ssh-agent")) {
		t.Fatalf("got %v", err)
	}
}

func TestHostSSHAuthSock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sidecar ssh-agent bind is unix-only")
	}
	sock := filepath.Join(t.TempDir(), "agent.sock")
	err := os.WriteFile(sock, []byte{}, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", sock)
	got, err := hostSSHAuthSock([]byte(`
credentials:
  key:
    source: ssh-agent
`))
	if err != nil {
		t.Fatal(err)
	}
	if got != sock {
		t.Fatalf("got %q", got)
	}
}

func TestWithSSHAuthSock(t *testing.T) {
	spec := withSSHAuthSock(containerSpecEnvOnly(), "/tmp/agent.sock")
	if len(spec.Mounts) != 1 || spec.Mounts[0].Source != "/tmp/agent.sock" || spec.Mounts[0].Target != sidecarSSHAuthSock {
		t.Fatalf("mounts %+v", spec.Mounts)
	}
	found := false
	for _, e := range spec.Env {
		if e == "SSH_AUTH_SOCK="+sidecarSSHAuthSock {
			found = true
		}
	}
	if !found {
		t.Fatalf("env %v", spec.Env)
	}
}

func containerSpecEnvOnly() container.Spec {
	return bouncerSidecarSpec(
		Request{Image: testImage, User: testUser},
		nil,
		"ext-net",
		"agent-net",
		"10.1.0.0/16",
		"10.2.0.0/16",
		18228,
	)
}
