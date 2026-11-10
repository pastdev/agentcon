package run

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func TestHostProvidedCreds(t *testing.T) {
	type testCase struct {
		policy      string
		extra       map[string]string
		skipWindows string
		want        map[string]string
		wantErr     string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		if tc.skipWindows != "" && runtime.GOOS == "windows" {
			t.Skip(tc.skipWindows)
		}
		got, err := hostProvidedCreds(context.Background(), []byte(tc.policy), tc.extra)
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("reads a file slot", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		err := os.WriteFile(path, []byte("from-file\n"), 0o600)
		require.NoError(t, err)
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: file
      file: ` + path + `
`,
			want: map[string]string{"tok.token": "from-file"},
		})
	})
	t.Run("reads a command slot", func(t *testing.T) {
		tester(t, testCase{
			skipWindows: "uses sh",
			policy: `
credentials:
  tok:
    token:
      source: command
      command: ["sh", "-c", "printf from-cmd"]
`,
			want: map[string]string{"tok.token": "from-cmd"},
		})
	})
	t.Run("reads a provided slot", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: provided
`,
			extra: map[string]string{"tok.token": "from-extra"},
			want:  map[string]string{"tok.token": "from-extra"},
		})
	})
	t.Run("lets extra pairs win over a file slot", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		err := os.WriteFile(path, []byte("from-file"), 0o600)
		require.NoError(t, err)
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: file
      file: ` + path + `
`,
			extra: map[string]string{"tok.token": "from-extra"},
			want:  map[string]string{"tok.token": "from-extra"},
		})
	})
	t.Run("reports a missing provided slot", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: provided
`,
			wantErr: "tok",
		})
	})
	t.Run("reports a missing file", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: file
      file: /no/such/agentcon-secret
`,
			wantErr: "tok",
		})
	})
	t.Run("reads a file password and leaves env username to hostEnvCreds", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		err := os.WriteFile(path, []byte("from-file\n"), 0o600)
		require.NoError(t, err)
		policy := `
credentials:
  login:
    username:
      source: env
      env: SMOKE_USER
    password:
      source: file
      file: ` + path + `
`
		t.Setenv("SMOKE_USER", "alice")
		tester(t, testCase{
			policy: policy,
			want:   map[string]string{"login.password": "from-file"},
		})
		env, err := hostEnvCreds([]byte(policy), nil)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"SMOKE_USER": "alice"}, env)
	})
	t.Run("skips env bitwarden and ssh-agent sources", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  envtok:
    token:
      source: env
      env: UNUSED
  bw:
    token:
      source: bitwarden
      email: user@example.com
      item: GitLab
      path: $.login.password
  key:
    private_key:
      source: ssh-agent
`,
			want: map[string]string{},
		})
	})
	t.Run("reads a keyring slot", func(t *testing.T) {
		keyring.MockInit()
		err := keyring.Set(creds.KeyringService, "tok", "from-keyring")
		require.NoError(t, err)
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: keyring
`,
			want: map[string]string{"tok.token": "from-keyring"},
		})
	})
}

func TestHostSSHAuthSock(t *testing.T) {
	type testCase struct {
		policy  string
		want    string
		wantErr []string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := hostSSHAuthSock([]byte(tc.policy))
		if len(tc.wantErr) > 0 {
			require.Error(t, err)
			found := slices.ContainsFunc(tc.wantErr, func(s string) bool {
				return strings.Contains(err.Error(), s)
			})
			assert.True(t, found, "got %v", err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("ignores policy without ssh-agent", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: env
      env: UNUSED
`,
		})
	})
	t.Run("requires SSH_AUTH_SOCK", func(t *testing.T) {
		t.Setenv("SSH_AUTH_SOCK", "")
		tester(t, testCase{
			policy: `
credentials:
  key:
    private_key:
      source: ssh-agent
`,
			wantErr: []string{"SSH_AUTH_SOCK", "ssh-agent"},
		})
	})
	t.Run("returns the socket path", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("sidecar ssh-agent bind is unix-only")
		}
		sock := filepath.Join(t.TempDir(), "agent.sock")
		err := os.WriteFile(sock, []byte{}, 0o600)
		require.NoError(t, err)
		t.Setenv("SSH_AUTH_SOCK", sock)
		tester(t, testCase{
			policy: `
credentials:
  key:
    private_key:
      source: ssh-agent
`,
			want: sock,
		})
	})
}

func TestWithSSHAuthSock(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		spec := withSSHAuthSock(containerSpecEnvOnly(), "/tmp/agent.sock")
		assert.Equal(t, []container.Mount{{Source: "/tmp/agent.sock", Target: sidecarSSHAuthSock}}, spec.Mounts)
		assert.Contains(t, spec.Env, "SSH_AUTH_SOCK="+sidecarSSHAuthSock)
	}

	t.Run("binds the socket and sets SSH_AUTH_SOCK", func(t *testing.T) {
		tester(t)
	})
}

func containerSpecEnvOnly() container.Spec {
	return bouncerSidecarSpec(
		Request{Image: testImage, User: testUser},
		sidecarImage,
		nil,
		externalNet{name: "ext-net", subnet: "10.2.0.0/16", hostPort: 18228, controlAddr: "127.0.0.1:18228"},
		"agent-net",
		"10.1.0.0/16",
	)
}
