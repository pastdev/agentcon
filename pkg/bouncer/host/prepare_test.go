package host

import (
	"maps"
	"runtime"
	"slices"
	"testing"

	"github.com/pastdev/agentcon/pkg/bouncer/crederr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareCredentials(t *testing.T) {
	type testCase struct {
		policy   string
		env      []string
		provided map[string]string
		skipWin  string
		want     Credentials
		// wantErr is a substring of the error. notInErr must not appear in it.
		wantErr  string
		notInErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		if tc.skipWin != "" && runtime.GOOS == "windows" {
			t.Skip(tc.skipWin)
		}
		env := slices.Clone(tc.env)
		provided := maps.Clone(tc.provided)
		got, err := PrepareCredentials(t.Context(), CredentialOptions{Policy: []byte(tc.policy), Env: env, Provided: provided})
		assert.Equal(t, tc.env, env, "Env must not change")
		assert.Equal(t, tc.provided, provided, "Provided must not change")
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			assert.Equal(t, Credentials{}, got, "an error returns no partial credentials")
			if tc.notInErr != "" {
				assert.NotContains(t, err.Error(), tc.notInErr)
			}
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("resolves env and provided sources", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  gh:
    token:
      source: env
      env: AGENTCON_TEST_GH
  gl:
    token:
      source: provided
`,
			env:      []string{"AGENTCON_TEST_GH=from-env"},
			provided: map[string]string{"gl.token": "from-caller", "unused.token": "x"},
			want: Credentials{
				Env:      map[string]string{"AGENTCON_TEST_GH": "from-env"},
				Provided: map[string]string{"gl.token": "from-caller"},
			},
		})
	})
	t.Run("forwards a bitwarden env password", func(t *testing.T) {
		tester(t, testCase{
			policy: `prompts: {cli: false}
bitwarden:
  work:
    email: user@example.com
    password: {source: env, env: AGENTCON_TEST_BW_MASTER}
credentials:
  vault:
    token:
      source: bitwarden
      account: work
      item: example
      path: $.login.password
`,
			env:  []string{"AGENTCON_TEST_BW_MASTER=fake-test-password"},
			want: Credentials{Env: map[string]string{"AGENTCON_TEST_BW_MASTER": "fake-test-password"}, Provided: map[string]string{}},
		})
	})
	t.Run("forwards a caller-provided bitwarden password", func(t *testing.T) {
		tester(t, testCase{
			policy: `prompts: {cli: false}
bitwarden:
  work:
    email: user@example.com
    password: {source: provided}
credentials:
  vault:
    token:
      source: bitwarden
      account: work
      item: example
      path: $.login.password
`,
			provided: map[string]string{"bitwarden.work": "fake-test-password"},
			want:     Credentials{Env: map[string]string{}, Provided: map[string]string{"bitwarden.work": "fake-test-password"}},
		})
	})
	t.Run("refuses an unanswerable policy first", func(t *testing.T) {
		tester(t, testCase{
			policy: `prompts: {cli: false}
bitwarden:
  work:
    email: user@example.com
credentials:
  bw:
    token:
      source: bitwarden
      account: work
      item: GitLab
      path: $.login.password
`,
			wantErr: "bouncer policy: bitwarden accounts work have no password",
		})
	})
	t.Run("names a malformed env entry by position", func(t *testing.T) {
		tester(t, testCase{
			policy:   "credentials: {}\n",
			env:      []string{"A=1", "TOKEN:s3cret"},
			wantErr:  "sidecar env entry 2 must be NAME=value",
			notInErr: "s3cret",
		})
	})
	t.Run("keeps command stderr out of the error and returns nothing", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  gh:
    token:
      source: env
      env: AGENTCON_TEST_GH
  cmd:
    token:
      source: command
      command: [sh, -c, "echo s3cret-stderr >&2; exit 1"]
`,
			env:      []string{"AGENTCON_TEST_GH=from-env"},
			skipWin:  "uses sh",
			wantErr:  "sh: exit status 1",
			notInErr: "s3cret-stderr",
		})
	})
}

func TestPrepareCredentialsCommandStderr(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		if runtime.GOOS == "windows" {
			t.Skip("uses sh")
		}
		_, err := PrepareCredentials(t.Context(), CredentialOptions{Policy: []byte(`
credentials:
  cmd:
    token:
      source: command
      command: [sh, -c, "echo vault locked >&2; exit 1"]
`)})
		assert.Equal(t, "vault locked", crederr.Stderr(err))
	}

	t.Run("carries stderr for the operator", func(t *testing.T) {
		tester(t)
	})
}
