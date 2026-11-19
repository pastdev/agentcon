package host

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvCreds(t *testing.T) {
	type testCase struct {
		policy  string
		extra   []string
		setenv  map[string]string
		want    map[string]string
		wantErr []string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		for k, v := range tc.setenv {
			t.Setenv(k, v)
		}
		got, err := envCreds([]byte(tc.policy), tc.extra)
		if len(tc.wantErr) > 0 {
			require.Error(t, err)
			for _, s := range tc.wantErr {
				require.ErrorContains(t, err, s)
			}
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("reads from the process environment", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: env
      env: SMOKE_TOKEN
`,
			setenv: map[string]string{"SMOKE_TOKEN": "from-os"},
			want:   map[string]string{"SMOKE_TOKEN": "from-os"},
		})
	})
	t.Run("lets extra pairs win over the process environment", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: env
      env: SMOKE_TOKEN
`,
			setenv: map[string]string{"SMOKE_TOKEN": "from-os"},
			extra:  []string{"SMOKE_TOKEN=from-extra"},
			want:   map[string]string{"SMOKE_TOKEN": "from-extra"},
		})
	})
	t.Run("reports every missing env slot", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: env
      env: SMOKE_TOKEN
  other:
    token:
      source: env
      env: OTHER_TOKEN
`,
			setenv:  map[string]string{"SMOKE_TOKEN": ""},
			wantErr: []string{"SMOKE_TOKEN", "OTHER_TOKEN"},
		})
	})
	t.Run("reads a bitwarden env password from the process environment", func(t *testing.T) {
		tester(t, testCase{
			policy: bitwardenPolicy("{source: env, env: BW_MASTER}"),
			setenv: map[string]string{"BW_MASTER": "fake-from-os"},
			want:   map[string]string{"BW_MASTER": "fake-from-os"},
		})
	})
	t.Run("lets extra pairs win for a bitwarden env password", func(t *testing.T) {
		tester(t, testCase{
			policy: bitwardenPolicy("{source: env, env: BW_MASTER}"),
			setenv: map[string]string{"BW_MASTER": "fake-from-os"},
			extra:  []string{"BW_MASTER=fake-from-extra"},
			want:   map[string]string{"BW_MASTER": "fake-from-extra"},
		})
	})
	t.Run("reports a missing bitwarden env password", func(t *testing.T) {
		tester(t, testCase{
			policy:  bitwardenPolicy("{source: env, env: BW_MASTER}"),
			setenv:  map[string]string{"BW_MASTER": ""},
			wantErr: []string{"missing BW_MASTER"},
		})
	})
	t.Run("names a variable shared by a slot and an account once", func(t *testing.T) {
		_, err := envCreds([]byte(bitwardenPolicy("{source: env, env: AGENTCON_TEST_UNSET}")+`  tok:
    token:
      source: env
      env: AGENTCON_TEST_UNSET
`), nil)
		require.EqualError(t, err, "missing AGENTCON_TEST_UNSET")
	})
	t.Run("skips an unused account", func(t *testing.T) {
		tester(t, testCase{
			policy: "bitwarden:\n  unused:\n    email: u@example.com\n    password: {source: env, env: AGENTCON_TEST_UNSET}\n",
			want:   map[string]string{},
		})
	})
	t.Run("skips non-env sources", func(t *testing.T) {
		tester(t, testCase{
			policy: bitwardenPolicy("{source: command, command: [unused]}"),
			extra:  []string{"UNUSED=1"},
			want:   map[string]string{},
		})
	})
}

// bitwardenPolicy is a policy whose bw credential uses account work with
// the given password source.
func bitwardenPolicy(password string) string {
	return `
bitwarden:
  work:
    email: user@example.com
    password: ` + password + `
credentials:
  bw:
    token:
      source: bitwarden
      account: work
      item: GitLab
      path: $.login.password
`
}

func TestParseEnvPairs(t *testing.T) {
	tester := func(t *testing.T, pairs []string, wantErr string) {
		t.Helper()
		_, err := parseEnvPairs(pairs)
		if wantErr == "" {
			require.NoError(t, err)
			return
		}
		require.ErrorContains(t, err, wantErr)
	}

	t.Run("rejects a bare name", func(t *testing.T) {
		tester(t, []string{"NOVALUE"}, "NAME=value")
	})
	t.Run("names a malformed entry by position, not content", func(t *testing.T) {
		_, err := parseEnvPairs([]string{"A=1", "TOKEN:s3cret"})
		require.EqualError(t, err, "sidecar env entry 2 must be NAME=value")
	})
}
