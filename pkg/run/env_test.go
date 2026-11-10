package run

import (
	"slices"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostEnvCreds(t *testing.T) {
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
		got, err := hostEnvCreds([]byte(tc.policy), tc.extra)
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
	t.Run("skips non-env sources", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  bw:
    token:
      source: bitwarden
      email: user@example.com
      item: GitLab
      path: $.login.password
`,
			extra: []string{"UNUSED=1"},
			want:  map[string]string{},
		})
	})
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
}

func TestBouncerSidecarSpec(t *testing.T) {
	type testCase struct {
		log      SidecarLog
		wantArgs []string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		spec := bouncerSidecarSpec(
			Request{
				Image:             testImage,
				User:              testUser,
				Context:           "git",
				Project:           "github.com/pastdev/agentcon",
				Slug:              testSlug,
				SidecarExtraHosts: []string{testExtraHost},
				SidecarEnv:        []string{"SMOKE_TOKEN=should-not-appear"},
				SidecarLog:        tc.log,
			},
			sidecarImage,
			map[string]string{labelRole: roleBouncer},
			externalNet{name: "ext-net", subnet: "10.2.0.0/16", hostPort: 18228, controlAddr: "127.0.0.1:18228"},
			"agent-net",
			"10.1.0.0/16",
		)
		assert.Equal(t, "agentcon-github-com-pastdev-agentcon-deadbeef-bouncer", spec.Name)
		assert.Equal(t, sidecarImage, spec.Image)
		assert.Equal(t, []string{sidecarBinPath}, spec.Entrypoint)
		assert.Equal(t, tc.wantArgs, spec.Args)
		assert.Equal(t, []string{testExtraHost}, spec.ExtraHosts)
		assert.Equal(t, []string{"ext-net", "agent-net"}, spec.Networks)
		require.NotEmpty(t, spec.Ports)
		assert.Equal(t, "18228", spec.Ports[0].HostPort)
		assert.Equal(t, defaultProxyPort, spec.Ports[0].ContainerPort)
		want := map[string]string{
			"AGENT_NETWORK":      "10.1.0.0/16",
			"MANAGEMENT_NETWORK": "10.2.0.0/16",
			"MANAGEMENT_PORT":    defaultProxyPort,
		}
		got := map[string]string{}
		for _, e := range spec.Env {
			k, v, ok := strings.Cut(e, "=")
			require.True(t, ok, "env %q", e)
			got[k] = v
		}
		assert.NotContains(t, got, "SMOKE_TOKEN", "secret in container env")
		assert.Subset(t, got, want)
	}

	serve := []string{roleBouncer, "serve", "--file", sidecarConfigPath, "--state-dir", sidecarStatePath}
	t.Run("uses serve as pid 1 and omits secrets", func(t *testing.T) {
		tester(t, testCase{wantArgs: serve})
	})
	t.Run("forwards log settings", func(t *testing.T) {
		tester(t, testCase{
			log: SidecarLog{Bouncer: "debug", Audit: "warn", Format: "json"},
			wantArgs: append(slices.Clone(serve),
				"--log", "bouncer=debug", "--log", "audit=warn", "--log-format", "json"),
		})
	})
}

func TestBouncerAgentEnv(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		env := bouncerAgentEnv(daemon.NewSession{SessionRecord: daemon.SessionRecord{Token: "tok"}}, "10.1.0.2")
		got := map[string]string{}
		for _, e := range env {
			k, v, ok := strings.Cut(e, "=")
			require.True(t, ok, "env %q", e)
			got[k] = v
		}
		want := `"` + agentSSHClient + `" -F "` + agentSSHConfig + `"`
		assert.Equal(t, want, got["GIT_SSH_COMMAND"])
		assert.NotContains(t, got["GIT_SSH_COMMAND"], agentBinPath, "should invoke ssh, not agentcon")
	}

	t.Run("sets GIT_SSH_COMMAND to ssh -F", func(t *testing.T) {
		tester(t)
	})
}
