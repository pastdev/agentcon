package run

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
