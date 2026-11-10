package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

func TestPlanListen(t *testing.T) {
	type testCase struct {
		cfg       *config.Config
		wantSplit bool
		wantProxy string
		wantMgmt  string
		wantErr   bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		plan, err := planListen(tc.cfg)
		if tc.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.wantSplit, plan.split, "split")
		assert.Equal(t, tc.wantProxy, plan.proxy)
		assert.Equal(t, tc.wantMgmt, plan.mgmt)
	}

	t.Run("uses a combined listen when network env is unset", func(t *testing.T) {
		t.Setenv("AGENT_NETWORK", "")
		t.Setenv("MANAGEMENT_NETWORK", "")
		tester(t, testCase{
			cfg:       &config.Config{Listen: "127.0.0.1:8228", SSHListen: "127.0.0.1:8229"},
			wantProxy: "127.0.0.1:8228",
			wantMgmt:  "127.0.0.1:8228",
		})
	})
	t.Run("requires both agent and management networks", func(t *testing.T) {
		t.Setenv("AGENT_NETWORK", "10.0.0.0/16")
		t.Setenv("MANAGEMENT_NETWORK", "")
		tester(t, testCase{
			cfg:     &config.Config{},
			wantErr: true,
		})
	})
}
