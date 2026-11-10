package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/audit"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
)

func TestCheck(t *testing.T) {
	type testCase struct {
		cfg         *bouncercfg.Config
		wantPath    string
		wantProfile string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := Check(tc.cfg)
		require.NoError(t, err)
		assert.Equal(t, tc.wantPath, got.Path)
		require.Len(t, got.Profiles, 1)
		assert.Equal(t, tc.wantProfile, got.Profiles[0].Name)
	}

	t.Run("compiles a minimal tunnel policy", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		err := os.WriteFile(path, []byte(`
listen: 127.0.0.1:8228
profiles:
  default:
    unmatched: tunnel
`), 0o600)
		require.NoError(t, err)
		cfg, err := bouncercfg.Load(path)
		require.NoError(t, err)
		tester(t, testCase{cfg: cfg, wantPath: cfg.Path, wantProfile: "default"})
	})
}

func TestFormatDecision(t *testing.T) {
	type testCase struct {
		entry audit.Entry
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := FormatDecision(tc.entry)
		assert.Contains(t, got, "DENY")
		assert.Contains(t, got, "blocked")
	}

	t.Run("includes the decision and reason", func(t *testing.T) {
		tester(t, testCase{
			entry: audit.Entry{
				Decision: "deny",
				Label:    "agent",
				Request:  "GET https://example",
				By:       "filter",
				Reason:   "blocked",
			},
		})
	})
}
