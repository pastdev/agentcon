package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		if err != nil {
			t.Fatal(err)
		}
		if got.Path != tc.wantPath {
			t.Fatalf("path %q", got.Path)
		}
		if len(got.Profiles) != 1 || got.Profiles[0].Name != tc.wantProfile {
			t.Fatalf("%+v", got.Profiles)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := bouncercfg.Load(path)
		if err != nil {
			t.Fatal(err)
		}
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
		if !strings.Contains(got, "DENY") || !strings.Contains(got, "blocked") {
			t.Fatalf("%q", got)
		}
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
