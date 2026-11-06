package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/audit"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
)

func TestCheckMinimalPolicy(t *testing.T) {
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
	got, err := Check(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != cfg.Path {
		t.Fatalf("path %q", got.Path)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].Name != "default" {
		t.Fatalf("%+v", got.Profiles)
	}
}

func TestFormatDecision(t *testing.T) {
	got := FormatDecision(audit.Entry{
		Decision: "deny",
		Label:    "agent",
		Request:  "GET https://example",
		By:       "filter",
		Reason:   "blocked",
	})
	if !strings.Contains(got, "DENY") || !strings.Contains(got, "blocked") {
		t.Fatalf("%q", got)
	}
}
