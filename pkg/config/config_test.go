package config

import (
	"testing"

	"github.com/pastdev/agentcon/pkg/harness"
)

func TestLoaderEmpty(t *testing.T) {
	loader := NewLoader()
	cfg, err := loader.Config()
	if err != nil {
		t.Fatalf("config load: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config")
	}
	spec, ok := cfg.Harnesses[harness.Cursor]
	if !ok || !containsHost(spec.Tunnel, testHostCursor) {
		t.Fatalf("harnesses.cursor %v", spec.Tunnel)
	}
}

func containsHost(hosts []string, want string) bool {
	for _, h := range hosts {
		if h == want {
			return true
		}
	}
	return false
}
