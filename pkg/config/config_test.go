package config

import (
	"testing"
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
	if len(cfg.Agents) != 0 {
		t.Fatalf("unexpected builtin agents %v", cfg.Agents)
	}
}
