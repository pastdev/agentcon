package config

import (
	"testing"
)

func TestNewLoader(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		loader := NewLoader()
		cfg, err := loader.Config()
		if err != nil {
			t.Fatal(err)
		}
		if cfg == nil {
			t.Fatal("expected config")
		}
		if len(cfg.Agents) != 0 {
			t.Fatalf("unexpected builtin agents %v", cfg.Agents)
		}
	}

	t.Run("returns an empty config", func(t *testing.T) {
		tester(t)
	})
}
