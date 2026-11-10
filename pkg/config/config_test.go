package config

import (
	"strings"
	"testing"

	cfgldr "github.com/pastdev/configloader/pkg/config"
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

func TestValueTemplateUrlFile(t *testing.T) {
	tester := func(t *testing.T, value string, want string) {
		t.Helper()
		var doc any
		err := valueTemplateUnmarshal()(cfgldr.LoadContext{}, []byte("v: '"+value+"'\n"), &doc)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want %q", err, want)
		}
	}

	t.Run("is registered", func(t *testing.T) {
		tester(t, `{{ urlFile "http://example.com/a" "a.pem" }}`, "url must be https")
	})
}
