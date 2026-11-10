package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoader(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		loader := NewLoader()
		cfg, err := loader.Config()
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Empty(t, cfg.Agents)
	}

	t.Run("returns an empty config", func(t *testing.T) {
		tester(t)
	})
}
