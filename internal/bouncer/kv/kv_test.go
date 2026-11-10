package kv

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	type testCase struct {
		path string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		s, err := Open(tc.path)
		require.NoError(t, err)
		assert.InDelta(t, 1, s.Incr("f", "pushes", 1, time.Hour), 0)
		assert.InDelta(t, 2, s.Incr("f", "pushes", 1, time.Hour), 0)
		s.Set("f", "short", "x", time.Millisecond)
		s.Set("other", "pushes", "separate namespace", 0)
		_ = s.Close()
		time.Sleep(5 * time.Millisecond)

		s2, err := Open(tc.path)
		require.NoError(t, err)
		defer func() { _ = s2.Close() }()
		v, ok := s2.Get("f", "pushes")
		require.True(t, ok, "pushes")
		assert.InDelta(t, 2, v, 0)
		_, ok = s2.Get("f", "short")
		assert.False(t, ok, "expired key survived")
		v, _ = s2.Get("other", "pushes")
		assert.Equal(t, "separate namespace", v)
	}

	t.Run("persists increments, expires ttl, and isolates namespaces", func(t *testing.T) {
		tester(t, testCase{path: filepath.Join(t.TempDir(), "kv.json")})
	})
}
