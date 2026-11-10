package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandHomePath(t *testing.T) {
	type testCase struct {
		path string
		home string
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := expandHomePath(tc.path, tc.home)
		assert.Equal(t, tc.want, got)
	}

	t.Run("joins a path under home", func(t *testing.T) {
		tester(t, testCase{
			path: "~/.cursor",
			home: "/home/me",
			want: filepath.Join("/home/me", ".cursor"),
		})
	})
	t.Run("expands a lone tilde to home", func(t *testing.T) {
		tester(t, testCase{
			path: "~",
			home: "/home/me",
			want: filepath.Clean("/home/me"),
		})
	})
	t.Run("leaves an absolute path unchanged", func(t *testing.T) {
		tester(t, testCase{
			path: "/abs",
			home: "/home/me",
			want: "/abs",
		})
	})
}

func TestResolveMountSource(t *testing.T) {
	type testCase struct {
		source string
		home   string
		want   string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := resolveMountSource(tc.source, tc.home)
		assert.Equal(t, tc.want, got)
	}

	t.Run("joins a relative source under home", func(t *testing.T) {
		home := t.TempDir()
		tester(t, testCase{
			source: ".config/cursor",
			home:   home,
			want:   filepath.Join(home, ".config", "cursor"),
		})
	})
}

func TestResolveConfigDir(t *testing.T) {
	type testCase struct {
		rel     string
		home    string
		overlay []string
		want    string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := resolveConfigDir(tc.rel, tc.home, tc.overlay)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("lets the last overlay win", func(t *testing.T) {
		home := t.TempDir()
		first := t.TempDir()
		second := t.TempDir()
		err := os.MkdirAll(filepath.Join(first, "image"), 0o700)
		require.NoError(t, err)
		err = os.MkdirAll(filepath.Join(second, "image"), 0o700)
		require.NoError(t, err)
		tester(t, testCase{
			rel:     "image",
			home:    home,
			overlay: []string{first, second},
			want:    filepath.Join(second, "image"),
		})
	})
}
