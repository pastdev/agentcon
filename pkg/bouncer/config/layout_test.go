package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteLayoutAndLoadDir(t *testing.T) {
	type testCase struct {
		policy     []byte
		tsFiles    map[string]string
		wantListen string
		wantTS     string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		dir := t.TempDir()
		err := WriteLayout(DirFS(dir), tc.policy, tc.tsFiles)
		require.NoError(t, err)
		got, err := LoadDir(dir)
		require.NoError(t, err)
		assert.Equal(t, tc.wantListen, got.Listen)
		if tc.wantTS == "" {
			return
		}
		//nolint:gosec // test fixture under TempDir
		data, err := os.ReadFile(filepath.Join(dir, TSDir, tc.wantTS))
		require.NoError(t, err)
		assert.Equal(t, "export {}\n", string(data))
	}

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "deny.ts")
	err := os.WriteFile(src, []byte("export {}\n"), 0o600)
	require.NoError(t, err)

	t.Run("loads written layout", func(t *testing.T) {
		tester(t, testCase{
			policy:     []byte("listen: 127.0.0.1:8228\n"),
			tsFiles:    map[string]string{"filters/deny.ts": src},
			wantListen: "127.0.0.1:8228",
			wantTS:     "filters/deny.ts",
		})
	})
}

func TestRewriteTSPaths(t *testing.T) {
	type testCase struct {
		overlay string
		text    func(ts string) string
		want    string
		leak    string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		ts := filepath.Join(tc.overlay, TSDir, "filters", "a.ts")
		got := RewriteTSPaths([]byte(tc.text(ts)), []string{tc.overlay})
		assert.NotContains(t, string(got), tc.leak, "host path leaked")
		assert.Contains(t, string(got), tc.want)
	}

	overlay := t.TempDir()
	t.Run("rewrites to relative ts", func(t *testing.T) {
		tester(t, testCase{
			overlay: overlay,
			text: func(ts string) string {
				return "path: " + ts + "\n"
			},
			want: "path: ts/filters/a.ts",
			leak: overlay,
		})
	})
}

func TestCollectTSFiles(t *testing.T) {
	type testCase struct {
		overlays []string
		wantRel  string
		wantData string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := CollectTSFiles(tc.overlays)
		require.NoError(t, err)
		require.Contains(t, got, tc.wantRel)
		abs := got[tc.wantRel]
		//nolint:gosec // test fixture collected from TempDir
		data, err := os.ReadFile(abs)
		require.NoError(t, err)
		assert.Equal(t, tc.wantData, string(data))
	}

	first := t.TempDir()
	second := t.TempDir()
	err := os.MkdirAll(filepath.Join(first, TSDir, "filters"), 0o700)
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Join(second, TSDir, "filters"), 0o700)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(first, TSDir, "filters", "a.ts"), []byte("first"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(second, TSDir, "filters", "a.ts"), []byte("second"), 0o600)
	require.NoError(t, err)

	t.Run("later overlay wins", func(t *testing.T) {
		tester(t, testCase{
			overlays: []string{first, second},
			wantRel:  "filters/a.ts",
			wantData: "second",
		})
	})
}

func TestDirFS(t *testing.T) {
	tester := func(t *testing.T, dir string) {
		t.Helper()
		err := DirFS(dir).WriteFile("../escape.yaml", []byte("x"), 0o644)
		require.NoError(t, err)
		_, err = os.Stat(filepath.Join(filepath.Dir(dir), "escape.yaml"))
		require.ErrorIs(t, err, fs.ErrNotExist, "wrote outside layout root")
		assert.FileExists(t, filepath.Join(dir, "escape.yaml"))
	}

	t.Run("cleans parent refs", func(t *testing.T) {
		tester(t, t.TempDir())
	})
}

func TestPrefix(t *testing.T) {
	tester := func(t *testing.T, dir string) {
		t.Helper()
		err := WriteLayout(Prefix(DirFS(dir), "bouncer"), []byte("listen: 127.0.0.1:8228\n"), nil)
		require.NoError(t, err)
		assert.FileExists(t, filepath.Join(dir, "bouncer", FileName))
	}

	t.Run("writes under the prefix", func(t *testing.T) {
		tester(t, t.TempDir())
	})
}
