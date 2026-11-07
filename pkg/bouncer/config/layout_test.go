package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := LoadDir(dir)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if got.Listen != tc.wantListen {
			t.Fatalf("listen %q, want %q", got.Listen, tc.wantListen)
		}
		if tc.wantTS == "" {
			return
		}
		//nolint:gosec // test fixture under TempDir
		data, err := os.ReadFile(filepath.Join(dir, TSDir, tc.wantTS))
		if err != nil {
			t.Fatalf("read ts: %v", err)
		}
		if string(data) != "export {}\n" {
			t.Fatalf("ts %q", data)
		}
	}

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "deny.ts")
	err := os.WriteFile(src, []byte("export {}\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

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
		if bytes.Contains(got, []byte(tc.leak)) {
			t.Fatalf("host path leaked: %s", got)
		}
		if !strings.Contains(string(got), tc.want) {
			t.Fatalf("got %s, want %q", got, tc.want)
		}
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
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		abs, ok := got[tc.wantRel]
		if !ok {
			t.Fatalf("missing %s, have %v", tc.wantRel, got)
		}
		//nolint:gosec // test fixture collected from TempDir
		data, err := os.ReadFile(abs)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != tc.wantData {
			t.Fatalf("data %q, want %q", data, tc.wantData)
		}
	}

	first := t.TempDir()
	second := t.TempDir()
	err := os.MkdirAll(filepath.Join(first, TSDir, "filters"), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	err = os.MkdirAll(filepath.Join(second, TSDir, "filters"), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(first, TSDir, "filters", "a.ts"), []byte("first"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(second, TSDir, "filters", "a.ts"), []byte("second"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

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
		if err != nil {
			t.Fatal(err)
		}
		_, err = os.Stat(filepath.Join(filepath.Dir(dir), "escape.yaml"))
		if err == nil {
			t.Fatal("wrote outside layout root")
		}
		_, err = os.Stat(filepath.Join(dir, "escape.yaml"))
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Run("cleans parent refs", func(t *testing.T) {
		tester(t, t.TempDir())
	})
}

func TestPrefix(t *testing.T) {
	tester := func(t *testing.T, dir string) {
		t.Helper()
		err := WriteLayout(Prefix(DirFS(dir), "bouncer"), []byte("listen: 127.0.0.1:8228\n"), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = os.Stat(filepath.Join(dir, "bouncer", FileName))
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Run("writes under the prefix", func(t *testing.T) {
		tester(t, t.TempDir())
	})
}
