package urlfile

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type server struct {
	*httptest.Server
	body atomic.Value
	hits atomic.Int32
	fail atomic.Bool
}

func newServer(t *testing.T) *server {
	t.Helper()
	s := &server{}
	s.body.Store("one")
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		if s.fail.Load() {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(s.body.Load().(string)))
	}))
	t.Cleanup(s.Close)
	return s
}

func newCache(t *testing.T, s *server) *Cache {
	t.Helper()
	c := New(t.TempDir())
	c.Client = s.Client()
	return c
}

func age(t *testing.T, path string, d time.Duration) {
	t.Helper()
	old := time.Now().Add(-d)
	err := os.Chtimes(path, old, old)
	if err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // path under the test cache dir
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustFile(t *testing.T, c *Cache, rawURL string, name string, ttl ...string) string {
	t.Helper()
	path, err := c.File(rawURL, name, ttl...)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFile(t *testing.T) {
	t.Run("downloads once and serves the cached copy", func(t *testing.T) {
		s := newServer(t)
		c := newCache(t, s)
		u := s.URL + "/raw/chain.txt?ref=main"

		path := mustFile(t, c, u, "chain.pem")
		if filepath.Base(path) != "chain.pem" || !strings.HasPrefix(path, c.Dir) {
			t.Fatalf("path = %s", path)
		}
		if got := readFile(t, path); got != "one" {
			t.Fatalf("content = %q", got)
		}

		s.body.Store("two")
		if again := mustFile(t, c, u, "chain.pem"); again != path {
			t.Fatalf("path = %s, want %s", again, path)
		}
		if hits := s.hits.Load(); hits != 1 {
			t.Fatalf("hits = %d, want 1", hits)
		}
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("entries = %v, want only the cached file", entries)
		}
	})

	t.Run("refetches after the ttl", func(t *testing.T) {
		s := newServer(t)
		c := newCache(t, s)

		path := mustFile(t, c, s.URL, "a.pem", "1h")
		age(t, path, 2*time.Hour)
		s.body.Store("two")
		mustFile(t, c, s.URL, "a.pem", "1h")
		if got := readFile(t, path); got != "two" {
			t.Fatalf("content = %q", got)
		}
		if hits := s.hits.Load(); hits != 2 {
			t.Fatalf("hits = %d, want 2", hits)
		}
	})

	t.Run("uses the stale copy when a refetch fails", func(t *testing.T) {
		s := newServer(t)
		c := newCache(t, s)

		path := mustFile(t, c, s.URL, "a.pem", "1h")
		age(t, path, 2*time.Hour)
		s.fail.Store(true)
		if again := mustFile(t, c, s.URL, "a.pem", "1h"); again != path {
			t.Fatalf("path = %s, want %s", again, path)
		}
		if got := readFile(t, path); got != "one" {
			t.Fatalf("content = %q", got)
		}
	})

	t.Run("fails without a cached copy and leaves nothing behind", func(t *testing.T) {
		s := newServer(t)
		s.fail.Store(true)
		c := newCache(t, s)

		_, err := c.File(s.URL, "a.pem")
		if err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("err = %v", err)
		}
		entries, err := os.ReadDir(c.Dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("entries = %v", entries)
		}
	})

	t.Run("keeps urls apart under the same name", func(t *testing.T) {
		s := newServer(t)
		c := newCache(t, s)

		a := mustFile(t, c, s.URL+"/a", "same.pem")
		b := mustFile(t, c, s.URL+"/b", "same.pem")
		if a == b {
			t.Fatalf("both urls cached at %s", a)
		}
	})
}

func TestFileRejects(t *testing.T) {
	type testCase struct {
		noDir bool
		url   string
		name  string
		ttl   []string
		want  string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		dir := t.TempDir()
		if tc.noDir {
			dir = ""
		}
		_, err := New(dir).File(tc.url, tc.name, tc.ttl...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("err = %v, want %q", err, tc.want)
		}
	}

	ok := "https://example.com/a"
	t.Run("http", func(t *testing.T) {
		tester(t, testCase{url: "http://example.com/a", name: "a.pem", want: "https"})
	})
	t.Run("no host", func(t *testing.T) {
		tester(t, testCase{url: "https:///a", name: "a.pem", want: "https"})
	})
	t.Run("empty name", func(t *testing.T) {
		tester(t, testCase{url: ok, want: "plain file name"})
	})
	t.Run("dot dot", func(t *testing.T) {
		tester(t, testCase{url: ok, name: "..", want: "plain file name"})
	})
	t.Run("separator", func(t *testing.T) {
		tester(t, testCase{url: ok, name: "../a.pem", want: "plain file name"})
	})
	t.Run("backslash", func(t *testing.T) {
		tester(t, testCase{url: ok, name: `a\b.pem`, want: "plain file name"})
	})
	t.Run("bad ttl", func(t *testing.T) {
		tester(t, testCase{url: ok, name: "a.pem", ttl: []string{"soon"}, want: "ttl"})
	})
	t.Run("negative ttl", func(t *testing.T) {
		tester(t, testCase{url: ok, name: "a.pem", ttl: []string{"-1h"}, want: "negative"})
	})
	t.Run("extra args", func(t *testing.T) {
		tester(t, testCase{url: ok, name: "a.pem", ttl: []string{"1h", "2h"}, want: "optional ttl"})
	})
	t.Run("no cache dir", func(t *testing.T) {
		tester(t, testCase{noDir: true, url: ok, name: "a.pem", want: "no cache directory"})
	})
}
