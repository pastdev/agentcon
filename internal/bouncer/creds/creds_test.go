package creds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

func tokenCred(name string, src config.ValueSource) *config.Credential {
	s := src
	return &config.Credential{Name: name, Token: &s}
}

func TestGet(t *testing.T) {
	type testCase struct {
		store     *Store
		name      string
		wantToken string
		wantUser  string
		wantPass  string
		wantHTTP  string
		override  string
		wantOver  string
		wantErr   string
		skipWin   string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		if tc.skipWin != "" && runtime.GOOS == "windows" {
			t.Skip(tc.skipWin)
		}
		v, err := tc.store.Get(context.Background(), tc.name)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantToken != "" && v.Token != tc.wantToken {
			t.Fatalf("got %+v, %v", v, err)
		}
		if tc.wantUser != "" && (v.Username != tc.wantUser || v.Password != tc.wantPass) {
			t.Fatalf("got %+v", v)
		}
		if tc.wantHTTP != "" && (v.HTTP() != tc.wantHTTP || v.BasicUser("") != tc.wantUser || v.BasicPass() != tc.wantPass) {
			t.Fatalf("helpers %+v", v)
		}
		if tc.override != "" && v.BasicUser(tc.override) != tc.wantOver {
			t.Fatalf("override %q", v.BasicUser(tc.override))
		}
	}

	t.Run("caches a command source until update", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("uses sh")
		}
		counter := t.TempDir() + "/n"
		c := tokenCred("x", config.ValueSource{Source: "command",
			Command: []string{"sh", "-c", "echo run >> " + counter + "; printf 'tok\\n'"}})
		s := NewStore(map[string]*config.Credential{"x": c})
		for i := 0; i < 3; i++ {
			tester(t, testCase{store: s, name: "x", wantToken: "tok"})
		}
		c2 := tokenCred("x", config.ValueSource{Source: "command", Command: []string{"sh", "-c", "printf other"}})
		s.Update(map[string]*config.Credential{"x": c2})
		tester(t, testCase{store: s, name: "x", wantToken: "other"})
	})
	t.Run("includes stderr from a failed command", func(t *testing.T) {
		s := NewStore(map[string]*config.Credential{"x": tokenCred("x", config.ValueSource{Source: "command",
			Command: []string{"sh", "-c", "echo vault locked >&2; exit 1"}})})
		tester(t, testCase{store: s, name: "x", skipWin: "uses sh", wantErr: "vault locked"})
	})
	t.Run("reads an env source", func(t *testing.T) {
		t.Setenv("BOUNCER_TEST_SECRET", "s3cret")
		s := NewStore(map[string]*config.Credential{"e": tokenCred("e", config.ValueSource{Source: "env", Env: "BOUNCER_TEST_SECRET"})})
		tester(t, testCase{store: s, name: "e", wantToken: "s3cret"})
	})
	t.Run("lets an env overlay win over the os", func(t *testing.T) {
		t.Setenv("BOUNCER_TEST_SECRET", "from-os")
		s := NewStore(map[string]*config.Credential{"e": tokenCred("e", config.ValueSource{Source: "env", Env: "BOUNCER_TEST_SECRET"})})
		tester(t, testCase{store: s, name: "e", wantToken: "from-os"})
		s.SetEnv(map[string]string{"BOUNCER_TEST_SECRET": "from-put"})
		tester(t, testCase{store: s, name: "e", wantToken: "from-put"})
	})
	t.Run("reads an env overlay without an os value", func(t *testing.T) {
		s := NewStore(map[string]*config.Credential{"e": tokenCred("e", config.ValueSource{Source: "env", Env: "BOUNCER_TEST_UNSET"})})
		_, err := s.Get(context.Background(), "e")
		if err == nil {
			t.Fatal("expected missing env")
		}
		s.SetEnv(map[string]string{"BOUNCER_TEST_UNSET": "from-put"})
		tester(t, testCase{store: s, name: "e", wantToken: "from-put"})
	})
	t.Run("clears the cache when provided values are set", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/secret"
		err := os.WriteFile(path, []byte("from-file"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		s := NewStore(map[string]*config.Credential{"tok": tokenCred("tok", config.ValueSource{Source: "file", File: path})})
		tester(t, testCase{store: s, name: "tok", wantToken: "from-file"})
		s.SetProvided(map[string]string{config.ProvidedKey("tok", config.SlotToken): "from-put"})
		tester(t, testCase{store: s, name: "tok", wantToken: "from-put"})
	})
	t.Run("wraps bitwarden source errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)
		ConfigureBitwarden(t.TempDir(), nil)
		s := NewStore(map[string]*config.Credential{"bw": tokenCred("bw", config.ValueSource{
			Source: "bitwarden", Email: "user@example.com", Server: srv.URL, Item: "GitLab", Path: "$.login.password",
		})})
		v, err := s.Get(context.Background(), "bw")
		if err == nil || !strings.Contains(err.Error(), `credential "bw"`) || !strings.Contains(err.Error(), "prelogin") {
			t.Fatalf("err = %v", err)
		}
		_ = v
	})
	t.Run("fills composite username and password slots", func(t *testing.T) {
		c := &config.Credential{
			Name:     "login",
			Username: &config.ValueSource{Source: "provided"},
			Password: &config.ValueSource{Source: "provided"},
		}
		s := NewStore(map[string]*config.Credential{"login": c})
		s.SetProvided(map[string]string{
			config.ProvidedKey("login", config.SlotUsername): "alice",
			config.ProvidedKey("login", config.SlotPassword): "s3cret",
		})
		tester(t, testCase{
			store:    s,
			name:     "login",
			wantUser: "alice",
			wantPass: "s3cret",
			wantHTTP: "s3cret",
			override: "oauth2",
			wantOver: "oauth2",
		})
	})
}

func TestExtractJSONPath(t *testing.T) {
	type testCase struct {
		payload []byte
		path    string
		want    string
		wantErr bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := extractJSONPath(tc.payload, tc.path)
		if tc.wantErr {
			if err == nil {
				t.Fatal("expected error")
			}
			return
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q %v, want %q", tc.path, got, err, tc.want)
		}
	}

	payload := []byte(`{"notes":"pat","login":{"username":"alice","password":"s3cret"},"fields":[{"name":"API Key","value":"k"}]}`)
	t.Run("returns the full payload for an empty path", func(t *testing.T) {
		tester(t, testCase{payload: payload, path: "", want: string(payload)})
	})
	t.Run("extracts notes", func(t *testing.T) {
		tester(t, testCase{payload: payload, path: "$.notes", want: "pat"})
	})
	t.Run("extracts login.password", func(t *testing.T) {
		tester(t, testCase{payload: payload, path: "$.login.password", want: "s3cret"})
	})
	t.Run("extracts login.username", func(t *testing.T) {
		tester(t, testCase{payload: payload, path: "$.login.username", want: "alice"})
	})
	t.Run("extracts a filtered field value", func(t *testing.T) {
		tester(t, testCase{payload: payload, path: "$.fields[?(@.name=='API Key')].value", want: "k"})
	})
	t.Run("rejects a missing path", func(t *testing.T) {
		tester(t, testCase{payload: payload, path: "$.missing", wantErr: true})
	})
	t.Run("rejects a non-json payload", func(t *testing.T) {
		tester(t, testCase{payload: []byte("not-json"), path: "$.notes", wantErr: true})
	})
}

func TestHTTP(t *testing.T) {
	type testCase struct {
		s    Secret
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		if tc.s.HTTP() != tc.want {
			t.Fatalf("HTTP %q", tc.s.HTTP())
		}
	}

	t.Run("prefers token over password", func(t *testing.T) {
		tester(t, testCase{s: Secret{Password: "p", Token: "t"}, want: "t"})
	})
}

func TestBasicPass(t *testing.T) {
	type testCase struct {
		s    Secret
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		if tc.s.BasicPass() != tc.want {
			t.Fatalf("BasicPass %q", tc.s.BasicPass())
		}
	}

	t.Run("uses the password slot", func(t *testing.T) {
		tester(t, testCase{s: Secret{Password: "p", Token: "t"}, want: "p"})
	})
}
