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

func TestCommandSourceAndCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	counter := t.TempDir() + "/n"
	c := tokenCred("x", config.ValueSource{Source: "command",
		Command: []string{"sh", "-c", "echo run >> " + counter + "; printf 'tok\\n'"}})
	s := NewStore(map[string]*config.Credential{"x": c})
	for i := 0; i < 3; i++ {
		v, err := s.Get(context.Background(), "x")
		if err != nil || v.Token != "tok" {
			t.Fatalf("got %+v, %v", v, err)
		}
	}
	c2 := tokenCred("x", config.ValueSource{Source: "command", Command: []string{"sh", "-c", "printf other"}})
	s.Update(map[string]*config.Credential{"x": c2})
	if v, _ := s.Get(context.Background(), "x"); v.Token != "other" {
		t.Fatalf("cache not invalidated: %+v", v)
	}
}

func TestCommandFailureIncludesStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	s := NewStore(map[string]*config.Credential{"x": tokenCred("x", config.ValueSource{Source: "command",
		Command: []string{"sh", "-c", "echo vault locked >&2; exit 1"}})})
	_, err := s.Get(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "vault locked") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnvSource(t *testing.T) {
	t.Setenv("BOUNCER_TEST_SECRET", "s3cret")
	s := NewStore(map[string]*config.Credential{"e": tokenCred("e", config.ValueSource{Source: "env", Env: "BOUNCER_TEST_SECRET"})})
	if v, err := s.Get(context.Background(), "e"); err != nil || v.Token != "s3cret" {
		t.Fatalf("got %+v, %v", v, err)
	}
}

func TestEnvOverlayWinsOverOS(t *testing.T) {
	t.Setenv("BOUNCER_TEST_SECRET", "from-os")
	s := NewStore(map[string]*config.Credential{"e": tokenCred("e", config.ValueSource{Source: "env", Env: "BOUNCER_TEST_SECRET"})})
	v, err := s.Get(context.Background(), "e")
	if err != nil || v.Token != "from-os" {
		t.Fatalf("got %+v, %v", v, err)
	}
	s.SetEnv(map[string]string{"BOUNCER_TEST_SECRET": "from-put"})
	v, err = s.Get(context.Background(), "e")
	if err != nil || v.Token != "from-put" {
		t.Fatalf("overlay got %+v, %v", v, err)
	}
}

func TestEnvOverlayWithoutOS(t *testing.T) {
	s := NewStore(map[string]*config.Credential{"e": tokenCred("e", config.ValueSource{Source: "env", Env: "BOUNCER_TEST_UNSET"})})
	_, err := s.Get(context.Background(), "e")
	if err == nil {
		t.Fatal("expected missing env")
	}
	s.SetEnv(map[string]string{"BOUNCER_TEST_UNSET": "from-put"})
	v, err := s.Get(context.Background(), "e")
	if err != nil || v.Token != "from-put" {
		t.Fatalf("got %+v, %v", v, err)
	}
}

func TestSetProvidedClearsCache(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/secret"
	err := os.WriteFile(path, []byte("from-file"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore(map[string]*config.Credential{"tok": tokenCred("tok", config.ValueSource{Source: "file", File: path})})
	v, err := s.Get(context.Background(), "tok")
	if err != nil || v.Token != "from-file" {
		t.Fatalf("got %+v, %v", v, err)
	}
	s.SetProvided(map[string]string{config.ProvidedKey("tok", config.SlotToken): "from-put"})
	v, err = s.Get(context.Background(), "tok")
	if err != nil || v.Token != "from-put" {
		t.Fatalf("overlay got %+v, %v", v, err)
	}
}

func TestBitwardenSourceWrapsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	ConfigureBitwarden(t.TempDir(), nil)
	s := NewStore(map[string]*config.Credential{"bw": tokenCred("bw", config.ValueSource{
		Source: "bitwarden", Email: "user@example.com", Server: srv.URL, Item: "GitLab", Path: "$.login.password",
	})})
	_, err := s.Get(context.Background(), "bw")
	if err == nil || !strings.Contains(err.Error(), `credential "bw"`) || !strings.Contains(err.Error(), "prelogin") {
		t.Fatalf("err = %v", err)
	}
}

func TestExtractJSONPath(t *testing.T) {
	payload := []byte(`{"notes":"pat","login":{"username":"alice","password":"s3cret"},"fields":[{"name":"API Key","value":"k"}]}`)
	cases := []struct {
		path, want string
	}{
		{"", string(payload)},
		{"$.notes", "pat"},
		{"$.login.password", "s3cret"},
		{"$.login.username", "alice"},
		{"$.fields[?(@.name=='API Key')].value", "k"},
	}
	for _, tc := range cases {
		got, err := extractJSONPath(payload, tc.path)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q %v, want %q", tc.path, got, err, tc.want)
		}
	}
	if _, err := extractJSONPath(payload, "$.missing"); err == nil {
		t.Fatal("expected no match")
	}
	if _, err := extractJSONPath([]byte("not-json"), "$.notes"); err == nil {
		t.Fatal("expected non-JSON payload to fail")
	}
}

func TestGetCompositeSlots(t *testing.T) {
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
	v, err := s.Get(context.Background(), "login")
	if err != nil {
		t.Fatal(err)
	}
	if v.Username != "alice" || v.Password != "s3cret" {
		t.Fatalf("got %+v", v)
	}
	if v.HTTP() != "s3cret" || v.BasicUser("") != "alice" || v.BasicPass() != "s3cret" {
		t.Fatalf("helpers %+v", v)
	}
	if v.BasicUser("oauth2") != "oauth2" {
		t.Fatalf("override %q", v.BasicUser("oauth2"))
	}
}

func TestSecretHTTPPrefersToken(t *testing.T) {
	s := Secret{Password: "p", Token: "t"}
	if s.HTTP() != "t" {
		t.Fatalf("HTTP %q", s.HTTP())
	}
	if s.BasicPass() != "p" {
		t.Fatalf("BasicPass %q", s.BasicPass())
	}
}
