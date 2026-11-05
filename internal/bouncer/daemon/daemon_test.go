package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfg, []byte("default_profile: p\nprofiles:\n  p: {}\n"), 0o644)
	d, err := New(Options{ConfigPath: cfg, StateDir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSessionTTL(t *testing.T) {
	d := newTestDaemon(t)
	short, err := d.CreateSession("", "short", 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	forever, _ := d.CreateSession("", "forever", 0)
	if len(short.ID) != 16 {
		t.Errorf("session ID %q should be 64 bits", short.ID)
	}
	if _, ok := d.Session(short.Token); !ok {
		t.Fatal("fresh session rejected")
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := d.Session(short.Token); ok {
		t.Fatal("expired session accepted")
	}
	if _, ok := d.Session(forever.Token); !ok {
		t.Fatal("session without ttl expired")
	}
	if n := len(d.listSessions()); n != 1 {
		t.Fatalf("expired session listed; got %d sessions", n)
	}
}

func TestControlPutEnv(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfg, []byte(`
default_profile: p
credentials:
  tok:
    source: env
    env: SMOKE_TOKEN
profiles:
  p: {}
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	d, err := New(Options{ConfigPath: cfg, StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SMOKE_TOKEN", "from-os")
	v, err := d.creds.Get(context.Background(), "tok")
	if err != nil || v != "from-os" {
		t.Fatalf("got %q, %v", v, err)
	}

	srv := httptest.NewServer(d.Control())
	t.Cleanup(srv.Close)
	token, err := os.ReadFile(AdminTokenPath(state))
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPut, srv.URL+"/_bouncer/credentials/sources/env", strings.NewReader(`{"SMOKE_TOKEN":"from-put"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	v, err = d.creds.Get(context.Background(), "tok")
	if err != nil || v != "from-put" {
		t.Fatalf("overlay got %q, %v", v, err)
	}
}

func TestControlPutProvided(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	secret := filepath.Join(dir, "secret")
	err := os.WriteFile(secret, []byte("from-file"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(cfg, []byte(`
default_profile: p
credentials:
  tok:
    source: file
    path: `+secret+`
  extra:
    source: provided
profiles:
  p: {}
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	d, err := New(Options{ConfigPath: cfg, StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	v, err := d.creds.Get(context.Background(), "tok")
	if err != nil || v != "from-file" {
		t.Fatalf("got %q, %v", v, err)
	}

	srv := httptest.NewServer(d.Control())
	t.Cleanup(srv.Close)
	token, err := os.ReadFile(AdminTokenPath(state))
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPut, srv.URL+"/_bouncer/credentials/provided", strings.NewReader(`{"tok":"from-put","extra":"provided-put"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	v, err = d.creds.Get(context.Background(), "tok")
	if err != nil || v != "from-put" {
		t.Fatalf("overlay got %q, %v", v, err)
	}
	v, err = d.creds.Get(context.Background(), "extra")
	if err != nil || v != "provided-put" {
		t.Fatalf("provided got %q, %v", v, err)
	}
}

func TestNewAllowsProvidedSourceWhenOptsNil(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfg, []byte(`
default_profile: p
credentials:
  tok:
    source: provided
profiles:
  p: {}
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Options{ConfigPath: cfg, StateDir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsMissingProvidedWhenOptsSet(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfg, []byte(`
default_profile: p
credentials:
  tok:
    source: provided
profiles:
  p: {}
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Options{
		ConfigPath: cfg,
		StateDir:   filepath.Join(dir, "state"),
		Provided:   map[string]string{},
	})
	if err == nil || !strings.Contains(err.Error(), "tok") {
		t.Fatalf("got %v", err)
	}
}
