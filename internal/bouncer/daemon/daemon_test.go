package daemon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/prompt"
)

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfg, []byte("default_profile: p\nprofiles:\n  p: {}\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Options{ConfigPath: cfg, StateDir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNew(t *testing.T) {
	type testCase struct {
		opts    Options
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		_, err := New(tc.opts)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Run("allows a provided source when provided opts are nil", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.yaml")
		err := os.WriteFile(cfg, []byte(`
default_profile: p
credentials:
  tok:
    token:
      source: provided
profiles:
  p: {}
`), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{opts: Options{ConfigPath: cfg, StateDir: filepath.Join(dir, "state")}})
	})
	t.Run("rejects a missing provided value when provided opts are set", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.yaml")
		err := os.WriteFile(cfg, []byte(`
default_profile: p
credentials:
  tok:
    token:
      source: provided
profiles:
  p: {}
`), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			opts: Options{
				ConfigPath: cfg,
				StateDir:   filepath.Join(dir, "state"),
				Provided:   map[string]string{},
			},
			wantErr: "tok",
		})
	})
}

func TestCreateSession(t *testing.T) {
	type testCase struct {
		d       *Daemon
		id      string
		label   string
		ttl     time.Duration
		wantID  string
		wantErr bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		rec, err := tc.d.CreateSession(tc.id, "", tc.label, tc.ttl)
		if tc.wantErr {
			if err == nil {
				t.Fatal("expected error")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantID != "" && rec.ID != tc.wantID {
			t.Fatalf("id %q", rec.ID)
		}
	}

	t.Run("expires a short ttl and keeps a forever session", func(t *testing.T) {
		d := newTestDaemon(t)
		short, err := d.CreateSession("", "", "short", 30*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		forever, err := d.CreateSession("", "", "forever", 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(short.ID) != 8 {
			t.Errorf("session ID %q should be 32 bits", short.ID)
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
	})
	t.Run("uses a supplied session id", func(t *testing.T) {
		tester(t, testCase{d: newTestDaemon(t), id: "deadbeef", label: "agentcon", wantID: "deadbeef"})
	})
	t.Run("rejects a duplicate session id", func(t *testing.T) {
		d := newTestDaemon(t)
		tester(t, testCase{d: d, id: "deadbeef", label: "agentcon", wantID: "deadbeef"})
		tester(t, testCase{d: d, id: "DEADBEEF", label: "dup", wantErr: true})
	})
	t.Run("rejects a short session id", func(t *testing.T) {
		tester(t, testCase{d: newTestDaemon(t), id: "abcd", label: "short", wantErr: true})
	})
}

func TestControl(t *testing.T) {
	type testCase struct {
		d          *Daemon
		token      string
		path       string
		body       string
		wantStatus int
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		srv := httptest.NewServer(tc.d.Control())
		t.Cleanup(srv.Close)
		req, err := http.NewRequest(http.MethodPut, srv.URL+tc.path, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(tc.token))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != tc.wantStatus {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status %d %s", resp.StatusCode, body)
		}
	}

	t.Run("overlays env credentials from put", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.yaml")
		err := os.WriteFile(cfg, []byte(`
default_profile: p
credentials:
  tok:
    token:
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
		if err != nil || v.Token != "from-os" {
			t.Fatalf("got %+v, %v", v, err)
		}
		token, err := os.ReadFile(AdminTokenPath(state))
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			d:          d,
			token:      string(token),
			path:       "/_bouncer/credentials/sources/env",
			body:       `{"SMOKE_TOKEN":"from-put"}`,
			wantStatus: http.StatusNoContent,
		})
		v, err = d.creds.Get(context.Background(), "tok")
		if err != nil || v.Token != "from-put" {
			t.Fatalf("overlay got %+v, %v", v, err)
		}
	})
	t.Run("overlays provided credentials from put", func(t *testing.T) {
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
    token:
      source: file
      file: `+secret+`
  extra:
    token:
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
		if err != nil || v.Token != "from-file" {
			t.Fatalf("got %+v, %v", v, err)
		}
		token, err := os.ReadFile(AdminTokenPath(state))
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			d:          d,
			token:      string(token),
			path:       "/_bouncer/credentials/provided",
			body:       `{"tok.token":"from-put","extra.token":"provided-put"}`,
			wantStatus: http.StatusNoContent,
		})
		v, err = d.creds.Get(context.Background(), "tok")
		if err != nil || v.Token != "from-put" {
			t.Fatalf("overlay got %+v, %v", v, err)
		}
		v, err = d.creds.Get(context.Background(), "extra")
		if err != nil || v.Token != "provided-put" {
			t.Fatalf("provided got %+v, %v", v, err)
		}
	})
}

func TestPromptsAPI(t *testing.T) {
	type testCase struct {
		config     string
		method     string
		body       string
		unknownID  bool
		wantStatus int
		wantErr    error
		wantAnswer prompt.Answer
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.yaml")
		err := os.WriteFile(cfg, []byte("default_profile: p\nprofiles:\n  p: {}\n"+tc.config), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(dir, "state")
		d, err := New(Options{ConfigPath: cfg, StateDir: state})
		if err != nil {
			t.Fatal(err)
		}
		token, err := os.ReadFile(AdminTokenPath(state))
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(d.Control())
		t.Cleanup(srv.Close)

		ticket := d.Prompts.Raise(prompt.Question{Kind: prompt.KindSecret, Source: "test", Message: "Master password"})
		id := ticket.ID()
		if tc.unknownID {
			id = "nope"
		}
		req, err := http.NewRequest(tc.method, srv.URL+"/_bouncer/prompts/"+id, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != tc.wantStatus {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status %d %s", resp.StatusCode, body)
		}
		if tc.wantStatus != http.StatusNoContent {
			if len(d.Prompts.List()) != 1 {
				t.Fatal("rejected request settled the prompt")
			}
			return
		}
		got, err := ticket.Wait(context.Background())
		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("err=%v, want %v", err, tc.wantErr)
		}
		if got != tc.wantAnswer {
			t.Fatalf("got %+v", got)
		}
	}

	t.Run("answers a secret", func(t *testing.T) {
		tester(t, testCase{method: http.MethodPost, body: `{"value":"hunter2"}`, wantStatus: http.StatusNoContent,
			wantAnswer: prompt.Answer{Value: "hunter2"}})
	})
	t.Run("declines", func(t *testing.T) {
		tester(t, testCase{method: http.MethodDelete, wantStatus: http.StatusNoContent, wantErr: prompt.ErrDeclined})
	})
	t.Run("rejects an answer that does not fit", func(t *testing.T) {
		tester(t, testCase{method: http.MethodPost, body: `{"allow":true}`, wantStatus: http.StatusBadRequest})
	})
	t.Run("rejects a malformed body", func(t *testing.T) {
		tester(t, testCase{method: http.MethodPost, body: `{`, wantStatus: http.StatusBadRequest})
	})
	t.Run("unknown id", func(t *testing.T) {
		tester(t, testCase{method: http.MethodPost, body: `{"value":"x"}`, unknownID: true, wantStatus: http.StatusNotFound})
	})
	t.Run("answering disabled", func(t *testing.T) {
		tester(t, testCase{config: "prompts: {cli: false}\n", method: http.MethodPost, body: `{"value":"x"}`, wantStatus: http.StatusForbidden})
	})
	t.Run("declining disabled", func(t *testing.T) {
		tester(t, testCase{config: "prompts: {cli: false}\n", method: http.MethodDelete, wantStatus: http.StatusForbidden})
	})
}
