package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfg, []byte("default_profile: p\nprofiles:\n  p: {}\n"), 0o600)
	require.NoError(t, err)
	d, err := New(Options{ConfigPath: cfg, StateDir: filepath.Join(dir, "state")})
	require.NoError(t, err)
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
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
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
		require.NoError(t, err)
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
		require.NoError(t, err)
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
		rec, err := tc.d.CreateSession(tc.id, "", tc.label, tc.ttl, nil)
		if tc.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		if tc.wantID != "" {
			assert.Equal(t, tc.wantID, rec.ID)
		}
	}

	t.Run("expires a short ttl and keeps a forever session", func(t *testing.T) {
		d := newTestDaemon(t)
		short, err := d.CreateSession("", "", "short", 30*time.Millisecond, nil)
		require.NoError(t, err)
		forever, err := d.CreateSession("", "", "forever", 0, nil)
		require.NoError(t, err)
		assert.Len(t, short.ID, 8, "session ID should be 32 bits")
		_, ok := d.Session(short.Token)
		require.True(t, ok, "fresh session rejected")
		time.Sleep(50 * time.Millisecond)
		_, ok = d.Session(short.Token)
		require.False(t, ok, "expired session accepted")
		_, ok = d.Session(forever.Token)
		require.True(t, ok, "session without ttl expired")
		assert.Len(t, d.listSessions(), 1, "expired session listed")
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
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(tc.token))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		require.Equal(t, tc.wantStatus, resp.StatusCode, string(body))
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
		require.NoError(t, err)
		state := filepath.Join(dir, "state")
		d, err := New(Options{ConfigPath: cfg, StateDir: state})
		require.NoError(t, err)
		t.Setenv("SMOKE_TOKEN", "from-os")
		v, err := d.creds.Get(context.Background(), "tok")
		require.NoError(t, err)
		assert.Equal(t, "from-os", v.Token)
		token, err := os.ReadFile(AdminTokenPath(state))
		require.NoError(t, err)
		tester(t, testCase{
			d:          d,
			token:      string(token),
			path:       "/_bouncer/credentials/sources/env",
			body:       `{"SMOKE_TOKEN":"from-put"}`,
			wantStatus: http.StatusNoContent,
		})
		v, err = d.creds.Get(context.Background(), "tok")
		require.NoError(t, err)
		assert.Equal(t, "from-put", v.Token)
	})
	t.Run("overlays provided credentials from put", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.yaml")
		secret := filepath.Join(dir, "secret")
		err := os.WriteFile(secret, []byte("from-file"), 0o600)
		require.NoError(t, err)
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
		require.NoError(t, err)
		state := filepath.Join(dir, "state")
		d, err := New(Options{ConfigPath: cfg, StateDir: state})
		require.NoError(t, err)
		v, err := d.creds.Get(context.Background(), "tok")
		require.NoError(t, err)
		assert.Equal(t, "from-file", v.Token)
		token, err := os.ReadFile(AdminTokenPath(state))
		require.NoError(t, err)
		tester(t, testCase{
			d:          d,
			token:      string(token),
			path:       "/_bouncer/credentials/provided",
			body:       `{"tok.token":"from-put","extra.token":"provided-put"}`,
			wantStatus: http.StatusNoContent,
		})
		v, err = d.creds.Get(context.Background(), "tok")
		require.NoError(t, err)
		assert.Equal(t, "from-put", v.Token)
		v, err = d.creds.Get(context.Background(), "extra")
		require.NoError(t, err)
		assert.Equal(t, "provided-put", v.Token)
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
		require.NoError(t, err)
		state := filepath.Join(dir, "state")
		d, err := New(Options{ConfigPath: cfg, StateDir: state})
		require.NoError(t, err)
		token, err := os.ReadFile(AdminTokenPath(state))
		require.NoError(t, err)
		srv := httptest.NewServer(d.Control())
		t.Cleanup(srv.Close)

		ticket := d.Prompts.Raise(prompt.Question{Kind: prompt.KindSecret, Source: "test", Message: "Master password"})
		id := ticket.ID()
		if tc.unknownID {
			id = "nope"
		}
		req, err := http.NewRequest(tc.method, srv.URL+"/_bouncer/prompts/"+id, strings.NewReader(tc.body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		require.Equal(t, tc.wantStatus, resp.StatusCode, string(body))
		if tc.wantStatus != http.StatusNoContent {
			assert.Len(t, d.Prompts.List(), 1, "rejected request settled the prompt")
			return
		}
		got, err := ticket.Wait(context.Background())
		require.ErrorIs(t, err, tc.wantErr)
		assert.Equal(t, tc.wantAnswer, got)
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

func TestStartupStatus(t *testing.T) {
	type status struct {
		Ready          bool   `json:"ready"`
		Error          string `json:"error"`
		PendingPrompts int    `json:"pending_prompts"`
	}
	type testCase struct {
		// prelogin is the Bitwarden prelogin handler. Nil means the config
		// has no Bitwarden credential.
		prelogin http.HandlerFunc
		// decline declines the first prompt after checking it is pending.
		decline   bool
		wantReady bool
		wantError string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		dir := t.TempDir()
		config := "default_profile: p\nprofiles:\n  p: {}\nprompts: {notify: false}\n"
		if tc.prelogin != nil {
			srv := httptest.NewServer(tc.prelogin)
			t.Cleanup(srv.Close)
			config += `credentials:
  bw:
    token:
      source: bitwarden
      email: user@example.com
      server: ` + srv.URL + `
      item: GitLab
      path: $.login.password
`
		}
		cfg := filepath.Join(dir, "config.yaml")
		err := os.WriteFile(cfg, []byte(config), 0o600)
		require.NoError(t, err)
		state := filepath.Join(dir, "state")
		d, err := New(Options{ConfigPath: cfg, StateDir: state})
		require.NoError(t, err)
		token, err := os.ReadFile(AdminTokenPath(state))
		require.NoError(t, err)
		srv := httptest.NewServer(d.Control())
		t.Cleanup(srv.Close)
		get := func() status {
			t.Helper()
			req, err := http.NewRequest(http.MethodGet, srv.URL+"/_bouncer/status", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			var st status
			err = json.NewDecoder(resp.Body).Decode(&st)
			require.NoError(t, err)
			return st
		}
		waitFor := func(what string, ok func(status) bool) status {
			t.Helper()
			deadline := time.Now().Add(5 * time.Second)
			for {
				st := get()
				if ok(st) {
					return st
				}
				if time.Now().After(deadline) {
					t.Fatalf("waiting for %s, status %+v", what, st)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}

		if tc.decline {
			st := waitFor("a pending prompt", func(st status) bool { return st.PendingPrompts == 1 })
			require.False(t, st.Ready, "ready before the prompt was answered")
			require.Empty(t, st.Error, "ready before the prompt was answered")
			err = d.Prompts.Decline(d.Prompts.List()[0].ID)
			require.NoError(t, err)
		}
		st := waitFor("startup to finish", func(st status) bool { return st.Ready || st.Error != "" })
		assert.Equal(t, tc.wantReady, st.Ready, "ready")
		if tc.wantError == "" {
			assert.Empty(t, st.Error)
		} else {
			assert.Contains(t, st.Error, tc.wantError)
		}
	}

	t.Run("ready without credentials to unlock", func(t *testing.T) {
		tester(t, testCase{wantReady: true})
	})
	t.Run("reports an unlock that fails", func(t *testing.T) {
		tester(t, testCase{
			prelogin: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "nope", http.StatusInternalServerError)
			},
			wantError: "prelogin",
		})
	})
	t.Run("waits on the master password prompt", func(t *testing.T) {
		tester(t, testCase{
			prelogin: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/identity/accounts/prelogin" {
					http.NotFound(w, r)
					return
				}
				_, _ = io.WriteString(w, `{"kdf":0,"kdfIterations":1000}`)
			},
			decline:   true,
			wantError: "declined",
		})
	})
}

func TestControlWithClient(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.yaml")
		err := os.WriteFile(cfg, []byte("default_profile: p\nprofiles:\n  p: {}\n"), 0o600)
		require.NoError(t, err)
		state := filepath.Join(dir, "state")
		d, err := New(Options{ConfigPath: cfg, StateDir: state})
		require.NoError(t, err)
		token, err := os.ReadFile(AdminTokenPath(state))
		require.NoError(t, err)
		srv := httptest.NewServer(d.Control())
		t.Cleanup(srv.Close)
		c := mgmt.New(srv.URL, strings.TrimSpace(string(token)))
		ctx := t.Context()

		created, err := c.CreateSession(ctx, "deadbeef", "", "test", "1h")
		require.NoError(t, err)
		assert.Equal(t, "deadbeef", created.ID)
		assert.Equal(t, "test", created.Label)
		assert.Equal(t, "p", created.Profile)
		assert.NotEmpty(t, created.Token)
		assert.False(t, created.Expires.IsZero())

		list, err := c.Sessions(ctx)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, created.ID, list[0].ID)
		assert.Empty(t, list[0].Token, "listing must not reveal session tokens")

		st, err := c.Status(ctx)
		require.NoError(t, err)
		assert.Equal(t, cfg, st.Config)
		assert.Equal(t, []string{"p"}, st.Profiles)
		assert.Equal(t, 1, st.Sessions)

		trust, err := c.Trust(ctx)
		require.NoError(t, err)
		assert.Contains(t, trust.CertPEM, "BEGIN CERTIFICATE")
		assert.Contains(t, trust.BundlePEM, trust.CertPEM)

		err = c.EndSession(ctx, "deadbeef")
		require.NoError(t, err)
		list, err = c.Sessions(ctx)
		require.NoError(t, err)
		assert.Empty(t, list)
	}

	t.Run("round-trips the public wire types", func(t *testing.T) {
		tester(t)
	})
}

func TestCredentialErrorsStayInTheLog(t *testing.T) {
	type testCase struct {
		err  error
		logs *lockedBuffer
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		require.Error(t, tc.err)
		assert.NotContains(t, tc.err.Error(), "s3cret-stderr")
		assert.Contains(t, tc.err.Error(), "is unavailable; see the bouncer log")
		assert.Contains(t, tc.logs.String(), "s3cret-stderr")
	}
	newDaemon := func(t *testing.T) (*Daemon, *lockedBuffer) {
		t.Helper()
		if runtime.GOOS == "windows" {
			t.Skip("uses sh")
		}
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.yaml")
		err := os.WriteFile(cfg, []byte(`default_profile: p
prompts: {notify: false}
credentials:
  gl:
    token:
      source: command
      command: [sh, -c, "echo s3cret-stderr >&2; exit 1"]
profiles:
  p:
    http:
      - name: gitlab
        hosts: [gitlab.example.com]
        credential: gl
`), 0o600)
		require.NoError(t, err)
		logs := &lockedBuffer{}
		d, err := New(Options{ConfigPath: cfg, StateDir: filepath.Join(dir, "state"), Log: zerolog.New(logs)})
		require.NoError(t, err)
		return d, logs
	}

	t.Run("gitlab project lookup", func(t *testing.T) {
		d, logs := newDaemon(t)
		_, err := d.resolveGitLabProject(t.Context(), "gitlab", "gitlab.example.com", "group/project")
		tester(t, testCase{err: err, logs: logs})
	})
	t.Run("filter credential", func(t *testing.T) {
		d, logs := newDaemon(t)
		_, err := d.env.Credential(t.Context(), "gl")
		tester(t, testCase{err: err, logs: logs})
	})
}

func TestClientClearsCredentials(t *testing.T) {
	type testCase struct {
		cred string
		put  func(c *mgmt.Client, ctx context.Context, values map[string]string) error
		set  map[string]string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.yaml")
		err := os.WriteFile(cfg, []byte(`default_profile: p
prompts: {notify: false}
credentials:
  from-env:
    token:
      source: env
      env: AGENTCON_TEST_CLEAR_ENV
  from-provided:
    token:
      source: provided
profiles:
  p: {}
`), 0o600)
		require.NoError(t, err)
		state := filepath.Join(dir, "state")
		d, err := New(Options{ConfigPath: cfg, StateDir: state})
		require.NoError(t, err)
		token, err := os.ReadFile(AdminTokenPath(state))
		require.NoError(t, err)
		srv := httptest.NewServer(d.Control())
		t.Cleanup(srv.Close)
		c := mgmt.New(srv.URL, strings.TrimSpace(string(token)))
		ctx := t.Context()

		err = tc.put(c, ctx, tc.set)
		require.NoError(t, err)
		sec, err := d.creds.Get(ctx, tc.cred)
		require.NoError(t, err)
		assert.Equal(t, "s3cret", sec.Token)

		err = tc.put(c, ctx, map[string]string{})
		require.NoError(t, err)
		_, err = d.creds.Get(ctx, tc.cred)
		require.Error(t, err, "the cleared value must not still resolve")
	}

	t.Run("env overlay", func(t *testing.T) {
		tester(t, testCase{cred: "from-env", put: (*mgmt.Client).PutEnv, set: map[string]string{"AGENTCON_TEST_CLEAR_ENV": "s3cret"}})
	})
	t.Run("provided values", func(t *testing.T) {
		tester(t, testCase{cred: "from-provided", put: (*mgmt.Client).PutProvided, set: map[string]string{"from-provided.token": "s3cret"}})
	})
}
