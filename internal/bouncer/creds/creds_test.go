package creds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/bouncer/crederr"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
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
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, Secret{Token: tc.wantToken, Username: tc.wantUser, Password: tc.wantPass}, v)
		if tc.wantHTTP != "" {
			assert.Equal(t, tc.wantHTTP, v.HTTP())
			assert.Equal(t, tc.wantUser, v.BasicUser(""))
			assert.Equal(t, tc.wantPass, v.BasicPass())
		}
		if tc.override != "" {
			assert.Equal(t, tc.wantOver, v.BasicUser(tc.override))
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
		require.Error(t, err)
		s.SetEnv(map[string]string{"BOUNCER_TEST_UNSET": "from-put"})
		tester(t, testCase{store: s, name: "e", wantToken: "from-put"})
	})
	t.Run("clears the cache when provided values are set", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/secret"
		err := os.WriteFile(path, []byte("from-file"), 0o600)
		require.NoError(t, err)
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
		ConfigureBitwarden(t.TempDir(), zerolog.Nop(), prompt.NewBroker(time.Minute))
		s := NewStore(map[string]*config.Credential{"bw": tokenCred("bw", config.ValueSource{
			Source: "bitwarden", Account: "work", Item: "GitLab", Path: "$.login.password",
			Bitwarden: &config.BitwardenAccount{Name: "work", Email: "user@example.com", Server: srv.URL},
		})})
		_, err := s.Get(context.Background(), "bw")
		require.ErrorContains(t, err, `credential "bw"`)
		require.ErrorContains(t, err, "prelogin")
	})
	t.Run("unlocks bitwarden with a password from the env overlay", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/identity/accounts/prelogin" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"kdf":0,"kdfIterations":1000}`))
		}))
		t.Cleanup(srv.Close)
		ConfigureBitwarden(t.TempDir(), zerolog.Nop(), prompt.NewBroker(time.Minute))
		s := NewStore(map[string]*config.Credential{"bw": tokenCred("bw", config.ValueSource{
			Source: "bitwarden", Account: "work", Item: "GitLab", Path: "$.login.password",
			Bitwarden: &config.BitwardenAccount{Name: "work", Email: "user@example.com", Server: srv.URL,
				Password: &config.ValueSource{Source: "env", Env: "BOUNCER_TEST_BW_MASTER"}},
		})})
		_, err := s.Get(context.Background(), "bw")
		require.ErrorContains(t, err, "bitwarden account work password: environment variable BOUNCER_TEST_BW_MASTER is not set")
		s.SetEnv(map[string]string{"BOUNCER_TEST_BW_MASTER": "fake-test-password"})
		_, err = s.Get(context.Background(), "bw")
		require.Error(t, err, "the fake vault has no login endpoint")
		assert.NotContains(t, err.Error(), "is not set")
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

func TestAccountPassword(t *testing.T) {
	type testCase struct {
		password *config.ValueSource
		provided map[string]string
		env      map[string]string
		setenv   map[string]string
		skipWin  string
		want     string
		wantErr  string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		if tc.skipWin != "" && runtime.GOOS == "windows" {
			t.Skip(tc.skipWin)
		}
		for k, v := range tc.setenv {
			t.Setenv(k, v)
		}
		s := NewStore(map[string]*config.Credential{})
		s.SetProvided(tc.provided)
		s.SetEnv(tc.env)
		got, err := s.AccountPassword(context.Background(), &config.BitwardenAccount{Name: "work", Email: "user@example.com", Password: tc.password})
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("prefers a provided value", func(t *testing.T) {
		tester(t, testCase{
			password: &config.ValueSource{Source: "env", Env: "BOUNCER_TEST_BW_MASTER"},
			provided: map[string]string{"bitwarden.work": "from-provided"},
			env:      map[string]string{"BOUNCER_TEST_BW_MASTER": "from-overlay"},
			want:     "from-provided",
		})
	})
	t.Run("reads env from the overlay before the process", func(t *testing.T) {
		tester(t, testCase{
			password: &config.ValueSource{Source: "env", Env: "BOUNCER_TEST_BW_MASTER"},
			env:      map[string]string{"BOUNCER_TEST_BW_MASTER": "from-overlay"},
			setenv:   map[string]string{"BOUNCER_TEST_BW_MASTER": "from-os"},
			want:     "from-overlay",
		})
	})
	t.Run("falls back to the process env", func(t *testing.T) {
		tester(t, testCase{
			password: &config.ValueSource{Source: "env", Env: "BOUNCER_TEST_BW_MASTER"},
			setenv:   map[string]string{"BOUNCER_TEST_BW_MASTER": "from-os"},
			want:     "from-os",
		})
	})
	t.Run("runs a command", func(t *testing.T) {
		tester(t, testCase{
			password: &config.ValueSource{Source: "command", Command: []string{"sh", "-c", "printf 'from-command\\n'"}},
			skipWin:  "uses sh",
			want:     "from-command",
		})
	})
	t.Run("names the account when the source fails", func(t *testing.T) {
		tester(t, testCase{
			password: &config.ValueSource{Source: "provided"},
			wantErr:  "bitwarden account work password: no value provided",
		})
	})
	t.Run("rejects an empty value", func(t *testing.T) {
		tester(t, testCase{
			password: &config.ValueSource{Source: "env", Env: "BOUNCER_TEST_BW_MASTER"},
			setenv:   map[string]string{"BOUNCER_TEST_BW_MASTER": ""},
			wantErr:  "bitwarden account work password: empty secret",
		})
	})
	t.Run("needs a password", func(t *testing.T) {
		tester(t, testCase{wantErr: "bitwarden account work has no password"})
	})
}

func TestMissingProvided(t *testing.T) {
	work := &config.BitwardenAccount{Name: "work", Email: "user@example.com", Password: &config.ValueSource{Source: "provided"}}
	s := NewStore(map[string]*config.Credential{
		"bw":  tokenCred("bw", config.ValueSource{Source: "bitwarden", Account: "work", Bitwarden: work}),
		"tok": tokenCred("tok", config.ValueSource{Source: "provided"}),
	})
	assert.Equal(t, []string{"bitwarden.work", "tok.token"}, s.MissingProvided())
	s.SetProvided(map[string]string{"bitwarden.work": "x"})
	assert.Equal(t, []string{"tok.token"}, s.MissingProvided())
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
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
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
		assert.Equal(t, tc.want, tc.s.HTTP())
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
		assert.Equal(t, tc.want, tc.s.BasicPass())
	}

	t.Run("uses the password slot", func(t *testing.T) {
		tester(t, testCase{s: Secret{Password: "p", Token: "t"}, want: "p"})
	})
}

func TestCommandError(t *testing.T) {
	type testCase struct {
		script     string
		wantStderr string
		wantLen    int
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		if runtime.GOOS == "windows" {
			t.Skip("uses sh")
		}
		s := NewStore(map[string]*config.Credential{"x": tokenCred("x", config.ValueSource{Source: "command",
			Command: []string{"sh", "-c", tc.script}})})
		_, err := s.Get(context.Background(), "x")
		var ce *crederr.CommandError
		require.ErrorAs(t, err, &ce)
		assert.Equal(t, "sh", ce.Name)
		assert.Contains(t, err.Error(), "sh: exit status 1")
		assert.NotContains(t, err.Error(), "-c", "arguments stay out of the error text")
		if tc.wantStderr != "" {
			assert.Equal(t, tc.wantStderr, crederr.Stderr(err))
			assert.NotContains(t, err.Error(), tc.wantStderr)
		}
		if tc.wantLen != 0 {
			assert.Len(t, crederr.Stderr(err), tc.wantLen)
		}
	}

	t.Run("keeps stderr out of the error text", func(t *testing.T) {
		tester(t, testCase{script: "echo vault locked >&2; exit 1", wantStderr: "vault locked"})
	})
	t.Run("caps stderr", func(t *testing.T) {
		tester(t, testCase{script: "head -c 10000 /dev/zero | tr '\\0' x >&2; exit 1", wantLen: crederr.MaxStderr})
	})
}

func TestInternalCredential(t *testing.T) {
	signing := func(internal bool) *config.Credential {
		return &config.Credential{
			Name:       "sign",
			Internal:   internal,
			PrivateKey: &config.ValueSource{Source: "provided"},
			Password:   &config.ValueSource{Source: "provided"},
		}
	}
	newStore := func(internal bool) *Store {
		s := NewStore(map[string]*config.Credential{"sign": signing(internal)})
		s.SetProvided(map[string]string{
			config.ProvidedKey("sign", config.SlotPrivateKey): "key",
			config.ProvidedKey("sign", config.SlotPassword):   "pass",
		})
		return s
	}
	type testCase struct {
		store   func() *Store
		read    func(*Store) error
		wantErr bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		err := tc.read(tc.store())
		if tc.wantErr {
			require.ErrorIs(t, err, ErrInternal)
			return
		}
		require.NoError(t, err)
	}
	get := func(s *Store) error {
		_, err := s.Get(t.Context(), "sign")
		return err
	}
	sshSigners := func(s *Store) error {
		_, err := s.SSHSigners(t.Context(), "sign")
		return err
	}
	getSlot := func(s *Store) error {
		v, err := s.GetSlot(t.Context(), "sign", config.SlotPassword)
		if err == nil && v != "pass" {
			return fmt.Errorf("got %q", v)
		}
		return err
	}
	madeInternalByReload := func() *Store {
		s := newStore(false)
		s.Update(map[string]*config.Credential{"sign": signing(true)})
		return s
	}

	t.Run("get refuses an internal credential", func(t *testing.T) {
		tester(t, testCase{store: func() *Store { return newStore(true) }, read: get, wantErr: true})
	})
	t.Run("ssh signers refuse an internal credential", func(t *testing.T) {
		tester(t, testCase{store: func() *Store { return newStore(true) }, read: sshSigners, wantErr: true})
	})
	t.Run("get slot reads an internal credential", func(t *testing.T) {
		tester(t, testCase{store: func() *Store { return newStore(true) }, read: getSlot})
	})
	t.Run("get reads a credential that is not internal", func(t *testing.T) {
		tester(t, testCase{store: func() *Store { return newStore(false) }, read: get})
	})
	t.Run("get refuses a credential a reload made internal", func(t *testing.T) {
		tester(t, testCase{store: madeInternalByReload, read: get, wantErr: true})
	})
	t.Run("ssh signers refuse a credential a reload made internal", func(t *testing.T) {
		tester(t, testCase{store: madeInternalByReload, read: sshSigners, wantErr: true})
	})
}

func TestSlotCacheAcrossReload(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(value), 0o600))
		return p
	}
	public := write("public", "public-value")
	secret := write("secret", "internal-value")
	record := func(file string, internal bool) *config.Credential {
		return &config.Credential{
			Name:     "x",
			Internal: internal,
			Token:    &config.ValueSource{Source: "file", File: file},
			Cache:    &config.Duration{D: time.Hour},
		}
	}
	type testCase struct {
		run  func(t *testing.T, s *Store) string
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		s := NewStore(map[string]*config.Credential{"x": record(public, false)})
		assert.Equal(t, tc.want, tc.run(t, s))
	}
	slot := func(c *config.Credential) config.Slot { return config.Slot{Name: config.SlotToken, Source: c.Token} }

	t.Run("a lookup from before a reload does not read the new record's cached value", func(t *testing.T) {
		tester(t, testCase{want: "public-value", run: func(t *testing.T, s *Store) string {
			t.Helper()
			old, _, err := s.lookup("x")
			require.NoError(t, err)
			s.Update(map[string]*config.Credential{"x": record(secret, true)})
			v, err := s.GetSlot(t.Context(), "x", config.SlotToken)
			require.NoError(t, err)
			require.Equal(t, "internal-value", v)
			v, err = s.slotValue(t.Context(), old, slot(old))
			require.NoError(t, err)
			return v
		}})
	})
	t.Run("a fetch from before a reload does not feed the new record", func(t *testing.T) {
		tester(t, testCase{want: "internal-value", run: func(t *testing.T, s *Store) string {
			t.Helper()
			old, _, err := s.lookup("x")
			require.NoError(t, err)
			s.Update(map[string]*config.Credential{"x": record(secret, true)})
			v, err := s.slotValue(t.Context(), old, slot(old))
			require.NoError(t, err)
			require.Equal(t, "public-value", v)
			v, err = s.GetSlot(t.Context(), "x", config.SlotToken)
			require.NoError(t, err)
			return v
		}})
	})
}
