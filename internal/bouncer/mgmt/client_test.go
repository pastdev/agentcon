package mgmt

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/pastdev/agentcon/internal/bouncer/running"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	type testCase struct {
		handler http.Handler
		token   string
		check   func(*testing.T, *Client)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		srv := httptest.NewServer(tc.handler)
		t.Cleanup(srv.Close)
		c := New(srv.URL, tc.token)
		tc.check(t, c)
	}

	t.Run("returns status and settles prompts", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /_bouncer/status", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
			_ = json.NewEncoder(w).Encode(Status{Ready: true, Config: "/tmp/c.yaml"})
		})
		mux.HandleFunc("POST /_bouncer/prompts/abc", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			assert.JSONEq(t, `{"allow":true,"remember":false}`, string(body))
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("POST /_bouncer/prompts/def", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			assert.JSONEq(t, `{"allow":false,"remember":false,"value":"123456"}`, string(body))
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("DELETE /_bouncer/prompts/ghi", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		tester(t, testCase{
			handler: mux,
			token:   "secret",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				st, err := c.Status()
				require.NoError(t, err)
				assert.True(t, st.Ready)
				assert.Equal(t, "/tmp/c.yaml", st.Config)
				err = c.AnswerPrompt("abc", prompt.Answer{Allow: true})
				require.NoError(t, err)
				err = c.AnswerPrompt("def", prompt.Answer{Value: "123456"})
				require.NoError(t, err)
				err = c.DeclinePrompt("ghi")
				require.NoError(t, err)
			},
		})
	})
	t.Run("includes the http error body", func(t *testing.T) {
		tester(t, testCase{
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "no such session", http.StatusNotFound)
			}),
			token: "t",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				err := c.EndSession("missing")
				require.ErrorContains(t, err, "no such session")
			},
		})
	})
	t.Run("puts env overlay values", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("PUT /_bouncer/credentials/sources/env", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
			body, _ := io.ReadAll(r.Body)
			assert.Contains(t, string(body), `"SMOKE_TOKEN":"s3cret"`)
			w.WriteHeader(http.StatusNoContent)
		})
		tester(t, testCase{
			handler: mux,
			token:   "secret",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				err := c.PutEnv(map[string]string{"SMOKE_TOKEN": "s3cret"})
				require.NoError(t, err)
			},
		})
	})
	t.Run("puts provided credential values", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("PUT /_bouncer/credentials/provided", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
			body, _ := io.ReadAll(r.Body)
			assert.Contains(t, string(body), `"tok":"from-file"`)
			w.WriteHeader(http.StatusNoContent)
		})
		tester(t, testCase{
			handler: mux,
			token:   "secret",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				err := c.PutProvided(map[string]string{"tok": "from-file"})
				require.NoError(t, err)
			},
		})
	})
	t.Run("returns the trust bundle", func(t *testing.T) {
		tester(t, testCase{
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/_bouncer/ca", r.URL.Path)
				_ = json.NewEncoder(w).Encode(Trust{CertPEM: "CERT", BundlePEM: "BUNDLE"})
			}),
			token: "t",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				got, err := c.Trust()
				require.NoError(t, err)
				assert.Equal(t, Trust{CertPEM: "CERT", BundlePEM: "BUNDLE"}, got)
			},
		})
	})
}

func TestDial(t *testing.T) {
	type testCase struct {
		stateDir   string
		configPath string
		wantErr    string
		after      func(*testing.T, *Client)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		c, err := Dial(tc.stateDir, tc.configPath)
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		if tc.after != nil {
			tc.after(t, c)
		}
	}

	t.Run("dials from host.json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/_bouncer/reload", r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)

		state := t.TempDir()
		addr := strings.TrimPrefix(srv.URL, "http://")
		err := os.WriteFile(filepath.Join(state, "host.json"), []byte(`{"control_addr":"`+addr+`"}`), 0o600)
		require.NoError(t, err)
		err = os.WriteFile(daemon.AdminTokenPath(state), []byte("tok\n"), 0o600)
		require.NoError(t, err)
		tester(t, testCase{
			stateDir:   state,
			configPath: filepath.Join(state, "missing.yaml"),
			after: func(t *testing.T, c *Client) {
				t.Helper()
				err := c.Reload()
				require.NoError(t, err)
			},
		})
	})
	t.Run("rejects a missing admin token", func(t *testing.T) {
		state := t.TempDir()
		err := os.WriteFile(filepath.Join(state, "host.json"), []byte(`{"control_addr":"127.0.0.1:1"}`), 0o600)
		require.NoError(t, err)
		tester(t, testCase{stateDir: state, wantErr: "admin token"})
	})
}

func TestDialContext(t *testing.T) {
	type testCase struct {
		home  string
		query running.Query
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		c, err := DialContext(tc.home, tc.query, "", "")
		require.NoError(t, err)
		err = c.Reload()
		require.NoError(t, err)
	}

	t.Run("uses a running record", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer from-record", r.Header.Get("Authorization"))
			assert.Equal(t, "/_bouncer/reload", r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)

		home := t.TempDir()
		addr := strings.TrimPrefix(srv.URL, "http://")
		err := running.Write(home, running.Record{
			Context:     "foo",
			Slug:        "deadbeef",
			ControlAddr: addr,
			Token:       "from-record",
			PID:         1,
		})
		require.NoError(t, err)
		tester(t, testCase{home: home, query: running.Query{Slug: "deadbeef"}})
	})
}
