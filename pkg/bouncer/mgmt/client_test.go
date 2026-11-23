package mgmt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
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
				st, err := c.Status(t.Context())
				require.NoError(t, err)
				assert.True(t, st.Ready)
				assert.Equal(t, "/tmp/c.yaml", st.Config)
				err = c.AnswerPrompt(t.Context(), "abc", prompt.Answer{Allow: true})
				require.NoError(t, err)
				err = c.AnswerPrompt(t.Context(), "def", prompt.Answer{Value: "123456"})
				require.NoError(t, err)
				err = c.DeclinePrompt(t.Context(), "ghi")
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
				err := c.EndSession(t.Context(), "missing")
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
				err := c.PutEnv(t.Context(), map[string]string{"SMOKE_TOKEN": "s3cret"})
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
				err := c.PutProvided(t.Context(), map[string]string{"tok": "from-file"})
				require.NoError(t, err)
			},
		})
	})
	t.Run("sends empty replacements so they clear old values", func(t *testing.T) {
		var bodies []string
		record := func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			bodies = append(bodies, r.URL.Path+" "+string(body))
			w.WriteHeader(http.StatusNoContent)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("PUT /_bouncer/credentials/sources/env", record)
		mux.HandleFunc("PUT /_bouncer/credentials/provided", record)
		tester(t, testCase{
			handler: mux,
			check: func(t *testing.T, c *Client) {
				t.Helper()
				require.NoError(t, c.PutEnv(t.Context(), map[string]string{"A": "1"}))
				require.NoError(t, c.PutEnv(t.Context(), map[string]string{}))
				require.NoError(t, c.PutProvided(t.Context(), map[string]string{"x.token": "1"}))
				require.NoError(t, c.PutProvided(t.Context(), nil))
				assert.Equal(t, []string{
					`/_bouncer/credentials/sources/env {"A":"1"}`,
					`/_bouncer/credentials/sources/env {}`,
					`/_bouncer/credentials/provided {"x.token":"1"}`,
					`/_bouncer/credentials/provided {}`,
				}, bodies)
			},
		})
	})
	t.Run("creates a session with and without claims", func(t *testing.T) {
		var bodies []string
		mux := http.NewServeMux()
		mux.HandleFunc("POST /_bouncer/sessions", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			bodies = append(bodies, string(body))
			_, _ = io.WriteString(w, `{"id":"deadbeef","claims":{"repository":["g/a"]}}`)
		})
		tester(t, testCase{
			handler: mux,
			check: func(t *testing.T, c *Client) {
				t.Helper()
				_, err := c.CreateSession(t.Context(), "", "", "plain", "")
				require.NoError(t, err)
				rec, err := c.CreateSession(t.Context(), "deadbeef", "p", "seeded", "1h",
					WithClaims(map[string][]string{"repository": {"g/a"}}))
				require.NoError(t, err)
				assert.Equal(t, claims.Set{"repository": {"g/a"}}, rec.Claims)
				require.Len(t, bodies, 2)
				assert.JSONEq(t, `{"id":"","profile":"","label":"plain","ttl":""}`, bodies[0])
				assert.JSONEq(t, `{"id":"deadbeef","profile":"p","label":"seeded","ttl":"1h","claims":{"repository":["g/a"]}}`, bodies[1])
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
				got, err := c.Trust(t.Context())
				require.NoError(t, err)
				assert.Equal(t, Trust{CertPEM: "CERT", BundlePEM: "BUNDLE"}, got)
			},
		})
	})
	t.Run("stops when the context ends", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		tester(t, testCase{
			handler: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				<-release
			}),
			token: "t",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				_, err := c.Status(ctx)
				require.ErrorIs(t, err, context.Canceled)
			},
		})
	})
}
