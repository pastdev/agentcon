package mgmt

import (
	"encoding/json"
	"errors"
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
			if got := r.Header.Get("Authorization"); got != "Bearer secret" {
				t.Errorf("auth %q", got)
			}
			_ = json.NewEncoder(w).Encode(Status{Ready: true, Config: "/tmp/c.yaml"})
		})
		mux.HandleFunc("POST /_bouncer/prompts/abc", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"allow":true,"remember":false}` {
				t.Errorf("body %s", body)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("POST /_bouncer/prompts/def", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"allow":false,"remember":false,"value":"123456"}` {
				t.Errorf("body %s", body)
			}
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
				if err != nil {
					t.Fatal(err)
				}
				if !st.Ready || st.Config != "/tmp/c.yaml" {
					t.Fatalf("%+v", st)
				}
				err = c.AnswerPrompt("abc", prompt.Answer{Allow: true})
				if err != nil {
					t.Fatal(err)
				}
				err = c.AnswerPrompt("def", prompt.Answer{Value: "123456"})
				if err != nil {
					t.Fatal(err)
				}
				err = c.DeclinePrompt("ghi")
				if err != nil {
					t.Fatal(err)
				}
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
				if err == nil || !strings.Contains(err.Error(), "no such session") {
					t.Fatalf("got %v", err)
				}
			},
		})
	})
	t.Run("unlocks bitwarden after a need-code challenge", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /_bouncer/credentials/sources/bitwarden/unlock", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(string(body), `"code":"123456"`) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "need_code", "method": "authenticator app"})
		})
		tester(t, testCase{
			handler: mux,
			token:   "secret",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				err := c.UnlockBitwarden("pw", "")
				var need *NeedCodeError
				if !errors.As(err, &need) || need.Method != "authenticator app" {
					t.Fatalf("got %v", err)
				}
				err = c.UnlockBitwarden("pw", "123456")
				if err != nil {
					t.Fatal(err)
				}
			},
		})
	})
	t.Run("puts env overlay values", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("PUT /_bouncer/credentials/sources/env", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer secret" {
				t.Errorf("auth %q", r.Header.Get("Authorization"))
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"SMOKE_TOKEN":"s3cret"`) {
				t.Errorf("body %s", body)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		tester(t, testCase{
			handler: mux,
			token:   "secret",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				err := c.PutEnv(map[string]string{"SMOKE_TOKEN": "s3cret"})
				if err != nil {
					t.Fatal(err)
				}
			},
		})
	})
	t.Run("puts provided credential values", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("PUT /_bouncer/credentials/provided", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer secret" {
				t.Errorf("auth %q", r.Header.Get("Authorization"))
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"tok":"from-file"`) {
				t.Errorf("body %s", body)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		tester(t, testCase{
			handler: mux,
			token:   "secret",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				err := c.PutProvided(map[string]string{"tok": "from-file"})
				if err != nil {
					t.Fatal(err)
				}
			},
		})
	})
	t.Run("returns the trust bundle", func(t *testing.T) {
		tester(t, testCase{
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/_bouncer/ca" {
					t.Errorf("path %s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(Trust{CertPEM: "CERT", BundlePEM: "BUNDLE"})
			}),
			token: "t",
			check: func(t *testing.T, c *Client) {
				t.Helper()
				got, err := c.Trust()
				if err != nil {
					t.Fatal(err)
				}
				if got.CertPEM != "CERT" || got.BundlePEM != "BUNDLE" {
					t.Fatalf("%+v", got)
				}
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
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if tc.after != nil {
			tc.after(t, c)
		}
	}

	t.Run("dials from host.json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/_bouncer/reload" {
				t.Errorf("path %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)

		state := t.TempDir()
		addr := strings.TrimPrefix(srv.URL, "http://")
		err := os.WriteFile(filepath.Join(state, "host.json"), []byte(`{"control_addr":"`+addr+`"}`), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(daemon.AdminTokenPath(state), []byte("tok\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			stateDir:   state,
			configPath: filepath.Join(state, "missing.yaml"),
			after: func(t *testing.T, c *Client) {
				t.Helper()
				err := c.Reload()
				if err != nil {
					t.Fatal(err)
				}
			},
		})
	})
	t.Run("rejects a missing admin token", func(t *testing.T) {
		state := t.TempDir()
		err := os.WriteFile(filepath.Join(state, "host.json"), []byte(`{"control_addr":"127.0.0.1:1"}`), 0o600)
		if err != nil {
			t.Fatal(err)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		err = c.Reload()
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Run("uses a running record", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer from-record" {
				t.Errorf("auth %s", r.Header.Get("Authorization"))
			}
			if r.URL.Path != "/_bouncer/reload" {
				t.Errorf("path %s", r.URL.Path)
			}
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
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{home: home, query: running.Query{Slug: "deadbeef"}})
	})
}
