package mgmtdial

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/running"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDial(t *testing.T) {
	type testCase struct {
		stateDir   string
		configPath string
		wantErr    string
		after      func(*testing.T, *mgmt.Client)
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
			after: func(t *testing.T, c *mgmt.Client) {
				t.Helper()
				err := c.Reload(t.Context())
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
		err = c.Reload(t.Context())
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
