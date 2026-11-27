package gitlab

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// recorder answers every project lookup with id 42 and records the
// Authorization each one carried.
type recorder struct {
	mu    sync.Mutex
	auths []string
	urls  []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auths = append(r.auths, req.Header.Get("Authorization"))
	r.urls = append(r.urls, req.URL.String())
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"id": 42}`)), Header: http.Header{}}, nil
}

func newResolver(t *testing.T) (*Resolver, *recorder) {
	t.Helper()
	cred := func(name string, allow ...string) *config.Credential {
		return &config.Credential{Name: name, Allow: allow, Token: &config.ValueSource{Source: "provided"}}
	}
	store := creds.NewStore(map[string]*config.Credential{
		"gitlab-ro":    cred("gitlab-ro", config.AllowAgent),
		"gitlab-dev":   cred("gitlab-dev", config.AllowAgent, config.AllowSubrequest),
		"gitlab-audit": cred("gitlab-audit", config.AllowSubrequest),
	})
	store.SetProvided(map[string]string{
		config.ProvidedKey("gitlab-ro", config.SlotToken):    "ro-secret",
		config.ProvidedKey("gitlab-dev", config.SlotToken):   "dev-secret",
		config.ProvidedKey("gitlab-audit", config.SlotToken): "audit-secret",
	})
	rec := &recorder{}
	return &Resolver{Transport: rec, Creds: store.Get, Log: zerolog.Nop()}, rec
}

func service(lookup string) *config.Service {
	return &config.Service{Name: "gitlab", Hosts: []string{"gitlab.example.com"}, Credentials: []string{lookup, "gitlab-audit"}, LookupCredential: lookup}
}

func TestResolve(t *testing.T) {
	type testCase struct {
		// services are looked up in order, each for group/project.
		services  []*config.Service
		wantAuths []string
		wantErr   string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		r, rec := newResolver(t)
		var err error
		for _, svc := range tc.services {
			var id int64
			id, err = r.Resolve(t.Context(), svc, "gitlab.example.com", "group/project")
			if err != nil {
				break
			}
			assert.Equal(t, int64(42), id)
		}
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, tc.wantAuths, rec.auths)
		for _, u := range rec.urls {
			assert.Equal(t, "https://gitlab.example.com/api/v4/projects/group%2Fproject", u)
		}
	}

	t.Run("looks up with the service's lookup_credential as a bearer token", func(t *testing.T) {
		tester(t, testCase{services: []*config.Service{service("gitlab-ro")}, wantAuths: []string{"Bearer ro-secret"}})
	})
	t.Run("caches a result per lookup credential", func(t *testing.T) {
		tester(t, testCase{services: []*config.Service{service("gitlab-ro"), service("gitlab-ro")}, wantAuths: []string{"Bearer ro-secret"}})
	})
	t.Run("profiles with the same service name and host keep their own credentials and cache entries", func(t *testing.T) {
		tester(t, testCase{
			services:  []*config.Service{service("gitlab-ro"), service("gitlab-dev")},
			wantAuths: []string{"Bearer ro-secret", "Bearer dev-secret"},
		})
	})
	t.Run("never sends an elevated credential, even if the load check were bypassed", func(t *testing.T) {
		tester(t, testCase{services: []*config.Service{service("gitlab-audit")}, wantErr: "gitlab api"})
	})
	t.Run("refuses a service without lookup_credential", func(t *testing.T) {
		tester(t, testCase{services: []*config.Service{{Name: "gitlab"}}, wantErr: `http "gitlab" has no lookup_credential`})
	})
}
