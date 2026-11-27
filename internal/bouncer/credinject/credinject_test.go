package credinject

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

var testCreds = map[string]*config.Credential{
	"github":       {Name: "github", Allow: []string{config.AllowAgent, config.AllowSubrequest}},
	"github-audit": {Name: "github-audit", Allow: []string{config.AllowSubrequest}},
	"agent-only":   {Name: "agent-only", Allow: []string{config.AllowAgent}},
}

func lookup(name string) (*config.Credential, bool) {
	c, ok := testCreds[name]
	return c, ok
}

var secrets = map[string]creds.Secret{
	"github":       {Token: "gh-secret"},
	"github-audit": {Token: "audit-secret"},
	"agent-only":   {Token: "agent-secret"},
}

func TestAgentRequests(t *testing.T) {
	type testCase struct {
		svc      *config.Service
		header   map[string]string
		rawQuery string
		want     map[string]string
		wantUsed []string
		// wantQuery is the query after Apply, when set.
		wantQuery string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		h := http.Header{}
		for k, v := range tc.header {
			h.Set(k, v)
		}
		u := &url.URL{Scheme: "https", Host: "api.github.com", Path: "/x", RawQuery: tc.rawQuery}
		req := &chain.Request{URL: u, Header: h}
		p := NewPlan(tc.svc, req, h, u, nil, lookup)
		assert.Equal(t, tc.wantUsed, p.Used)
		_, _ = p.Apply(h, u, nil, secrets)
		for k, v := range tc.want {
			assert.Equal(t, v, h.Get(k), k)
		}
		if tc.wantQuery != "" {
			assert.Equal(t, tc.wantQuery, u.RawQuery)
		}
	}
	both := &config.Service{Credentials: []string{"github", "github-audit"}}

	t.Run("replaces a usable static placeholder in auth headers", func(t *testing.T) {
		tester(t, testCase{
			svc:      both,
			header:   map[string]string{"Authorization": "Bearer bouncer-placeholder-github"},
			want:     map[string]string{"Authorization": "Bearer gh-secret"},
			wantUsed: []string{"github"},
		})
	})
	t.Run("never replaces an elevated credential's placeholder for the agent", func(t *testing.T) {
		tester(t, testCase{
			svc:    both,
			header: map[string]string{"Authorization": "Bearer bouncer-placeholder-github-audit"},
			want:   map[string]string{"Authorization": "Bearer bouncer-placeholder-github-audit"},
		})
	})
	t.Run("a shorter name never matches inside a longer placeholder", func(t *testing.T) {
		tester(t, testCase{
			svc:    &config.Service{Credentials: []string{"github"}},
			header: map[string]string{"Private-Token": "bouncer-placeholder-github-audit"},
			want:   map[string]string{"Private-Token": "bouncer-placeholder-github-audit"},
		})
	})
	t.Run("replaces inside basic auth", func(t *testing.T) {
		basic := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
		tester(t, testCase{
			svc:      both,
			header:   map[string]string{"Authorization": basic("x-access-token:bouncer-placeholder-github")},
			want:     map[string]string{"Authorization": basic("x-access-token:gh-secret")},
			wantUsed: []string{"github"},
		})
	})
	t.Run("leaves other headers and the query alone", func(t *testing.T) {
		tester(t, testCase{
			svc:       both,
			header:    map[string]string{"X-Note": "bouncer-placeholder-github"},
			rawQuery:  "q=bouncer-placeholder-github",
			want:      map[string]string{"X-Note": "bouncer-placeholder-github"},
			wantQuery: "q=bouncer-placeholder-github",
		})
	})
	t.Run("a placeholder in the inject header takes precedence over inject", func(t *testing.T) {
		tester(t, testCase{
			svc: &config.Service{
				Credentials: []string{"github", "agent-only"},
				Inject:      &config.Inject{Credential: "github", Bearer: true},
			},
			header:   map[string]string{"Authorization": "Bearer bouncer-placeholder-agent-only"},
			want:     map[string]string{"Authorization": "Bearer agent-secret"},
			wantUsed: []string{"agent-only"},
		})
	})
	t.Run("inject attaches its credential", func(t *testing.T) {
		tester(t, testCase{
			svc:       &config.Service{Credentials: []string{"github"}, Inject: &config.Inject{Credential: "github", Query: "api_key"}},
			rawQuery:  "a=1",
			wantUsed:  []string{"github"},
			wantQuery: "a=1&api_key=gh-secret",
		})
	})
	t.Run("inject uses basic with the username slot", func(t *testing.T) {
		tester(t, testCase{
			svc:      &config.Service{Credentials: []string{"github"}, Inject: &config.Inject{Credential: "github", Basic: &config.BasicInject{Username: "oauth2"}}},
			want:     map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:gh-secret"))},
			wantUsed: []string{"github"},
		})
	})
}

func TestStrip(t *testing.T) {
	svc := &config.Service{Credentials: []string{"github"}, Inject: &config.Inject{Credential: "github", Query: "api_key"}}
	h := http.Header{}
	h.Set("Authorization", "Bearer bouncer-placeholder-github")
	h.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("oauth2:bouncer-placeholder-github")))
	h.Set("Private-Token", "bouncer-placeholder-github")
	h.Set("X-Other", "keep")
	u, err := url.Parse("https://example.com/x?api_key=bouncer-placeholder-github&ok=1")
	require.NoError(t, err)
	req := &chain.Request{URL: u, Header: h}
	NewPlan(svc, req, h, u, nil, lookup).Strip(h, u)
	assert.Empty(t, h.Values("Authorization"))
	assert.Empty(t, h.Get("Private-Token"))
	assert.Equal(t, "keep", h.Get("X-Other"))
	assert.Empty(t, u.Query().Get("api_key"))
	assert.Equal(t, "1", u.Query().Get("ok"))
}
