package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/audit"
	"github.com/pastdev/agentcon/internal/bouncer/ca"
	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// lookupFilter answers an agent request with the result of a subrequest
// to /rules/main on the same service. It runs on the subrequest too, and
// passes it through.
const lookupFilter = `import { defineFilter, respond, subrequest } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    if (req.subrequest) return next(req);
    const r = await subrequest({ url: "https://localhost:PORT/rules/main" });
    if (r.denied) return respond(200, "denied " + r.denied.reason);
    return respond(200, "lookup " + r.status + " " + (await r.body.text()));
  },
});`

type subEnv struct {
	srv    *Server
	client *http.Client
	audit  *auditSink
	port   string
}

func setupSubrequest(t *testing.T, rules string) *subEnv {
	t.Helper()
	e := &subEnv{audit: &auditSink{}}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "auth="+r.Header.Get("Authorization")+" path="+r.URL.Path) //nolint:gosec // test upstream echoes the request on purpose
	}))
	t.Cleanup(upstream.Close)
	_, e.port, _ = net.SplitHostPort(upstream.Listener.Addr().String())

	dir := t.TempDir()
	filterPath := filepath.Join(dir, "lookup.ts")
	err := os.WriteFile(filterPath, []byte(strings.ReplaceAll(lookupFilter, "PORT", e.port)), 0o600)
	require.NoError(t, err)

	t.Setenv("BOUNCER_TEST_TOKEN", "real-secret")
	cfg, err := config.Parse([]byte(`
credentials:
  tok: {allow: [agent, subrequest], token: {source: env, env: BOUNCER_TEST_TOKEN}}
profiles:
  p:
    unmatched: deny
    http:
      - name: api
        hosts: ["localhost:`+e.port+`"]
        credentials: [tok]
        inject: {credential: tok, bearer: true}
        filters:
          - path: `+filterPath+`
        rules:
`+rules), filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	env := &chain.Env{Log: zerolog.Nop()}
	set, err := policy.Compile(cfg, env, nil)
	require.NoError(t, err)
	authority, err := ca.LoadOrCreate(t.TempDir())
	require.NoError(t, err)
	tr := NewTransport()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test upstream uses a self-signed certificate
	e.srv = &Server{
		Backend:   &fakeBackend{set: set, sessions: map[string]*chain.Session{"tok123": {ID: "s1", Profile: "p"}}},
		CA:        authority,
		Creds:     creds.NewStore(cfg.Credentials),
		Audit:     audit.New(zerolog.New(e.audit)),
		Transport: tr,
		Dialer:    &net.Dialer{},
	}
	env.Subrequest = e.srv.Subrequest
	px := httptest.NewServer(e.srv)
	t.Cleanup(px.Close)

	roots := x509.NewCertPool()
	roots.AddCert(authority.Cert())
	proxyURL, err := url.Parse(px.URL)
	require.NoError(t, err)
	proxyURL.User = url.UserPassword("bouncer", "tok123")
	e.client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	return e
}

func TestSubrequestThroughProxy(t *testing.T) {
	type testCase struct {
		rules      string
		want       string
		wantDecide string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		e := setupSubrequest(t, tc.rules)
		resp, err := e.client.Get("https://localhost:" + e.port + "/push")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, strings.ReplaceAll(tc.want, "PORT", e.port), string(b))

		// The subrequest's entry and the parent's.
		entries := e.audit.wait(t, 2)
		var sub *audit.Entry
		for i := range entries {
			if entries[i].Subrequest != nil {
				sub = &entries[i]
			}
		}
		require.NotNil(t, sub, "the subrequest is audited")
		assert.Equal(t, "lookup", sub.Subrequest.Filter)
		assert.Equal(t, 1, sub.Subrequest.Depth)
		assert.Equal(t, "GET localhost:"+e.port+"/push", sub.Subrequest.Parent)
		assert.Equal(t, "api", sub.Service)
		assert.Equal(t, tc.wantDecide, sub.Decision)
	}

	t.Run("a subrequest gets the service credential", func(t *testing.T) {
		tester(t, testCase{
			rules: `          - action: allow
            path: /**
`,
			want:       "lookup 200 auth=Bearer real-secret path=/rules/main",
			wantDecide: audit.DecisionAllow,
		})
	})
	t.Run("the service rules judge a subrequest", func(t *testing.T) {
		tester(t, testCase{
			rules: `          - action: allow
            path: /push
`,
			want:       "denied no rule allows GET localhost:PORT/rules/main",
			wantDecide: audit.DecisionDeny,
		})
	})
}

func TestSubrequestFromSSHParent(t *testing.T) {
	e := setupSubrequest(t, `          - action: allow
            path: /rules/**
`)
	parent := &chain.Request{Ctx: context.Background(), Transport: chain.TransportSSH, Session: &chain.Session{ID: "s1", Profile: "p"},
		SSH: &chain.SSHInfo{Host: "github.com", User: "git", Kind: "git", Command: "git-receive-pack 'o/r.git'"}}
	resp, u, err := e.srv.Subrequest(parent, chain.SubrequestCaller{Filter: "ssh-filter"}, chain.SubrequestSpec{URL: "https://localhost:" + e.port + "/rules/main"})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := resp.Body.ReadAll()
	require.NoError(t, err)
	assert.Equal(t, "auth=Bearer real-secret path=/rules/main", string(b))
	assert.Equal(t, "https://localhost:"+e.port+"/rules/main", u.String())
	entries := e.audit.wait(t, 1)
	require.Len(t, entries, 1)
	assert.Equal(t, "ssh git@github.com git: git-receive-pack 'o/r.git'", entries[0].Subrequest.Parent)
}

func TestSubrequestUpstreamFailureRejects(t *testing.T) {
	e := setupSubrequest(t, `          - action: allow
            path: /**
`)
	// The transport fails the way a refused connection does.
	parent := &chain.Request{Ctx: context.Background(), Transport: chain.TransportHTTP, Session: &chain.Session{ID: "s1", Profile: "p"},
		Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "localhost", Path: "/"}}
	e.srv.Transport = refusingTransport{}
	_, _, err := e.srv.Subrequest(parent, chain.SubrequestCaller{Filter: "f"}, chain.SubrequestSpec{URL: "https://localhost:" + e.port + "/rules/main"})
	require.ErrorContains(t, err, "subrequest: upstream: dial tcp: connection refused")
}

type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errConnRefused{}}
}

type errConnRefused struct{}

func (errConnRefused) Error() string { return "connection refused" }

// elevatedEnv is a service with an ordinary credential (tok) and an
// elevated one (audit) that only the /secrets rule lets a subrequest use.
type elevatedEnv struct {
	srv   *Server
	audit *auditSink
	base  string
}

// echoBodiesFilter answers with the request body it sees after the
// forwarder ran, then the upstream's answer.
const echoBodiesFilter = `import { defineFilter, respond } from "bouncer";
export default defineFilter({
  async onResponse(res, req) {
    return respond(200, "filter-saw=" + (await req.body.text()) + " upstream=" + (await res.body.text()));
  },
});`

// setupElevated builds the service. filters, when set, is a service
// filters: entry.
func setupElevated(t *testing.T, filters ...string) *elevatedEnv {
	t.Helper()
	e := &elevatedEnv{audit: &auditSink{}}
	dir := t.TempDir()
	svcFilters := ""
	for i, src := range filters {
		p := filepath.Join(dir, fmt.Sprintf("f%d.ts", i))
		require.NoError(t, os.WriteFile(p, []byte(src), 0o600))
		svcFilters += "\n          - path: " + p
	}
	if svcFilters != "" {
		svcFilters = "\n        filters:" + svcFilters
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secrets/redirect" {
			http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "auth="+r.Header.Get("Authorization")+" key="+r.Header.Get("X-Key")+ //nolint:gosec // test upstream echoes the request on purpose
			" query="+r.URL.RawQuery+" body="+string(body))
	}))
	t.Cleanup(upstream.Close)
	_, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	e.base = "https://localhost:" + port

	t.Setenv("BOUNCER_TEST_TOKEN", "tok-secret")
	t.Setenv("BOUNCER_TEST_AUDIT", `audit"&secret`)
	cfg, err := config.Parse([]byte(`
credentials:
  tok: {allow: [agent, subrequest], token: {source: env, env: BOUNCER_TEST_TOKEN}}
  audit: {allow: [subrequest], token: {source: env, env: BOUNCER_TEST_AUDIT}}
profiles:
  p:
    unmatched: deny
    http:
      - name: api
        hosts: ["localhost:`+port+`"]
        credentials: [tok, audit]
        inject: {credential: tok, bearer: true}`+svcFilters+`
        rules:
          - action: allow
            path: /secrets/**
            subrequest: {credentials: [audit]}
          - action: allow
            path: /**
`), filepath.Join(dir, "config.yaml"))
	require.NoError(t, err)
	set, err := policy.Compile(cfg, &chain.Env{Log: zerolog.Nop()}, nil)
	require.NoError(t, err)
	authority, err := ca.LoadOrCreate(t.TempDir())
	require.NoError(t, err)
	tr := NewTransport()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test upstream uses a self-signed certificate
	e.srv = &Server{
		Backend:   &fakeBackend{set: set, sessions: map[string]*chain.Session{"tok123": {ID: "s1", Profile: "p"}}},
		CA:        authority,
		Creds:     creds.NewStore(cfg.Credentials),
		Audit:     audit.New(zerolog.New(e.audit)),
		Transport: tr,
		Dialer:    &net.Dialer{},
	}
	return e
}

func TestSubstitutedBodyStaysOutOfFilters(t *testing.T) {
	const ph = "bouncer-placeholder-audit-0123456789abcdef"
	e := setupElevated(t, echoBodiesFilter)
	parent := &chain.Request{Ctx: context.Background(), Transport: chain.TransportHTTP, Session: &chain.Session{ID: "s1", Profile: "p"},
		Method: http.MethodPost, URL: &url.URL{Scheme: "https", Host: "github.com", Path: "/o/r.git/git-receive-pack"}}
	caller := chain.SubrequestCaller{Filter: "f", Placeholders: map[string]string{ph: "audit"}}
	resp, _, err := e.srv.Subrequest(parent, caller, chain.SubrequestSpec{
		Method: http.MethodPost, URL: e.base + "/secrets/create",
		Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"token":"` + ph + `"}`),
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := resp.Body.ReadAll()
	require.NoError(t, err)
	saw, upstream, ok := strings.Cut(string(b), " upstream=")
	require.True(t, ok, string(b))
	assert.Equal(t, `filter-saw={"token":"`+ph+`"}`, saw, "the filter sees the placeholder, never the secret")
	assert.Contains(t, upstream, `body={"token":"audit\"&secret"}`, "the upstream got the secret")
}

func TestElevatedSubrequest(t *testing.T) {
	const (
		auditPH = "bouncer-placeholder-audit-0123456789abcdef"
		tokPH   = "bouncer-placeholder-tok-fedcba9876543210"
	)
	type testCase struct {
		method string
		path   string
		header map[string]string
		body   string
		want   string
		// wantCreds lists each hop's audited credentials.
		wantCreds [][]string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		e := setupElevated(t)
		parent := &chain.Request{Ctx: context.Background(), Transport: chain.TransportHTTP, Session: &chain.Session{ID: "s1", Profile: "p"},
			Method: http.MethodPost, URL: &url.URL{Scheme: "https", Host: "github.com", Path: "/o/r.git/git-receive-pack"}}
		h := http.Header{}
		for k, v := range tc.header {
			h.Set(k, v)
		}
		caller := chain.SubrequestCaller{Filter: "f", Placeholders: map[string]string{auditPH: "audit", tokPH: "tok"}}
		resp, _, err := e.srv.Subrequest(parent, caller, chain.SubrequestSpec{Method: tc.method, URL: e.base + tc.path, Header: h, Body: []byte(tc.body)})
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := resp.Body.ReadAll()
		require.NoError(t, err)
		assert.Equal(t, tc.want, string(b))
		entries := e.audit.wait(t, len(tc.wantCreds))
		var got [][]string
		for _, en := range entries {
			got = append(got, en.Credentials)
		}
		assert.Equal(t, tc.wantCreds, got)
	}

	t.Run("an elevated placeholder is replaced on the rule that lists it, ahead of inject", func(t *testing.T) {
		tester(t, testCase{
			path:      "/secrets/list",
			header:    map[string]string{"Authorization": "Bearer " + auditPH},
			want:      `auth=Bearer audit"&secret key= query= body=`,
			wantCreds: [][]string{{"audit"}},
		})
	})
	t.Run("an elevated placeholder is left as text on another route", func(t *testing.T) {
		tester(t, testCase{
			path:      "/repos/merge",
			header:    map[string]string{"X-Key": auditPH},
			want:      "auth=Bearer tok-secret key=" + auditPH + " query= body=",
			wantCreds: [][]string{{"tok"}},
		})
	})
	t.Run("inject overwrites an elevated placeholder it may not use", func(t *testing.T) {
		tester(t, testCase{
			path:      "/repos/merge",
			header:    map[string]string{"Authorization": "Bearer " + auditPH},
			want:      "auth=Bearer tok-secret key= query= body=",
			wantCreds: [][]string{{"tok"}},
		})
	})
	t.Run("the static placeholder is never replaced in a subrequest", func(t *testing.T) {
		tester(t, testCase{
			path:      "/secrets/list",
			header:    map[string]string{"X-Key": "bouncer-placeholder-audit"},
			want:      "auth=Bearer tok-secret key=bouncer-placeholder-audit query= body=",
			wantCreds: [][]string{{"tok"}},
		})
	})
	t.Run("a placeholder in the query is escaped for the query", func(t *testing.T) {
		tester(t, testCase{
			path:      "/secrets/list?token=" + auditPH,
			want:      "auth=Bearer tok-secret key= query=token=audit%22%26secret body=",
			wantCreds: [][]string{{"audit", "tok"}},
		})
	})
	t.Run("a placeholder in a JSON body is escaped for JSON", func(t *testing.T) {
		tester(t, testCase{
			method:    http.MethodPost,
			path:      "/secrets/create",
			header:    map[string]string{"Content-Type": "application/json"},
			body:      `{"token":"` + auditPH + `"}`,
			want:      `auth=Bearer tok-secret key= query= body={"token":"audit\"&secret"}`,
			wantCreds: [][]string{{"audit", "tok"}},
		})
	})
	t.Run("a placeholder in a form body is escaped for the form", func(t *testing.T) {
		tester(t, testCase{
			method:    http.MethodPost,
			path:      "/secrets/create",
			header:    map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			body:      "client_secret=" + auditPH + "&a=1",
			want:      "auth=Bearer tok-secret key= query= body=client_secret=audit%22%26secret&a=1",
			wantCreds: [][]string{{"audit", "tok"}},
		})
	})
	t.Run("an ordinary credential's placeholder works on any route", func(t *testing.T) {
		tester(t, testCase{
			path:      "/repos/x",
			header:    map[string]string{"X-Key": tokPH},
			want:      "auth=Bearer tok-secret key=tok-secret query= body=",
			wantCreds: [][]string{{"tok"}},
		})
	})
	t.Run("a same-host redirect to another route loses the elevated credential", func(t *testing.T) {
		tester(t, testCase{
			path:      "/secrets/redirect",
			header:    map[string]string{"Authorization": "Bearer " + auditPH},
			want:      "auth=Bearer tok-secret key= query= body=",
			wantCreds: [][]string{{"audit"}, {"tok"}},
		})
	})
}
