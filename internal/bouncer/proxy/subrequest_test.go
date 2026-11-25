package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	audit  []audit.Entry
	port   string
}

func setupSubrequest(t *testing.T, rules string) *subEnv {
	t.Helper()
	e := &subEnv{}
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
  tok: {token: {source: env, env: BOUNCER_TEST_TOKEN}}
profiles:
  p:
    unmatched: deny
    http:
      - name: api
        hosts: ["localhost:`+e.port+`"]
        credential: tok
        inject: {bearer: true}
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
		Audit:     audit.New(zerolog.New(entryWriter{&e.audit})),
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

		var sub *audit.Entry
		for i := range e.audit {
			if e.audit[i].Subrequest != nil {
				sub = &e.audit[i]
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
	resp, u, err := e.srv.Subrequest(parent, "ssh-filter", chain.SubrequestSpec{URL: "https://localhost:" + e.port + "/rules/main"})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := resp.Body.ReadAll()
	require.NoError(t, err)
	assert.Equal(t, "auth=Bearer real-secret path=/rules/main", string(b))
	assert.Equal(t, "https://localhost:"+e.port+"/rules/main", u.String())
	require.Len(t, e.audit, 1)
	assert.Equal(t, "ssh git@github.com git: git-receive-pack 'o/r.git'", e.audit[0].Subrequest.Parent)
}

func TestSubrequestUpstreamFailureRejects(t *testing.T) {
	e := setupSubrequest(t, `          - action: allow
            path: /**
`)
	// The transport fails the way a refused connection does.
	parent := &chain.Request{Ctx: context.Background(), Transport: chain.TransportHTTP, Session: &chain.Session{ID: "s1", Profile: "p"},
		Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "localhost", Path: "/"}}
	e.srv.Transport = refusingTransport{}
	_, _, err := e.srv.Subrequest(parent, "f", chain.SubrequestSpec{URL: "https://localhost:" + e.port + "/rules/main"})
	require.ErrorContains(t, err, "subrequest: upstream: dial tcp: connection refused")
}

type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errConnRefused{}}
}

type errConnRefused struct{}

func (errConnRefused) Error() string { return "connection refused" }
