package subreq

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/audit"
	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// seen is one request a fake upstream or tunnel received.
type seen struct {
	via        string
	method     string
	url        string
	header     http.Header
	body       string
	subrequest *chain.SubrequestInfo
	claims     claims.Set
}

// filterFunc is a Go chain filter for tests.
type filterFunc func(req *chain.Request, next chain.Handler) (*chain.Response, error)

func (filterFunc) Name() string { return "test-filter" }

func (f filterFunc) Handle(req *chain.Request, next chain.Handler) (*chain.Response, error) {
	return f(req, next)
}

// answer is a fake upstream response keyed by URL.
type answer struct {
	status   int
	location string
	body     string
	err      error
	block    bool
}

type env struct {
	router  *Router
	seen    []seen
	audit   []audit.Entry
	answers map[string]answer
	live    bool
}

func newEnv(unmatched string, filters ...chain.Filter) *env {
	e := &env{answers: map[string]answer{}, live: true}
	prof := &policy.Profile{
		Name:      "p",
		Unmatched: unmatched,
		HTTP: []*policy.Service{{
			Config:  &config.Service{Name: "github", Hosts: []string{"github.com", "api.github.com"}, Credential: "pat"},
			Filters: filters,
		}},
	}
	respond := func(via string, req *chain.Request) *chain.Response {
		body, _ := req.Body.ReadAll()
		e.seen = append(e.seen, seen{via: via, method: req.Method, url: req.URL.String(), header: req.Header.Clone(),
			body: string(body), subrequest: req.Subrequest, claims: req.Session.Claims})
		a, ok := e.answers[req.URL.String()]
		if !ok {
			a = answer{status: http.StatusOK, body: "ok"}
		}
		if a.block {
			<-req.Ctx.Done()
			return &chain.Response{Status: http.StatusBadGateway, UpstreamErr: req.Ctx.Err()}
		}
		if a.err != nil {
			return &chain.Response{Status: http.StatusBadGateway, UpstreamErr: a.err}
		}
		h := http.Header{}
		if a.location != "" {
			h.Set("Location", a.location)
		}
		return &chain.Response{Status: a.status, Header: h, Body: chain.BytesBody([]byte(a.body))}
	}
	e.router = &Router{
		Session: func(s *chain.Session) (*chain.Session, bool) {
			if !e.live {
				return nil, false
			}
			c := s.Clone()
			c.Claims = claims.Set{"repository": {"github.com/o/r"}}
			return c, true
		},
		Profile: func(name string) (*policy.Profile, bool) { return prof, name == "p" },
		Terminal: func(*policy.Service, int64) chain.Handler {
			return func(req *chain.Request) (*chain.Response, error) { return respond("service", req), nil }
		},
		Tunnel: func(_ *policy.Profile, req *chain.Request) (*chain.Response, error) {
			return respond("tunnel", req), nil
		},
		Audit: func(a audit.Entry) { e.audit = append(e.audit, a) },
	}
	return e
}

func parent(depth int) *chain.Request {
	u, _ := url.Parse("https://github.com/o/r.git/git-receive-pack")
	p := &chain.Request{Ctx: context.Background(), Transport: chain.TransportHTTP, Method: http.MethodPost, URL: u,
		Header: http.Header{}, Body: chain.BytesBody(nil), Session: &chain.Session{ID: "s1", Profile: "p", Claims: claims.Set{}}}
	if depth > 0 {
		p.Subrequest = &chain.SubrequestInfo{Filter: "outer", Depth: depth, Parent: "GET x"}
	}
	return p
}

func TestDo(t *testing.T) {
	type testCase struct {
		env       *env
		parent    *chain.Request
		spec      chain.SubrequestSpec
		wantErr   string
		wantURL   string
		status    int
		denied    string
		seen      []seen
		auditN    int
		auditDeny bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		p := tc.parent
		if p == nil {
			p = parent(0)
		}
		resp, u, err := tc.env.router.Do(p, "probe", tc.spec)
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		if tc.wantURL != "" {
			assert.Equal(t, tc.wantURL, u.String())
		}
		if tc.status != 0 {
			assert.Equal(t, tc.status, resp.Status)
		}
		if tc.denied != "" {
			require.NotNil(t, resp.Denial)
			assert.Contains(t, resp.Denial.Reason, tc.denied)
		} else {
			assert.Nil(t, resp.Denial)
		}
		if tc.seen != nil {
			require.Len(t, tc.env.seen, len(tc.seen))
			for i, want := range tc.seen {
				got := tc.env.seen[i]
				assert.Equal(t, want.via, got.via, "hop %d via", i)
				assert.Equal(t, want.method, got.method, "hop %d method", i)
				assert.Equal(t, want.url, got.url, "hop %d url", i)
				assert.Equal(t, want.body, got.body, "hop %d body", i)
				for k := range want.header {
					assert.Equal(t, want.header.Get(k), got.header.Get(k), "hop %d header %s", i, k)
				}
			}
		}
		if tc.auditN != 0 {
			require.Len(t, tc.env.audit, tc.auditN)
			for _, a := range tc.env.audit {
				require.NotNil(t, a.Subrequest)
				assert.Equal(t, "probe", a.Subrequest.Filter)
			}
		}
		if tc.auditDeny {
			require.NotEmpty(t, tc.env.audit)
			assert.Equal(t, audit.DecisionDeny, tc.env.audit[len(tc.env.audit)-1].Decision)
		}
	}

	t.Run("an intercepted host runs the service chain", func(t *testing.T) {
		var sawReq *chain.Request
		e := newEnv(config.UnmatchedDeny, filterFunc(func(req *chain.Request, next chain.Handler) (*chain.Response, error) {
			sawReq = req
			return next(req)
		}))
		tester(t, testCase{
			env:     e,
			spec:    chain.SubrequestSpec{URL: "https://api.github.com:443/repos/o/r/rules/branches/main#x", Header: http.Header{"Accept": {"application/json"}}},
			wantURL: "https://api.github.com/repos/o/r/rules/branches/main",
			status:  http.StatusOK,
			seen:    []seen{{via: "service", method: http.MethodGet, url: "https://api.github.com/repos/o/r/rules/branches/main", header: http.Header{"Accept": {"application/json"}}}},
			auditN:  1,
		})
		require.NotNil(t, sawReq)
		assert.Equal(t, "github", sawReq.Service)
		assert.Equal(t, &chain.SubrequestInfo{Filter: "probe", Depth: 1, Parent: "POST github.com/o/r.git/git-receive-pack"}, sawReq.Subrequest)
		assert.Equal(t, claims.Set{"repository": {"github.com/o/r"}}, sawReq.Session.Claims, "a subrequest reads the session's live claims")
		assert.Equal(t, "github", e.audit[0].Service)
		assert.Equal(t, audit.DecisionAllow, e.audit[0].Decision)
	})
	t.Run("a service filter can deny a subrequest", func(t *testing.T) {
		tester(t, testCase{
			env: newEnv(config.UnmatchedDeny, filterFunc(func(*chain.Request, chain.Handler) (*chain.Response, error) {
				return chain.Deny("guard", "no"), nil
			})),
			spec:      chain.SubrequestSpec{URL: "https://api.github.com/x"},
			denied:    "no",
			auditDeny: true,
		})
	})
	t.Run("an empty path becomes slash", func(t *testing.T) {
		tester(t, testCase{
			env:  newEnv(config.UnmatchedDeny),
			spec: chain.SubrequestSpec{URL: "https://api.github.com"},
			seen: []seen{{via: "service", method: http.MethodGet, url: "https://api.github.com/"}},
		})
	})
	t.Run("a dot segment is denied like an agent request", func(t *testing.T) {
		tester(t, testCase{
			env:    newEnv(config.UnmatchedDeny),
			spec:   chain.SubrequestSpec{URL: "https://api.github.com/a/%2e%2e/b"},
			status: http.StatusBadRequest,
			denied: "dot segment",
		})
	})
	t.Run("an unmatched host is denied under unmatched deny", func(t *testing.T) {
		tester(t, testCase{
			env:       newEnv(config.UnmatchedDeny),
			spec:      chain.SubrequestSpec{URL: "https://hooks.example.com/x"},
			status:    http.StatusForbidden,
			denied:    "host not allowed by profile p",
			auditDeny: true,
		})
	})
	t.Run("an unmatched host is tunneled under unmatched tunnel", func(t *testing.T) {
		e := newEnv(config.UnmatchedTunnel)
		tester(t, testCase{
			env:  e,
			spec: chain.SubrequestSpec{URL: "https://hooks.example.com/x", Method: http.MethodPost, Body: []byte("hi")},
			seen: []seen{{via: "tunnel", method: http.MethodPost, url: "https://hooks.example.com/x", body: "hi"}},
		})
		assert.Equal(t, audit.DecisionTunnel, e.audit[0].Decision)
	})
	t.Run("depth past the cap rejects", func(t *testing.T) {
		tester(t, testCase{
			env:     newEnv(config.UnmatchedDeny),
			parent:  parent(chain.MaxSubrequestDepth),
			spec:    chain.SubrequestSpec{URL: "https://api.github.com/x"},
			wantErr: "subrequest: depth 5 exceeds limit 4",
		})
	})
	t.Run("depth grows from the parent", func(t *testing.T) {
		var got *chain.SubrequestInfo
		tester(t, testCase{
			env: newEnv(config.UnmatchedDeny, filterFunc(func(req *chain.Request, next chain.Handler) (*chain.Response, error) {
				got = req.Subrequest
				return next(req)
			})),
			parent: parent(3),
			spec:   chain.SubrequestSpec{URL: "https://api.github.com/x"},
		})
		require.NotNil(t, got)
		assert.Equal(t, 4, got.Depth)
	})
	t.Run("redirects are followed through the chain", func(t *testing.T) {
		e := newEnv(config.UnmatchedTunnel)
		e.answers["https://api.github.com/repos/old/r"] = answer{status: http.StatusMovedPermanently, location: "/repositories/1"}
		e.answers["https://api.github.com/repositories/1"] = answer{status: http.StatusTemporaryRedirect, location: "https://objects.example.com/blob"}
		tester(t, testCase{
			env: e,
			spec: chain.SubrequestSpec{URL: "https://api.github.com/repos/old/r",
				Header: http.Header{"Authorization": {"Bearer x"}, "Accept": {"a/b"}}},
			wantURL: "https://objects.example.com/blob",
			status:  http.StatusOK,
			seen: []seen{
				{via: "service", method: http.MethodGet, url: "https://api.github.com/repos/old/r", header: http.Header{"Authorization": {"Bearer x"}}},
				{via: "service", method: http.MethodGet, url: "https://api.github.com/repositories/1", header: http.Header{"Authorization": {"Bearer x"}}},
				{via: "tunnel", method: http.MethodGet, url: "https://objects.example.com/blob", header: http.Header{"Authorization": nil, "Accept": {"a/b"}}},
			},
			auditN: 3,
		})
	})
	t.Run("303 after a POST becomes a GET without a body", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		e.answers["https://api.github.com/a"] = answer{status: http.StatusSeeOther, location: "/b"}
		tester(t, testCase{
			env:  e,
			spec: chain.SubrequestSpec{URL: "https://api.github.com/a", Method: http.MethodPost, Body: []byte("x")},
			seen: []seen{
				{via: "service", method: http.MethodPost, url: "https://api.github.com/a", body: "x"},
				{via: "service", method: http.MethodGet, url: "https://api.github.com/b"},
			},
		})
	})
	t.Run("308 resends the method and body", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		e.answers["https://api.github.com/a"] = answer{status: http.StatusPermanentRedirect, location: "/b"}
		tester(t, testCase{
			env:  e,
			spec: chain.SubrequestSpec{URL: "https://api.github.com/a", Method: http.MethodPut, Body: []byte("x")},
			seen: []seen{
				{via: "service", method: http.MethodPut, url: "https://api.github.com/a", body: "x"},
				{via: "service", method: http.MethodPut, url: "https://api.github.com/b", body: "x"},
			},
		})
	})
	t.Run("manual returns the redirect", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		e.answers["https://api.github.com/a"] = answer{status: http.StatusFound, location: "/b"}
		tester(t, testCase{
			env:     e,
			spec:    chain.SubrequestSpec{URL: "https://api.github.com/a", Manual: true},
			wantURL: "https://api.github.com/a",
			status:  http.StatusFound,
			seen:    []seen{{via: "service", method: http.MethodGet, url: "https://api.github.com/a"}},
		})
	})
	t.Run("too many redirects rejects", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		e.answers["https://api.github.com/loop"] = answer{status: http.StatusFound, location: "/loop"}
		tester(t, testCase{
			env:     e,
			spec:    chain.SubrequestSpec{URL: "https://api.github.com/loop"},
			wantErr: "subrequest: stopped after 5 redirects",
		})
		assert.Len(t, e.seen, chain.MaxSubrequestRedirects+1)
	})
	t.Run("a redirect to another scheme rejects", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		e.answers["https://api.github.com/a"] = answer{status: http.StatusFound, location: "ftp://x/y"}
		tester(t, testCase{
			env:     e,
			spec:    chain.SubrequestSpec{URL: "https://api.github.com/a"},
			wantErr: `redirect to unsupported scheme "ftp"`,
		})
	})
	t.Run("an upstream failure rejects", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		e.answers["https://api.github.com/a"] = answer{err: errors.New("connection refused")}
		tester(t, testCase{
			env:     e,
			spec:    chain.SubrequestSpec{URL: "https://api.github.com/a"},
			wantErr: "connection refused",
			auditN:  1,
		})
		assert.Equal(t, audit.DecisionError, e.audit[0].Decision)
	})
	t.Run("a timeout rejects", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		e.answers["https://api.github.com/slow"] = answer{block: true}
		start := time.Now()
		tester(t, testCase{
			env:     e,
			spec:    chain.SubrequestSpec{URL: "https://api.github.com/slow", Timeout: 50 * time.Millisecond},
			wantErr: "deadline exceeded",
		})
		assert.Less(t, time.Since(start), 5*time.Second)
	})
	t.Run("a cancelled parent rejects", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		e.answers["https://api.github.com/slow"] = answer{block: true}
		p := parent(0)
		ctx, cancel := context.WithCancel(context.Background())
		p.Ctx = ctx
		cancel()
		tester(t, testCase{
			env:     e,
			parent:  p,
			spec:    chain.SubrequestSpec{URL: "https://api.github.com/slow"},
			wantErr: "context canceled",
		})
	})
	t.Run("an ended session rejects", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		e.live = false
		tester(t, testCase{
			env:     e,
			spec:    chain.SubrequestSpec{URL: "https://api.github.com/a"},
			wantErr: "session is no longer valid",
		})
	})
	t.Run("invalid input rejects", func(t *testing.T) {
		for _, c := range []struct {
			spec chain.SubrequestSpec
			want string
		}{
			{chain.SubrequestSpec{URL: "/relative"}, "must be http or https"},
			{chain.SubrequestSpec{URL: "ftp://x/y"}, "must be http or https"},
			{chain.SubrequestSpec{URL: "https://u:p@api.github.com/"}, "must not carry user info"}, //nolint:gosec // not a credential
			{chain.SubrequestSpec{URL: "https://api.github.com/", Method: "get"}, "non-canonical method"},
			{chain.SubrequestSpec{URL: "https://api.github.com/", Method: "CONNECT"}, "method CONNECT is not allowed"},
		} {
			tester(t, testCase{env: newEnv(config.UnmatchedDeny), spec: c.spec, wantErr: c.want})
		}
	})
	t.Run("hop headers are dropped", func(t *testing.T) {
		e := newEnv(config.UnmatchedDeny)
		tester(t, testCase{
			env:  e,
			spec: chain.SubrequestSpec{URL: "https://api.github.com/a", Header: http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}}},
		})
		assert.Empty(t, e.seen[0].header.Get("Upgrade"))
		assert.Empty(t, e.seen[0].header.Get("Connection"))
	})
}

func TestReleaseOnClose(t *testing.T) {
	t.Run("closing a streamed body cancels the context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		pr, pw := io.Pipe()
		resp := releaseOnClose(&chain.Response{Status: 200, Body: chain.NewBody(pr)}, cancel)
		go func() {
			_, _ = pw.Write([]byte("data"))
			_ = pw.Close()
		}()
		b, err := resp.Body.ReadAll()
		require.NoError(t, err)
		assert.Equal(t, "data", string(b))
		require.NoError(t, ctx.Err(), "the context lives until the body is closed")
		require.NoError(t, resp.Body.Close())
		assert.Error(t, ctx.Err())
	})
	t.Run("a body in memory cancels at once", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		releaseOnClose(&chain.Response{Status: 200, Body: chain.BytesBody([]byte("x"))}, cancel)
		assert.Error(t, ctx.Err())
	})
}
