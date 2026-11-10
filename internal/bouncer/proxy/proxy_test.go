package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/audit"
	"github.com/pastdev/agentcon/internal/bouncer/ca"
	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeBackend struct {
	set      *policy.Set
	sessions map[string]*chain.Session
}

func (b *fakeBackend) Session(token string) (*chain.Session, bool) {
	s, ok := b.sessions[token]
	return s, ok
}
func (b *fakeBackend) Profile(name string) (*policy.Profile, bool) {
	p, ok := b.set.Profiles[name]
	return p, ok
}
func (b *fakeBackend) Control() http.Handler { return http.NotFoundHandler() }

type env struct {
	upstream *httptest.Server
	proxy    *httptest.Server
	client   *http.Client
	audit    []audit.Entry
	port     string
	backend  *fakeBackend
}

func setup(t *testing.T, profileYAML string) *env {
	t.Helper()
	e := &env{}
	e.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upgrade" {
			conn, buf, _ := http.NewResponseController(w).Hijack()
			_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
			_ = buf.Flush()
			_, _ = io.Copy(conn, buf)
			_ = conn.Close()
			return
		}
		if r.URL.Path == "/redirect" {
			// Echo the URL (query included) back to the client.
			http.Redirect(w, r, "/new?"+r.URL.RawQuery, http.StatusMovedPermanently) //nolint:gosec // test upstream echoes the request on purpose
			return
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "widget=%s auth=%s private=%s path=%s query=%s body=%s", r.Header.Get("X-Widget-Key"), r.Header.Get("Authorization"), r.Header.Get("Private-Token"), r.URL.EscapedPath(), r.URL.RawQuery, body) //nolint:gosec // test upstream echoes the request on purpose
	}))
	t.Cleanup(e.upstream.Close)
	_, e.port, _ = net.SplitHostPort(e.upstream.Listener.Addr().String())

	t.Setenv("BOUNCER_TEST_TOKEN", "real-secret")
	// Patterns without a port mean :443; pin the test upstream's port.
	profileYAML = strings.ReplaceAll(profileYAML, "hosts: [localhost]", `hosts: ["localhost:`+e.port+`"]`)
	cfg, err := config.Parse([]byte(`
credentials:
  tok: {token: {source: env, env: BOUNCER_TEST_TOKEN}}
profiles:
`+profileYAML), t.TempDir()+"/config.yaml")
	require.NoError(t, err)
	set, err := policy.Compile(cfg, &chain.Env{}, nil)
	require.NoError(t, err)
	authority, err := ca.LoadOrCreate(t.TempDir())
	require.NoError(t, err)
	tr := NewTransport()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test upstream uses a self-signed certificate
	log, err := audit.Open("", func(en audit.Entry) { e.audit = append(e.audit, en) })
	require.NoError(t, err)
	e.backend = &fakeBackend{set: set, sessions: map[string]*chain.Session{"tok123": {ID: "s1", Profile: "p"}}}
	srv := &Server{
		Backend:   e.backend,
		CA:        authority,
		Creds:     creds.NewStore(cfg.Credentials),
		Audit:     log,
		Transport: tr,
		Dialer:    &net.Dialer{},
	}
	e.proxy = httptest.NewServer(srv)
	t.Cleanup(e.proxy.Close)

	roots := x509.NewCertPool()
	roots.AddCert(authority.Cert())
	roots.AddCert(e.upstream.Certificate())
	proxyURL, err := url.Parse(e.proxy.URL)
	require.NoError(t, err)
	proxyURL.User = url.UserPassword("bouncer", "tok123")
	e.client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	return e
}

func (e *env) get(t *testing.T, method, rawURL string, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader("payload"))
	require.NoError(t, err)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	require.NoError(t, err, "%s %s", method, rawURL)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

const scopedProfile = `
  p:
    unmatched: tunnel
    http:
      - name: api
        hosts: [localhost]
        credential: tok
        inject: {bearer: true}
        rules:
          - action: allow
            gitlab_project: group/proj
`

func TestIntercept(t *testing.T) {
	type testCase struct {
		e            *env
		method       string
		rawURL       string
		hdr          map[string]string
		wantStatus   int
		contains     []string
		notContains  []string
		wantCount    map[string]int
		clientGetErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		if tc.clientGetErr != "" {
			_, err := tc.e.client.Get(tc.rawURL)
			require.ErrorContains(t, err, tc.clientGetErr)
			return
		}
		status, body := tc.e.get(t, tc.method, tc.rawURL, tc.hdr)
		if tc.wantStatus != 0 {
			require.Equal(t, tc.wantStatus, status, body)
		}
		for _, s := range tc.contains {
			assert.Contains(t, body, s)
		}
		for _, s := range tc.notContains {
			assert.NotContains(t, body, s)
		}
		for s, n := range tc.wantCount {
			assert.Equal(t, n, strings.Count(body, s), "count of %q in %s", s, body)
		}
	}

	t.Run("injects credentials on allow and audits deny", func(t *testing.T) {
		e := setup(t, scopedProfile)
		base := "https://localhost:" + e.port
		status, body := e.get(t, "POST", base+"/api/v4/projects/group%2Fproj/issues?x=1", nil)
		assert.Equal(t, 200, status, body)
		assert.Contains(t, body, "auth=Bearer real-secret")
		assert.Contains(t, body, "path=/api/v4/projects/group%2Fproj/issues")
		assert.Contains(t, body, "body=payload")
		status, body = e.get(t, "GET", base+"/api/v4/projects/group%2Fother", nil)
		assert.Equal(t, 200, status, body)
		assert.NotContains(t, body, "real-secret")
		assert.Contains(t, body, "auth= ")
		status, _ = e.get(t, "GET", base+"/api/v4/projects/group%2Fproj/../../other", nil)
		assert.Equal(t, 400, status, "dot-segment path")
		var decisions []string
		for _, a := range e.audit {
			decisions = append(decisions, a.Decision)
		}
		assert.Equal(t, []string{"allow", "allow", "deny"}, decisions)
	})
	t.Run("strips placeholders on an unmatched path", func(t *testing.T) {
		e := setup(t, scopedProfile)
		ph := config.Placeholder("tok")
		tester(t, testCase{
			e:           e,
			method:      "GET",
			rawURL:      "https://localhost:" + e.port + "/api/v4/projects/group%2Fother",
			hdr:         map[string]string{"Authorization": "Bearer " + ph, "Private-Token": ph},
			wantStatus:  200,
			notContains: []string{"real-secret", ph},
			contains:    []string{"auth= ", "private= "},
		})
	})
	t.Run("denies an unmatched path when the profile denies", func(t *testing.T) {
		e := setup(t, strings.Replace(scopedProfile, "unmatched: tunnel", "unmatched: deny", 1))
		tester(t, testCase{
			e:           e,
			method:      "GET",
			rawURL:      "https://localhost:" + e.port + "/api/v4/projects/group%2Fother",
			wantStatus:  403,
			contains:    []string{"denied by rules:api"},
			notContains: []string{"real-secret"},
		})
	})
	t.Run("denies an unmatched path when default is deny", func(t *testing.T) {
		e := setup(t, `
  p:
    unmatched: tunnel
    http:
      - name: api
        hosts: [localhost]
        credential: tok
        inject: {bearer: true}
        default: deny
        rules:
          - action: allow
            gitlab_project: group/proj
`)
		tester(t, testCase{
			e:          e,
			method:     "GET",
			rawURL:     "https://localhost:" + e.port + "/api/v4/projects/group%2Fother",
			wantStatus: 403,
			contains:   []string{"denied by rules:api"},
		})
	})
	t.Run("replaces placeholders only in auth headers", func(t *testing.T) {
		e := setup(t, `
  p:
    http:
      - name: api
        hosts: [localhost]
        credential: tok
`)
		ph := config.Placeholder("tok")
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:"+ph))
		wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:real-secret"))
		tester(t, testCase{
			e:      e,
			method: "GET",
			rawURL: "https://localhost:" + e.port + "/x?title=" + ph,
			hdr:    map[string]string{"Authorization": basic, "Private-Token": ph, "X-Widget-Key": ph},
			contains: []string{
				"auth=" + wantBasic,
				"private=real-secret",
				"query=title=" + ph,
				"widget=" + ph,
			},
			wantCount: map[string]int{"real-secret": 1},
		})
	})
	t.Run("injects a query parameter", func(t *testing.T) {
		e := setup(t, `
  p:
    http:
      - name: api
        hosts: [localhost]
        credential: tok
        inject: {query: api_key}
`)
		tester(t, testCase{
			e:        e,
			method:   "GET",
			rawURL:   "https://localhost:" + e.port + "/x?a=1",
			contains: []string{"api_key=real-secret", "a=1"},
		})
	})
	t.Run("tunnels an unmatched public-shaped loopback when allow_private is set", func(t *testing.T) {
		e := setup(t, strings.Replace(scopedProfile, "unmatched: tunnel", "unmatched: tunnel\n    allow_private: true", 1))
		tester(t, testCase{
			e:          e,
			method:     "GET",
			rawURL:     "https://127.0.0.1:" + e.port + "/anything",
			wantStatus: 200,
			contains:   []string{"auth= "},
		})
	})
	t.Run("refuses CONNECT when unmatched is deny", func(t *testing.T) {
		e := setup(t, strings.Replace(scopedProfile, "unmatched: tunnel", "unmatched: deny", 1))
		tester(t, testCase{
			e:            e,
			rawURL:       "https://127.0.0.1:" + e.port + "/anything",
			clientGetErr: "Forbidden",
		})
	})
	t.Run("refuses CONNECT to loopback by default", func(t *testing.T) {
		e := setup(t, scopedProfile)
		tester(t, testCase{
			e:            e,
			rawURL:       "https://127.0.0.1:" + e.port + "/",
			clientGetErr: "Forbidden",
		})
	})
	t.Run("refuses plain http forwarding to loopback", func(t *testing.T) {
		e := setup(t, scopedProfile)
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "reached") }))
		t.Cleanup(plain.Close)
		tester(t, testCase{
			e:           e,
			method:      "GET",
			rawURL:      plain.URL + "/",
			wantStatus:  403,
			notContains: []string{"reached"},
		})
	})
	t.Run("requires a session token", func(t *testing.T) {
		e := setup(t, scopedProfile)
		proxyURL, err := url.Parse(e.proxy.URL)
		require.NoError(t, err)
		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
		_, err = c.Get("https://localhost:" + e.port + "/")
		require.ErrorContains(t, err, "Proxy Authentication Required")
	})
	t.Run("does not inject credentials over plain http unless insecure", func(t *testing.T) {
		var gotAuth []string
		plain := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		}))
		t.Cleanup(plain.Close)
		_, port, err := net.SplitHostPort(plain.Listener.Addr().String())
		require.NoError(t, err)
		e := setup(t, `
  p:
    allow_private: true
    http:
      - name: api
        hosts: ["127.0.0.1:`+port+`"]
        credential: tok
        inject: {bearer: true}
      - name: dev
        hosts: ["localhost:`+port+`"]
        credential: tok
        insecure: true
        inject: {bearer: true}
`)
		status, _ := e.get(t, "GET", plain.URL+"/x", nil)
		require.Equal(t, 403, status, "plain HTTP to a credentialed service")
		e.get(t, "GET", "http://localhost:"+port+"/x", nil)
		assert.Equal(t, []string{"Bearer real-secret"}, gotAuth)
	})
	t.Run("hides credential error details from the agent", func(t *testing.T) {
		e := setup(t, scopedProfile)
		t.Setenv("BOUNCER_TEST_TOKEN", "")
		_ = os.Unsetenv("BOUNCER_TEST_TOKEN")
		_, body := e.get(t, "GET", "https://localhost:"+e.port+"/api/v4/projects/group%2Fproj", nil)
		assert.Contains(t, body, "unavailable; see the bouncer log")
		assert.NotContains(t, body, "BOUNCER_TEST_TOKEN")
	})
	t.Run("serves reverse mode with a session token", func(t *testing.T) {
		e := setup(t, scopedProfile)
		resp, err := http.Get(e.proxy.URL + "/s/tok123/localhost:" + e.port + "/api/v4/projects/group%2Fproj")
		require.NoError(t, err)
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, 200, resp.StatusCode)
		assert.Contains(t, string(b), "auth=Bearer real-secret")
		assert.Contains(t, string(b), "path=/api/v4/projects/group%2Fproj")
		resp, err = http.Get(e.proxy.URL + "/s/wrong/localhost:" + e.port + "/x")
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode, "bad token")
	})
	t.Run("refuses upgrade on a credentialed service", func(t *testing.T) {
		e := setup(t, `
  p:
    http:
      - name: api
        hosts: [localhost]
        credential: tok
`)
		tester(t, testCase{
			e:          e,
			method:     "GET",
			rawURL:     "https://localhost:" + e.port + "/upgrade",
			hdr:        map[string]string{"Connection": "Upgrade", "Upgrade": "echo"},
			wantStatus: 403,
			contains:   []string{"allow_upgrade"},
		})
	})
	t.Run("refuses an unrequested upstream upgrade", func(t *testing.T) {
		e := setup(t, `
  p:
    http:
      - name: api
        hosts: [localhost]
        credential: tok
        allow_upgrade: true
`)
		status, _ := e.get(t, "GET", "https://localhost:"+e.port+"/upgrade", nil)
		assert.NotEqual(t, http.StatusSwitchingProtocols, status, "spliced an unrequested upgrade")
	})
	t.Run("passes an upgrade through an uncredentialed service", func(t *testing.T) {
		e := setup(t, `
  p:
    http:
      - name: api
        hosts: [localhost]
`)
		req, err := http.NewRequest("GET", "https://localhost:"+e.port+"/upgrade", nil)
		require.NoError(t, err)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "echo")
		resp, err := e.client.Do(req)
		require.NoError(t, err)
		require.Equal(t, 101, resp.StatusCode)
		rwc := resp.Body.(io.ReadWriteCloser)
		_, err = rwc.Write([]byte("ping"))
		require.NoError(t, err)
		buf := make([]byte, 4)
		_, err = io.ReadFull(rwc, buf)
		require.NoError(t, err)
		assert.Equal(t, "ping", string(buf))
		_ = rwc.Close()
	})
	t.Run("preserves a malformed query and scrubs secrets from redirects", func(t *testing.T) {
		e := setup(t, `
  p:
    http:
      - name: api
        hosts: [localhost]
        credential: tok
        inject: {query: api_key}
`)
		_, body := e.get(t, "GET", "https://localhost:"+e.port+"/x?a=1;b=2&q=%2B", nil)
		assert.Contains(t, body, "query=a=1;b=2&q=%2B&api_key=real-secret")
		req, err := http.NewRequest("GET", "https://localhost:"+e.port+"/redirect?a=1", nil)
		require.NoError(t, err)
		e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := e.client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.NotContains(t, resp.Header.Get("Location"), "real-secret")
	})
	t.Run("stops a live tunnel after session revocation", func(t *testing.T) {
		e := setup(t, scopedProfile)
		base := "https://localhost:" + e.port
		status, _ := e.get(t, "GET", base+"/api/v4/projects/group%2Fproj", nil)
		require.Equal(t, 200, status, "first request")
		delete(e.backend.sessions, "tok123")
		status, _ = e.get(t, "GET", base+"/api/v4/projects/group%2Fproj", nil)
		assert.Equal(t, http.StatusProxyAuthRequired, status, "after revocation")
	})
}

func TestInject(t *testing.T) {
	type testCase struct {
		spec   *config.Inject
		secret creds.Secret
		want   string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		h := http.Header{}
		u, err := url.Parse("https://example.com/")
		require.NoError(t, err)
		Inject(h, u, "login", tc.spec, tc.secret)
		assert.Equal(t, tc.want, h.Get("Authorization"))
	}

	t.Run("uses the username slot for basic auth", func(t *testing.T) {
		tester(t, testCase{
			spec:   &config.Inject{Basic: &config.BasicInject{}},
			secret: creds.Secret{Username: "alice", Password: "s3cret"},
			want:   "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret")),
		})
	})
	t.Run("uses an override username with a token", func(t *testing.T) {
		tester(t, testCase{
			spec:   &config.Inject{Basic: &config.BasicInject{Username: "oauth2"}},
			secret: creds.Secret{Username: "alice", Token: "pat"},
			want:   "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:pat")),
		})
	})
}

func TestStripPlaceholder(t *testing.T) {
	type testCase struct{}
	tester := func(t *testing.T, _ testCase) {
		t.Helper()
		ph := config.Placeholder("tok")
		h := http.Header{}
		h.Set("Authorization", "Bearer "+ph)
		h.Set("Private-Token", ph)
		h.Set("X-Other", "keep")
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:"+ph))
		h.Add("Authorization", basic)
		u, err := url.Parse("https://example.com/x?api_key=" + ph + "&ok=1")
		require.NoError(t, err)
		stripPlaceholder(h, u, "tok", &config.Inject{Query: "api_key"})
		assert.Empty(t, h.Get("Authorization"))
		assert.Empty(t, h.Get("Private-Token"))
		assert.Equal(t, "keep", h.Get("X-Other"))
		assert.Empty(t, u.Query().Get("api_key"))
		assert.Equal(t, "1", u.Query().Get("ok"))
	}

	t.Run("strips placeholders from auth headers and the inject query", func(t *testing.T) {
		tester(t, testCase{})
	})
}

func TestNonPublic(t *testing.T) {
	type testCase struct {
		ip   string
		want bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, nonPublic(net.ParseIP(tc.ip)), "non-public")
	}

	t.Run("flags loopback ipv4", func(t *testing.T) {
		tester(t, testCase{ip: "127.0.0.1", want: true})
	})
	t.Run("flags a private 10/8 address", func(t *testing.T) {
		tester(t, testCase{ip: "10.1.2.3", want: true})
	})
	t.Run("flags a private 192.168/16 address", func(t *testing.T) {
		tester(t, testCase{ip: "192.168.1.1", want: true})
	})
	t.Run("flags a link-local address", func(t *testing.T) {
		tester(t, testCase{ip: "169.254.169.254", want: true})
	})
	t.Run("flags a cgnat address", func(t *testing.T) {
		tester(t, testCase{ip: "100.100.1.1", want: true})
	})
	t.Run("flags loopback ipv6", func(t *testing.T) {
		tester(t, testCase{ip: "::1", want: true})
	})
	t.Run("flags a link-local ipv6 address", func(t *testing.T) {
		tester(t, testCase{ip: "fe80::1", want: true})
	})
	t.Run("flags unspecified ipv4", func(t *testing.T) {
		tester(t, testCase{ip: "0.0.0.0", want: true})
	})
	t.Run("flags a this-network address", func(t *testing.T) {
		tester(t, testCase{ip: "0.1.2.3", want: true})
	})
	t.Run("flags an ietf protocol assignment", func(t *testing.T) {
		tester(t, testCase{ip: "192.0.0.170", want: true})
	})
	t.Run("flags a benchmarking address", func(t *testing.T) {
		tester(t, testCase{ip: "198.19.0.1", want: true})
	})
	t.Run("flags a reserved class e address", func(t *testing.T) {
		tester(t, testCase{ip: "240.0.0.1", want: true})
	})
	t.Run("flags limited broadcast", func(t *testing.T) {
		tester(t, testCase{ip: "255.255.255.255", want: true})
	})
	t.Run("flags nat64 of a metadata endpoint", func(t *testing.T) {
		tester(t, testCase{ip: "64:ff9b::a9fe:a9fe", want: true})
	})
	t.Run("flags nat64 of loopback", func(t *testing.T) {
		tester(t, testCase{ip: "64:ff9b::7f00:1", want: true})
	})
	t.Run("accepts nat64 of a public address", func(t *testing.T) {
		tester(t, testCase{ip: "64:ff9b::808:808", want: false})
	})
	t.Run("flags local-use nat64", func(t *testing.T) {
		tester(t, testCase{ip: "64:ff9b:1::808:808", want: true})
	})
	t.Run("accepts a public ipv6 address", func(t *testing.T) {
		tester(t, testCase{ip: "2001:4860:4860::8888", want: false})
	})
	t.Run("accepts a public address", func(t *testing.T) {
		tester(t, testCase{ip: "140.82.112.3", want: false})
	})
}
