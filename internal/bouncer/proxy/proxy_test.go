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
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.Compile(cfg, &chain.Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTransport()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test upstream uses a self-signed certificate
	log, err := audit.Open("", func(en audit.Entry) { e.audit = append(e.audit, en) })
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("bouncer", "tok123")
	e.client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	return e
}

func (e *env) get(t *testing.T, method, rawURL string, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
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
			if err == nil || !strings.Contains(err.Error(), tc.clientGetErr) {
				t.Fatalf("expected %s, got %v", tc.clientGetErr, err)
			}
			return
		}
		status, body := tc.e.get(t, tc.method, tc.rawURL, tc.hdr)
		if tc.wantStatus != 0 && status != tc.wantStatus {
			t.Fatalf("%d %s", status, body)
		}
		for _, s := range tc.contains {
			if !strings.Contains(body, s) {
				t.Fatalf("%d %s", status, body)
			}
		}
		for _, s := range tc.notContains {
			if strings.Contains(body, s) {
				t.Fatalf("%d %s", status, body)
			}
		}
		for s, n := range tc.wantCount {
			if strings.Count(body, s) != n {
				t.Fatalf("%s", body)
			}
		}
	}

	t.Run("injects credentials on allow and audits deny", func(t *testing.T) {
		e := setup(t, scopedProfile)
		base := "https://localhost:" + e.port
		status, body := e.get(t, "POST", base+"/api/v4/projects/group%2Fproj/issues?x=1", nil)
		if status != 200 || !strings.Contains(body, "auth=Bearer real-secret") || !strings.Contains(body, "path=/api/v4/projects/group%2Fproj/issues") || !strings.Contains(body, "body=payload") {
			t.Fatalf("allowed request: %d %s", status, body)
		}
		status, body = e.get(t, "GET", base+"/api/v4/projects/group%2Fother", nil)
		if status != 200 || strings.Contains(body, "real-secret") || !strings.Contains(body, "auth= ") {
			t.Fatalf("unmatched path should forward without credential: %d %s", status, body)
		}
		status, _ = e.get(t, "GET", base+"/api/v4/projects/group%2Fproj/../../other", nil)
		if status != 400 {
			t.Fatalf("dot-segment path: %d", status)
		}
		var decisions []string
		for _, a := range e.audit {
			decisions = append(decisions, a.Decision)
		}
		if strings.Join(decisions, ",") != "allow,allow,deny" {
			t.Errorf("audit decisions: %v", decisions)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
		_, err = c.Get("https://localhost:" + e.port + "/")
		if err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Fatalf("expected 407, got %v", err)
		}
	})
	t.Run("does not inject credentials over plain http unless insecure", func(t *testing.T) {
		var gotAuth []string
		plain := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		}))
		t.Cleanup(plain.Close)
		_, port, err := net.SplitHostPort(plain.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
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
		if status != 403 {
			t.Fatalf("plain HTTP to a credentialed service: %d", status)
		}
		e.get(t, "GET", "http://localhost:"+port+"/x", nil)
		if len(gotAuth) != 1 || gotAuth[0] != "Bearer real-secret" {
			t.Fatalf("insecure: true should allow injection; upstream saw %q", gotAuth)
		}
	})
	t.Run("hides credential error details from the agent", func(t *testing.T) {
		e := setup(t, scopedProfile)
		t.Setenv("BOUNCER_TEST_TOKEN", "")
		_ = os.Unsetenv("BOUNCER_TEST_TOKEN")
		_, body := e.get(t, "GET", "https://localhost:"+e.port+"/api/v4/projects/group%2Fproj", nil)
		if !strings.Contains(body, "unavailable; see the bouncer log") || strings.Contains(body, "BOUNCER_TEST_TOKEN") {
			t.Fatalf("agent saw credential error details: %s", body)
		}
	})
	t.Run("serves reverse mode with a session token", func(t *testing.T) {
		e := setup(t, scopedProfile)
		resp, err := http.Get(e.proxy.URL + "/s/tok123/localhost:" + e.port + "/api/v4/projects/group%2Fproj")
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), "auth=Bearer real-secret") || !strings.Contains(string(b), "path=/api/v4/projects/group%2Fproj") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		resp, err = http.Get(e.proxy.URL + "/s/wrong/localhost:" + e.port + "/x")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 401 {
			t.Fatalf("bad token: %d", resp.StatusCode)
		}
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
		if status == http.StatusSwitchingProtocols {
			t.Fatalf("spliced an unrequested upgrade: %d", status)
		}
	})
	t.Run("passes an upgrade through an uncredentialed service", func(t *testing.T) {
		e := setup(t, `
  p:
    http:
      - name: api
        hosts: [localhost]
`)
		req, err := http.NewRequest("GET", "https://localhost:"+e.port+"/upgrade", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "echo")
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 101 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		rwc := resp.Body.(io.ReadWriteCloser)
		_, err = rwc.Write([]byte("ping"))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(rwc, buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf) != "ping" {
			t.Fatalf("echo: %q", buf)
		}
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
		if !strings.Contains(body, "query=a=1;b=2&q=%2B&api_key=real-secret") {
			t.Fatalf("query mangled: %s", body)
		}
		req, err := http.NewRequest("GET", "https://localhost:"+e.port+"/redirect?a=1", nil)
		if err != nil {
			t.Fatal(err)
		}
		e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if loc := resp.Header.Get("Location"); strings.Contains(loc, "real-secret") {
			t.Fatalf("secret leaked in Location: %q", loc)
		}
	})
	t.Run("stops a live tunnel after session revocation", func(t *testing.T) {
		e := setup(t, scopedProfile)
		base := "https://localhost:" + e.port
		if status, _ := e.get(t, "GET", base+"/api/v4/projects/group%2Fproj", nil); status != 200 {
			t.Fatalf("first request: %d", status)
		}
		delete(e.backend.sessions, "tok123")
		if status, _ := e.get(t, "GET", base+"/api/v4/projects/group%2Fproj", nil); status != http.StatusProxyAuthRequired {
			t.Fatalf("after revocation the tunnel still served: %d", status)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		Inject(h, u, "login", tc.spec, tc.secret)
		if got := h.Get("Authorization"); got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		stripPlaceholder(h, u, "tok", &config.Inject{Query: "api_key"})
		if h.Get("Authorization") != "" || h.Get("Private-Token") != "" {
			t.Fatalf("headers %v", h)
		}
		if h.Get("X-Other") != "keep" {
			t.Fatalf("stripped unrelated header")
		}
		if u.Query().Get("api_key") != "" || u.Query().Get("ok") != "1" {
			t.Fatalf("query %q", u.RawQuery)
		}
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
		if nonPublic(net.ParseIP(tc.ip)) != tc.want {
			if tc.want {
				t.Errorf("%s should be non-public", tc.ip)
			} else {
				t.Error("public address flagged")
			}
		}
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
	t.Run("accepts a public address", func(t *testing.T) {
		tester(t, testCase{ip: "140.82.112.3", want: false})
	})
}
