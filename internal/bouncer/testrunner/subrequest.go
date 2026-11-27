package testrunner

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/credinject"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
	"github.com/pastdev/agentcon/internal/bouncer/signer"
	"github.com/pastdev/agentcon/internal/bouncer/subreq"
)

const schemeHTTP = "http"

// subrequests answers a step's subrequests from its fixtures and records
// what the fixtures saw.
type subrequests struct {
	fixtures   []SubrequestFixture
	keys       []string
	seen       []*fixtureSeen
	unexpected []string
}

// fixtureSeen is what a fixture received. It records the last call.
type fixtureSeen struct {
	header      http.Header
	credentials []string
}

// router routes subrequests the way the daemon does. With a policy, they
// run through the profile's chains, and fixtures stand in for upstreams
// and tunnels. Without one, a filter spec's subrequests go straight to the
// fixtures.
func (s *subrequests) router(profiles func(string) (*policy.Profile, bool), lookup credinject.Lookup, cl *scriptedClaims) *subreq.Router {
	r := &subreq.Router{
		// Like the daemon, a subrequest sees the session's claims as they
		// are now.
		Session: func(sess *chain.Session) (*chain.Session, bool) {
			live := sess.Clone()
			live.Claims = cl.set.Clone()
			return live, true
		},
	}
	if profiles == nil {
		r.Direct = func(req *chain.Request) (*chain.Response, error) { return s.answer(req, nil), nil }
		return r
	}
	r.Profile = profiles
	r.Terminal = func(svc *policy.Service, _ int64) chain.Handler {
		if svc.Config.Signer != nil {
			return signer.Terminal(svc.Config, testSigner{}, zerolog.Nop())
		}
		return func(req *chain.Request) (*chain.Response, error) {
			return s.answer(req, planCredentials(svc.Config, req, lookup)), nil
		}
	}
	r.Tunnel = func(_ *policy.Profile, req *chain.Request) (*chain.Response, error) {
		return s.answer(req, nil), nil
	}
	return r
}

// reset starts a step with its fixtures. They were checked before the case
// ran.
func (s *subrequests) reset(fixtures []SubrequestFixture) {
	s.fixtures = fixtures
	s.keys = make([]string, len(fixtures))
	s.seen = make([]*fixtureSeen, len(fixtures))
	s.unexpected = nil
	for i, f := range fixtures {
		s.keys[i], _ = fixtureKey(f.Method, f.URL)
	}
}

// answer is the upstream response to req from its fixture.
func (s *subrequests) answer(req *chain.Request, credentials []string) *chain.Response {
	key, _ := fixtureKey(req.Method, req.URL.String())
	for i, f := range s.fixtures {
		if s.keys[i] != key {
			continue
		}
		s.seen[i] = &fixtureSeen{header: req.Header.Clone(), credentials: credentials}
		if f.Error != "" {
			return &chain.Response{Status: http.StatusBadGateway, Header: http.Header{}, Body: chain.BytesBody(nil), UpstreamErr: errors.New(f.Error)}
		}
		h := http.Header{}
		for k, v := range f.Headers {
			h.Set(k, v)
		}
		status := f.Status
		if status == 0 {
			status = http.StatusOK
		}
		return &chain.Response{Status: status, Header: h, Body: chain.BytesBody([]byte(f.Body))}
	}
	s.unexpected = append(s.unexpected, key)
	return &chain.Response{Status: http.StatusBadGateway, Header: http.Header{}, Body: chain.BytesBody(nil),
		UpstreamErr: errors.New("unexpected subrequest " + key)}
}

// problems lists what the step's subrequests did wrong.
func (s *subrequests) problems() []string {
	var out []string
	for _, key := range s.unexpected {
		out = append(out, "unexpected subrequest "+key)
	}
	for i, f := range s.fixtures {
		seen := s.seen[i]
		if seen == nil {
			out = append(out, "subrequest fixture "+s.keys[i]+" was not used")
			continue
		}
		for k, v := range f.ExpectHeader {
			if got := seen.header.Get(k); got != v {
				out = append(out, fmt.Sprintf("subrequest %s: expected header %s=%q, got %q", s.keys[i], k, v, got))
			}
		}
		if f.ExpectCredentials != nil {
			if p := credentialProblem(*f.ExpectCredentials, seen.credentials); p != "" {
				out = append(out, fmt.Sprintf("subrequest %s: %s", s.keys[i], p))
			}
		}
	}
	return out
}

// checkFixtures validates a step's fixtures before the case runs.
func checkFixtures(s *Step, filterSpec bool) error {
	seen := map[string]bool{}
	for i, f := range s.Subrequests {
		key, err := fixtureKey(f.Method, f.URL)
		if err != nil {
			return fmt.Errorf("subrequests[%d]: %w", i, err)
		}
		if seen[key] {
			return fmt.Errorf("subrequests[%d]: duplicate fixture %s", i, key)
		}
		seen[key] = true
		if f.Error != "" && (f.Status != 0 || f.Body != "" || len(f.Headers) > 0) {
			return fmt.Errorf("subrequests[%d]: error excludes status, headers, and body", i)
		}
		if f.RemovedExpectCredential != nil {
			return fmt.Errorf("subrequests[%d]: expect_credential is removed; use expect_credentials", i)
		}
		if f.ExpectCredentials != nil && filterSpec {
			return fmt.Errorf("subrequests[%d]: expect_credentials needs a bouncer spec, since a filter spec has no service", i)
		}
	}
	return nil
}

// fixtureKey is "METHOD url" with the URL in the form the router sends:
// no default port, no fragment, and "/" for an empty path.
func fixtureKey(method, raw string) (string, error) {
	if method == "" {
		method = http.MethodGet
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("url %q: %w", raw, err)
	}
	if u.Scheme != schemeHTTP && u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("url %q must be an absolute http or https url", raw)
	}
	port := "443"
	if u.Scheme == schemeHTTP {
		port = "80"
	}
	if u.Port() == port {
		h := u.Hostname()
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		u.Host = h
	} else if u.Port() != "" {
		u.Host = net.JoinHostPort(u.Hostname(), u.Port())
	}
	u.Fragment, u.RawFragment = "", ""
	if u.Path == "" {
		u.Path, u.RawPath = "/", ""
	}
	return method + " " + u.String(), nil
}

// joinProblems adds problems to a step's failure message.
func joinProblems(msg string, problems []string) string {
	if len(problems) == 0 {
		return msg
	}
	all := problems
	if msg != "" {
		all = append([]string{msg}, problems...)
	}
	return strings.Join(all, "; ")
}
