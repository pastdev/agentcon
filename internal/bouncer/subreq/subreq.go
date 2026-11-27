// Package subreq routes a filter's subrequest through the session's policy,
// exactly as an agent request to the same URL would go: through the chain
// of the HTTP service its host matches, or the profile's tunnel rules for a
// host with no service.
package subreq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/audit"
	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// Router sends subrequests. Each hop of a followed redirect is routed and
// audited on its own.
type Router struct {
	// Session returns sess as it is now, with its current claims. False
	// means the session ended.
	Session func(sess *chain.Session) (*chain.Session, bool)
	// Profile returns a compiled profile. Nil sends every hop to Direct.
	Profile func(name string) (*policy.Profile, bool)
	// Terminal is the end of an intercepted service's chain.
	Terminal func(svc *policy.Service, length int64) chain.Handler
	// Tunnel sends a request to a host the profile has no service for.
	Tunnel func(prof *policy.Profile, req *chain.Request) (*chain.Response, error)
	// Direct answers every hop when Profile is nil, with no chain. Filter
	// tests use it.
	Direct chain.Handler
	// Audit records each hop. Nil records nothing.
	Audit func(audit.Entry)
}

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
	// byBouncer attributes a decision Bouncer itself made.
	byBouncer = "bouncer"
)

// hopHeaders never travel in a subrequest.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// crossHostHeaders are dropped when a redirect leaves the host, as Go's
// HTTP client does, so a value the filter set for one host never reaches
// another. Bouncer's own credentials are injected per hop anyway, and a
// one-time placeholder is replaced only where the hop's service and rule
// let the subrequest use its credential.
var crossHostHeaders = []string{"Authorization", "Private-Token", "Cookie", "Cookie2", "Www-Authenticate"}

// Do implements chain.SubrequestFunc.
func (r *Router) Do(parent *chain.Request, caller chain.SubrequestCaller, spec chain.SubrequestSpec) (*chain.Response, *url.URL, error) {
	depth := 1
	if parent.Subrequest != nil {
		depth = parent.Subrequest.Depth + 1
	}
	if depth > chain.MaxSubrequestDepth {
		return nil, nil, fmt.Errorf("subrequest: depth %d exceeds limit %d", depth, chain.MaxSubrequestDepth)
	}
	if parent.Session == nil {
		return nil, nil, errors.New("subrequest: request has no session")
	}
	method := spec.Method
	if method == "" {
		method = http.MethodGet
	}
	err := chain.CheckMethod(method)
	if err != nil {
		return nil, nil, fmt.Errorf("subrequest: %w", err)
	}
	if method == http.MethodConnect || method == http.MethodTrace {
		return nil, nil, fmt.Errorf("subrequest: method %s is not allowed", method)
	}
	u, err := parseURL(spec.URL)
	if err != nil {
		return nil, nil, err
	}
	u = normalized(u)
	header := spec.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	for _, k := range hopHeaders {
		header.Del(k)
	}
	body := spec.Body
	info := &chain.SubrequestInfo{Filter: caller.Filter, ID: caller.ID, Depth: depth, Parent: parent.Describe()}

	base := parent.Ctx
	if base == nil {
		base = context.Background()
	}
	// The context lives until the response body is closed, so a body read
	// after Do returns still works, and closing it releases the upstream.
	ctx, cancel := context.WithCancel(base)
	if spec.Timeout > 0 {
		ctx, cancel = withTimeout(ctx, cancel, spec.Timeout)
	}

	for redirects := 0; ; redirects++ {
		resp, err := r.hop(ctx, parent.Session, info, caller.Placeholders, method, u, header, body)
		if err != nil {
			cancel()
			return nil, nil, err
		}
		next, ok := redirectTarget(resp, u, spec.Manual)
		if !ok {
			return releaseOnClose(resp, cancel), u, nil
		}
		closeBody(resp)
		if redirects == chain.MaxSubrequestRedirects {
			cancel()
			return nil, nil, fmt.Errorf("subrequest: stopped after %d redirects", chain.MaxSubrequestRedirects)
		}
		if next.Scheme != schemeHTTP && next.Scheme != schemeHTTPS {
			cancel()
			return nil, nil, fmt.Errorf("subrequest: redirect to unsupported scheme %q", next.Scheme)
		}
		method, body = redirectMethod(resp.Status, method, body)
		if body == nil {
			header.Del("Content-Type")
			header.Del("Content-Length")
		}
		if hostport(next) != hostport(u) {
			for _, k := range crossHostHeaders {
				header.Del(k)
			}
		}
		u = normalized(next)
	}
}

func withTimeout(ctx context.Context, cancel context.CancelFunc, d time.Duration) (context.Context, context.CancelFunc) {
	tctx, tcancel := context.WithTimeout(ctx, d)
	return tctx, func() {
		tcancel()
		cancel()
	}
}

// parseURL accepts an absolute http or https URL with a host.
func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("subrequest: %w", err)
	}
	if u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS {
		return nil, fmt.Errorf("subrequest: url %q must be http or https", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("subrequest: url %q has no host", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("subrequest: url %q must not carry user info", raw)
	}
	return u, nil
}

// defaultPort is the port a scheme implies.
func defaultPort(scheme string) string {
	if scheme == schemeHTTP {
		return "80"
	}
	return "443"
}

// hostport is u's host with its port, the form services match against.
func hostport(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), defaultPort(u.Scheme))
}

// normalized drops the default port, as the proxy does, so rules and
// filters see the same URL an agent request would have.
func normalized(u *url.URL) *url.URL {
	c := *u
	h, p := config.SplitHostPort(hostport(u))
	if p == defaultPort(u.Scheme) {
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		c.Host = h
	}
	c.Fragment, c.RawFragment = "", ""
	if c.Path == "" {
		c.Path, c.RawPath = "/", ""
	}
	return &c
}

// hop sends one request, with no redirect handling.
func (r *Router) hop(ctx context.Context, sess *chain.Session, info *chain.SubrequestInfo, placeholders map[string]string, method string, u *url.URL, header http.Header, body []byte) (*chain.Response, error) {
	start := time.Now()
	live, ok := r.Session(sess)
	if !ok {
		return nil, errors.New("subrequest: session is no longer valid")
	}
	req := &chain.Request{
		Ctx: ctx, Transport: chain.TransportHTTP, Session: live, Profile: live.Profile,
		Method: method, URL: u, Header: header.Clone(), Body: chain.BytesBody(body), Subrequest: info,
		Placeholders: placeholders,
	}
	e := audit.Entry{
		Session: live.ID, Label: live.Label, Profile: live.Profile, Transport: chain.TransportHTTP,
		Subrequest: &audit.Subrequest{Filter: info.Filter, ID: info.ID, Depth: info.Depth, Parent: info.Parent},
	}
	resp, err := r.route(req, &e)
	if err == nil && resp.UpstreamErr != nil {
		err = fmt.Errorf("subrequest: %w", resp.UpstreamErr)
		closeBody(resp)
	}
	if err == nil && resp.Upgrade != nil {
		_ = resp.Upgrade.Close()
		err = errors.New("subrequest: protocol upgrades are not supported")
	}
	e.Request = req.Describe()
	e.Credentials = req.Credentials
	e.DurationMS = time.Since(start).Milliseconds()
	switch {
	case err != nil:
		e.Decision, e.By, e.Reason = audit.DecisionError, byBouncer, err.Error()
	case resp.Denial != nil:
		e.Decision, e.By, e.Reason, e.Status = audit.DecisionDeny, resp.Denial.By, resp.Denial.Reason, resp.Denial.Status
	case e.Decision == "":
		e.Decision, e.By, e.Status = audit.DecisionAllow, req.AllowedBy, resp.Status
	}
	if r.Audit != nil {
		r.Audit(e)
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// route picks the chain, tunnel, or denial for req.
func (r *Router) route(req *chain.Request, e *audit.Entry) (*chain.Response, error) {
	if r.Profile == nil {
		if r.Direct == nil {
			return nil, errors.New("subrequest: no route is configured")
		}
		return r.Direct(req)
	}
	prof, ok := r.Profile(req.Profile)
	if !ok {
		return nil, errors.New("subrequest: session profile no longer exists")
	}
	hp := hostport(req.URL)
	if svc := prof.MatchHTTP(hp); svc != nil {
		req.Service = svc.Config.Name
		req.SignerRequest = svc.Config.Signer != nil
		e.Service = svc.Config.Name
		err := Check(req)
		if err != nil {
			return &chain.Response{Status: http.StatusBadRequest, Denial: &chain.Denial{By: byBouncer, Reason: err.Error(), Status: http.StatusBadRequest}}, nil //nolint:nilerr // a failed check is a denial, as for an agent request
		}
		resp, _ := chain.Build(svc.Filters, r.Terminal(svc, req.Body.Len()))(req)
		return resp, nil
	}
	if !prof.Tunnels(hp) {
		reason := "host not allowed by profile " + prof.Name
		return &chain.Response{Status: http.StatusForbidden, Denial: &chain.Denial{By: byBouncer, Reason: reason, Status: http.StatusForbidden}}, nil
	}
	if r.Tunnel == nil {
		return nil, errors.New("subrequest: tunneling is not configured")
	}
	resp, err := r.Tunnel(prof, req)
	if err != nil {
		return nil, err
	}
	if resp.UpstreamErr == nil {
		e.Decision, e.Status = audit.DecisionTunnel, resp.Status
	}
	return resp, nil
}

// Check applies the request checks every intercepted request gets.
func Check(req *chain.Request) error {
	if !strings.HasPrefix(req.URL.Path, "/") {
		return fmt.Errorf("request target %q is not an origin-form path", req.URL.Path)
	}
	// The checks' own messages are the denial reasons agents see, so they
	// are returned as is.
	err := chain.CheckPath(req.URL.Path)
	if err != nil {
		return err //nolint:wrapcheck // the message is the denial reason
	}
	return chain.CheckMethodOverride(req) //nolint:wrapcheck // the message is the denial reason
}

// redirectTarget returns where resp redirects to, when it should be
// followed.
func redirectTarget(resp *chain.Response, from *url.URL, manual bool) (*url.URL, bool) {
	if manual || resp.Denial != nil {
		return nil, false
	}
	switch resp.Status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return nil, false
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, false
	}
	next, err := from.Parse(loc)
	if err != nil {
		return nil, false
	}
	return next, true
}

// redirectMethod is the method and body for the next hop, following what
// HTTP clients do: 303 becomes GET, as do 301 and 302 after a POST, and 307
// and 308 resend the request as is.
func redirectMethod(status int, method string, body []byte) (string, []byte) {
	switch status {
	case http.StatusSeeOther:
		if method != http.MethodHead {
			return http.MethodGet, nil
		}
		return method, nil
	case http.StatusMovedPermanently, http.StatusFound:
		if method == http.MethodPost {
			return http.MethodGet, nil
		}
	}
	return method, body
}

func closeBody(resp *chain.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

// releaseOnClose ties cancel to the response body, so the subrequest's
// context ends when its body is closed. A body already in memory releases
// it at once.
func releaseOnClose(resp *chain.Response, cancel context.CancelFunc) *chain.Response {
	if resp.Body == nil || resp.Body.Complete() {
		cancel()
		return resp
	}
	resp.Body = chain.NewBody(&cancelCloser{rc: resp.Body.Reader(), cancel: cancel})
	return resp
}

type cancelCloser struct {
	rc     io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelCloser) Read(p []byte) (int, error) { return c.rc.Read(p) } //nolint:wrapcheck // io.Reader contract: io.EOF must be returned unwrapped

func (c *cancelCloser) Close() error {
	err := c.rc.Close()
	c.cancel()
	return err //nolint:wrapcheck // thin adapter: return the wrapped reader's error as-is
}
