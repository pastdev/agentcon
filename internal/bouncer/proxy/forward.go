package proxy

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/credinject"
	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
)

// forwarder is the terminal handler: attach credentials and send upstream.
// It runs only after every filter and rule has allowed the request, so
// filters never see a secret.
func (s *Server) forwarder(svc *policy.Service, origLength int64) chain.Handler {
	return func(req *chain.Request) (*chain.Response, error) {
		header := req.Header.Clone()
		// Let the transport negotiate (and transparently decode) compression
		// so response filters always see plain bodies.
		header.Del("Accept-Encoding")
		u := *req.URL
		credentialed := len(svc.Config.Credentials) > 0
		if credentialed && header.Get("Upgrade") != "" && !svc.Config.AllowUpgrade {
			return synthetic(http.StatusForbidden, "agent-bouncer: protocol upgrades on "+svc.Config.Name+" are not allowed (the upgraded stream can't be filtered); set allow_upgrade: true to permit"), nil
		}
		var querySecrets []string
		if credentialed {
			var resp *chain.Response
			querySecrets, resp = s.attach(svc, req, header, &u)
			if resp != nil {
				return resp, nil
			}
		}

		length := req.Body.Len()
		if length < 0 {
			length = origLength
		}
		var body io.ReadCloser = http.NoBody
		if length != 0 {
			body = req.Body.Reader()
		}
		out, err := http.NewRequestWithContext(req.Ctx, req.Method, u.String(), body)
		if err != nil {
			r := synthetic(http.StatusBadGateway, "agent-bouncer: "+err.Error())
			r.UpstreamErr = err
			return r, nil //nolint:nilerr // upstream problems become a synthetic 502 for the agent
		}
		out.Header = header
		out.ContentLength = length
		out.Host = u.Host

		resp, err := s.Transport.RoundTrip(out)
		if err != nil {
			r := synthetic(http.StatusBadGateway, "agent-bouncer: upstream error: "+err.Error())
			r.UpstreamErr = fmt.Errorf("upstream: %w", err)
			return r, nil
		}
		// A secret placed in the query can come back in a URL the upstream
		// echoes (a redirect Location, say), which the agent would then read.
		// Scrub it.
		for _, secret := range querySecrets {
			scrubSecret(resp.Header, secret)
		}
		r := &chain.Response{Status: resp.StatusCode, Header: resp.Header}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			// Only splice a 101 if the client actually asked to upgrade and
			// the service permits it; otherwise an upstream could hand the
			// agent a raw stream on a request that was never meant to upgrade.
			if header.Get("Upgrade") == "" || (credentialed && !svc.Config.AllowUpgrade) {
				_ = resp.Body.Close()
				return synthetic(http.StatusBadGateway, "agent-bouncer: unexpected protocol upgrade from upstream"), nil
			}
			if rwc, ok := resp.Body.(io.ReadWriteCloser); ok {
				r.Upgrade = rwc
				return r, nil
			}
		}
		r.Body = chain.NewBody(resp.Body)
		return r, nil
	}
}

// scrubSecret removes a secret (raw, percent-encoded, or base64) from
// response headers that commonly carry a URL back to the client.
func scrubSecret(h http.Header, secret string) {
	forms := []string{secret, url.QueryEscape(secret), base64.StdEncoding.EncodeToString([]byte(secret))}
	for _, name := range []string{"Location", "Content-Location", "Link", "Refresh"} {
		vs := h.Values(name)
		for i, v := range vs {
			for _, f := range forms {
				if f != "" && strings.Contains(v, f) {
					v = strings.ReplaceAll(v, f, "REDACTED-BY-AGENT-BOUNCER")
				}
			}
			vs[i] = v
		}
	}
}

func synthetic(status int, msg string) *chain.Response {
	return &chain.Response{Status: status, Header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body: chain.BytesBody([]byte(msg + "\n"))}
}

// attach replaces the placeholders req may use and applies inject, or
// strips them when the request is forwarded without credentials. It
// returns the secrets it put in the query, or a response that ends the
// request instead.
func (s *Server) attach(svc *policy.Service, req *chain.Request, header http.Header, u *url.URL) ([]string, *chain.Response) {
	var body []byte
	if req.Subrequest != nil && len(req.Placeholders) > 0 && req.Body != nil {
		b, err := req.Body.ReadAll()
		if err != nil {
			return nil, synthetic(http.StatusBadGateway, "agent-bouncer: read subrequest body: "+err.Error())
		}
		body = b
	}
	plan := credinject.NewPlan(svc.Config, req, header, u, body, s.Creds.Credential)
	if req.SkipCredential {
		plan.Strip(header, u)
		return nil, nil
	}
	if len(plan.Used) == 0 {
		return nil, nil
	}
	if u.Scheme != "https" && !svc.Config.Insecure {
		return nil, synthetic(http.StatusForbidden, "agent-bouncer: refusing to send credentials over plain HTTP; use https (or set insecure: true on the service for local development)")
	}
	kind := credinject.Kind(req)
	secrets := map[string]creds.Secret{}
	for _, name := range plan.Used {
		secret, err := s.Creds.Get(req.Ctx, name, kind)
		if err != nil {
			creds.LogError(s.Log.Warn(), err).Str("service", svc.Config.Name).Str("credential", name).Msg("credential unavailable")
			return nil, synthetic(http.StatusBadGateway, "agent-bouncer: "+creds.Unavailable(svc.Config.Name).Error())
		}
		secrets[name] = secret
	}
	newBody, querySecrets := plan.Apply(header, u, body, secrets)
	if plan.Body {
		req.Body.Set(newBody)
	}
	req.Credentials = plan.Used
	return querySecrets, nil
}
