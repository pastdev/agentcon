// Package credinject decides which credentials a request may use and
// attaches them. The forwarder applies the result with real secrets; the
// test runner plans the same way, so tests report the credentials the
// forwarder would send.
//
// An agent request may use a service credential that allows agent. Its
// static placeholder is replaced only in authentication headers, because an
// API that stores and echoes a value would otherwise hand the agent the
// secret.
//
// A subrequest may use a service credential that allows subrequest. An
// elevated one (subrequest without agent) also needs the matched rule to
// list it in subrequest.credentials. Only the one-time placeholders of the
// filter run that made the subrequest are replaced, in any header, the
// query, and the body. The static placeholder passes through unchanged, so
// text the agent wrote never chooses a subrequest's credential.
//
// inject attaches its credential when the request may use it, unless the
// header it would write already holds a placeholder the request may use.
package credinject

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// placeholderPrefix starts every placeholder, static or one-time.
const placeholderPrefix = "bouncer-placeholder-"

// Lookup returns a configured credential.
type Lookup func(name string) (*config.Credential, bool)

// Getter returns a credential's secret for a request of kind.
type Getter func(ctx context.Context, name, kind string) (creds.Secret, error)

// Kind is the request kind a credential's allow list is checked against.
func Kind(req *chain.Request) string {
	if req.Subrequest != nil {
		return config.AllowSubrequest
	}
	return config.AllowAgent
}

// Usable returns the credentials req may use on svc, in the service's
// order.
func Usable(svc *config.Service, req *chain.Request, lookup Lookup) []string {
	kind := Kind(req)
	var out []string
	for _, name := range svc.Credentials {
		c, ok := lookup(name)
		if !ok || !c.Allows(kind) {
			continue
		}
		if kind == config.AllowSubrequest && c.Elevated() && !slices.Contains(req.RuleCredentials, name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// Plan is what Apply will do to one request. It holds no secrets.
type Plan struct {
	kind string
	// tokens maps each placeholder the request may use to its credential.
	tokens map[string]string
	// headers lists the headers placeholders are replaced in. Nil means
	// every header.
	headers []string
	spec    *config.Inject
	// inject is the credential the inject spec attaches, or empty.
	inject string
	// contentType of the body, for escaping a secret placed in it.
	contentType string
	// Used names the credentials the request will carry, sorted.
	Used []string
	// Body reports whether a placeholder in the body will be replaced, so
	// the caller must pass the whole body to Apply.
	Body bool
}

// NewPlan decides which credentials req will carry on svc. body is the
// whole request body, or nil when it is not available; only a subrequest's
// body is searched.
func NewPlan(svc *config.Service, req *chain.Request, header http.Header, u *url.URL, body []byte, lookup Lookup) *Plan {
	p := &Plan{kind: Kind(req), tokens: map[string]string{}}
	usable := Usable(svc, req, lookup)
	if svc.Inject != nil {
		p.spec = svc.Inject.For(req.Git() != nil)
	}
	if p.kind == config.AllowAgent {
		for _, name := range usable {
			p.tokens[config.Placeholder(name)] = name
		}
		p.headers = placeholderHeaders(p.spec)
	} else {
		for tok, name := range req.Placeholders {
			if slices.Contains(usable, name) {
				p.tokens[tok] = name
			}
		}
	}
	used := map[string]bool{}
	for _, k := range p.headerNames(header) {
		for _, v := range header.Values(k) {
			p.find(headerText(k, v), used)
		}
	}
	if p.kind == config.AllowSubrequest && u != nil {
		p.find(u.RawQuery, used)
		if body != nil {
			before := len(used)
			n := p.count(string(body))
			p.find(string(body), used)
			p.Body = n > 0 || len(used) > before
		}
		p.contentType = header.Get("Content-Type")
	}
	if svc.Inject != nil && slices.Contains(usable, svc.Inject.Credential) && !p.preempted(header, u) {
		p.inject = svc.Inject.Credential
		used[p.inject] = true
	}
	for name := range used {
		p.Used = append(p.Used, name)
	}
	sort.Strings(p.Used)
	return p
}

// Apply replaces placeholders and applies inject. secrets holds the secret
// of every credential in Used. It returns the new body when Body is set,
// and the secrets it put in the query, which the caller scrubs from
// response headers.
func (p *Plan) Apply(header http.Header, u *url.URL, body []byte, secrets map[string]creds.Secret) ([]byte, []string) {
	val := func(tok string) string { return secrets[p.tokens[tok]].HTTP() }
	for _, k := range p.headerNames(header) {
		vs := header.Values(k)
		for i, v := range vs {
			vs[i] = p.replaceHeader(k, v, val)
		}
	}
	var querySecrets []string
	if p.kind == config.AllowSubrequest && u != nil && u.RawQuery != "" {
		q, names := p.replace(u.RawQuery, func(tok string) string { return url.QueryEscape(val(tok)) })
		u.RawQuery = q
		for _, name := range names {
			querySecrets = append(querySecrets, secrets[name].HTTP())
		}
	}
	if p.Body && body != nil {
		esc := bodyEscaper(p.contentType)
		out, _ := p.replace(string(body), func(tok string) string { return esc(val(tok)) })
		body = []byte(out)
	}
	if p.inject != "" {
		s := secrets[p.inject]
		applySpec(header, u, p.spec, s)
		if p.spec.Query != "" {
			querySecrets = append(querySecrets, s.HTTP())
		}
	}
	return body, querySecrets
}

// Strip removes header and query values that carry a placeholder the
// request may use, so a request forwarded without credentials does not
// send a fake token.
func (p *Plan) Strip(header http.Header, u *url.URL) {
	for _, k := range p.headerNames(header) {
		vs := header.Values(k)
		if len(vs) == 0 {
			continue
		}
		var kept []string
		for _, v := range vs {
			if p.count(headerText(k, v)) == 0 {
				kept = append(kept, v)
			}
		}
		header.Del(k)
		for _, v := range kept {
			header.Add(k, v)
		}
	}
	if u == nil || u.RawQuery == "" {
		return
	}
	q := u.Query()
	changed := false
	for k, vs := range q {
		kept := vs[:0]
		for _, v := range vs {
			if p.count(v) > 0 {
				changed = true
				continue
			}
			kept = append(kept, v)
		}
		if len(kept) == 0 {
			q.Del(k)
			continue
		}
		q[k] = kept
	}
	if changed {
		u.RawQuery = q.Encode()
	}
}

// headerNames lists the headers to search: the placeholder headers for an
// agent request, every header of a subrequest.
func (p *Plan) headerNames(h http.Header) []string {
	if p.headers != nil {
		return p.headers
	}
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	return out
}

// preempted reports whether the header (or query parameter) inject would
// write already holds a placeholder the request may use.
func (p *Plan) preempted(h http.Header, u *url.URL) bool {
	s := p.spec
	if s == nil {
		return false
	}
	var target string
	switch {
	case s.Bearer, s.Basic != nil:
		target = "Authorization"
	case s.Header != "":
		target = s.Header
	}
	if target != "" {
		for _, v := range h.Values(target) {
			if p.count(headerText(target, v)) > 0 {
				return true
			}
		}
	}
	if s.Query != "" && u != nil && p.kind == config.AllowSubrequest {
		for _, v := range u.Query()[s.Query] {
			if p.count(v) > 0 {
				return true
			}
		}
	}
	return false
}

// headerText is a header value as placeholders appear in it: Basic
// credentials decoded.
func headerText(k, v string) string {
	if raw, ok := basicPayload(k, v); ok {
		return raw
	}
	return v
}

func basicPayload(k, v string) (string, bool) {
	if !strings.EqualFold(k, "Authorization") || !strings.HasPrefix(v, "Basic ") {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(v[len("Basic "):])
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func (p *Plan) replaceHeader(k, v string, val func(string) string) string {
	if raw, ok := basicPayload(k, v); ok {
		out, names := p.replace(raw, val)
		if len(names) > 0 {
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(out))
		}
		return v
	}
	out, _ := p.replace(v, val)
	return out
}

// find records the credentials of the placeholders in s.
func (p *Plan) find(s string, used map[string]bool) {
	_, names := p.replace(s, func(string) string { return "" })
	for _, n := range names {
		used[n] = true
	}
}

func (p *Plan) count(s string) int {
	_, names := p.replace(s, func(string) string { return "" })
	return len(names)
}

// replace swaps every whole placeholder in s for val(token). A placeholder
// counts only where it is not part of a longer name, so
// bouncer-placeholder-github never matches inside
// bouncer-placeholder-github-audit. It returns the credentials replaced,
// one entry per occurrence.
func (p *Plan) replace(s string, val func(string) string) (string, []string) {
	if len(p.tokens) == 0 || !strings.Contains(s, placeholderPrefix) {
		return s, nil
	}
	var b strings.Builder
	var names []string
	rest := s
	for {
		i := strings.Index(rest, placeholderPrefix)
		if i < 0 {
			b.WriteString(rest)
			break
		}
		tok, ok := p.tokenAt(rest, i)
		if !ok {
			b.WriteString(rest[:i+len(placeholderPrefix)])
			rest = rest[i+len(placeholderPrefix):]
			continue
		}
		b.WriteString(rest[:i])
		b.WriteString(val(tok))
		names = append(names, p.tokens[tok])
		rest = rest[i+len(tok):]
	}
	return b.String(), names
}

// tokenAt returns the placeholder starting at s[i], when it is a whole one.
func (p *Plan) tokenAt(s string, i int) (string, bool) {
	if i > 0 && nameChar(s[i-1]) {
		return "", false
	}
	end := i
	for end < len(s) && nameChar(s[end]) {
		end++
	}
	tok := s[i:end]
	_, ok := p.tokens[tok]
	return tok, ok
}

// nameChar reports whether c may appear in a placeholder.
func nameChar(c byte) bool {
	return c == '-' || c == '_' || c == '.' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// bodyEscaper encodes a secret for the body's media type.
func bodyEscaper(contentType string) func(string) string {
	mt, _, _ := mime.ParseMediaType(contentType)
	switch {
	case mt == "application/x-www-form-urlencoded":
		return url.QueryEscape
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		return jsonEscape
	}
	return func(s string) string { return s }
}

// jsonEscape encodes s for the inside of a JSON string.
func jsonEscape(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	out := strings.TrimSuffix(b.String(), "\n")
	return out[1 : len(out)-1]
}

// placeholderHeaders lists the headers in which an agent's placeholders
// are replaced.
func placeholderHeaders(spec *config.Inject) []string {
	out := []string{"Authorization", "Private-Token"}
	if spec != nil {
		if spec.Header != "" {
			out = append(out, spec.Header)
		}
		out = append(out, spec.PlaceholderHeaders...)
	}
	return out
}

// applySpec attaches a secret as the inject spec says.
func applySpec(h http.Header, u *url.URL, spec *config.Inject, secret creds.Secret) {
	httpSecret := secret.HTTP()
	switch {
	case spec.Bearer:
		h.Set("Authorization", "Bearer "+httpSecret)
	case spec.Basic != nil:
		user := secret.BasicUser(spec.Basic.Username)
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+secret.BasicPass())))
	case spec.Header != "":
		v := spec.Value
		if v == "" {
			v = "{{secret}}"
		}
		h.Set(spec.Header, strings.ReplaceAll(v, "{{secret}}", httpSecret))
	}
	if spec.Query != "" && u != nil {
		// Append rather than re-encode: url.Values.Encode() drops malformed
		// pairs and reorders the rest, so the forwarded query would differ
		// from the one the rules evaluated.
		pair := url.QueryEscape(spec.Query) + "=" + url.QueryEscape(httpSecret)
		if u.RawQuery == "" {
			u.RawQuery = pair
		} else {
			u.RawQuery += "&" + pair
		}
	}
}
