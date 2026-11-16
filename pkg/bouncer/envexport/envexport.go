// Package envexport builds the environment that routes an agent's traffic
// through bouncer.
package envexport

import (
	"net/url"
	"sort"
)

// Params describe one session's environment.
type Params struct {
	ProxyAddr    string
	SSHAddr      string
	Token        string
	SessionID    string
	CACert       string // PEM file with only the bouncer CA
	CABundle     string // PEM file with system roots + bouncer CA
	SSHCommand   string // command for GIT_SSH_COMMAND
	Placeholders map[string]string
}

// Env is an ordered set of variables.
type Env struct {
	Vars [][2]string
}

// Build computes the environment for a session.
func Build(p Params) Env {
	proxyURL := (&url.URL{Scheme: "http", User: url.UserPassword("bouncer", p.Token), Host: p.ProxyAddr}).String()
	e := Env{}
	add := func(k, v string) { e.Vars = append(e.Vars, [2]string{k, v}) }
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		add(k, proxyURL)
	}
	add("NO_PROXY", "localhost,127.0.0.1,::1")
	add("no_proxy", "localhost,127.0.0.1,::1")
	// Node.js >= 24 honors the proxy variables for fetch/http only with this set.
	add("NODE_USE_ENV_PROXY", "1")
	// Variables that replace the trust store get the combined bundle so
	// tunneled hosts still verify; NODE_EXTRA_CA_CERTS appends, so it gets just the CA.
	for _, k := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"} {
		add(k, p.CABundle)
	}
	add("NODE_EXTRA_CA_CERTS", p.CACert)
	if p.SSHCommand != "" {
		add("GIT_SSH_COMMAND", p.SSHCommand)
	}
	add("BOUNCER_SESSION", p.Token)
	add("BOUNCER_SESSION_ID", p.SessionID)
	add("BOUNCER_PROXY", "http://"+p.ProxyAddr)
	add("BOUNCER_SSH_ADDR", p.SSHAddr)
	// Base URL for tools that can't use a proxy: $BOUNCER_BASE/<host>/<path>.
	add("BOUNCER_BASE", "http://"+p.ProxyAddr+"/s/"+p.Token)

	names := make([]string, 0, len(p.Placeholders))
	for n := range p.Placeholders {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		add(n, p.Placeholders[n])
	}
	return e
}
