// Package gitsign is the agent side of a bouncer signer service. Git runs it
// as gpg.openpgp.program. It sends the object git wants signed to the
// signer and writes the signature and gpg-style status lines git expects.
package gitsign

import (
	"errors"
	"fmt"
	"net/url"
	pathpkg "path"
	"regexp"
	"strings"
)

var scpLikeRe = regexp.MustCompile(`^(?:[^@/]+@)?([^:/]+):(.+)$`)

// NormalizeRemote turns a git remote URL into host/path. The host is
// lowercased and its port dropped. The path is cleaned, a trailing .git is
// trimmed, and its case is kept.
func NormalizeRemote(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("remote url is empty")
	}
	if !strings.Contains(raw, "://") {
		m := scpLikeRe.FindStringSubmatch(raw)
		if m == nil {
			return "", fmt.Errorf("remote url %q: not a url or host:path", raw)
		}
		return join(raw, m[1], m[2])
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("remote url %q: %w", raw, err)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", fmt.Errorf("remote url %q: must not have a query", raw)
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("remote url %q: must not have a fragment", raw)
	}
	return join(raw, u.Hostname(), u.Path)
}

func join(raw, host, p string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	p = strings.TrimPrefix(pathpkg.Clean("/"+p), "/")
	p = strings.TrimSuffix(p, ".git")
	p = strings.TrimSuffix(p, "/")
	if host == "" {
		return "", fmt.Errorf("remote url %q: missing host", raw)
	}
	if p == "" || p == "." {
		return "", fmt.Errorf("remote url %q: missing path", raw)
	}
	return host + "/" + p, nil
}
