package config

import (
	"net"
	"strings"
)

// HostMatches reports whether host (optionally host:port) matches any pattern.
// Patterns are exact hostnames or "*.example.com" (one or more labels), and
// may carry a ":port" suffix that must then match exactly. A pattern without
// a port matches only the default HTTPS port (or a bare host, as for SSH),
// so "gitlab.com" never matches plain-HTTP gitlab.com:80.
//
// A host that is neither an IP nor made of hostname characters never
// matches: "evil.example#.github.com" ends in ".github.com", but a URL
// assembled from it as a string points at evil.example.
func HostMatches(patterns []string, hostport string) bool {
	host, port := SplitHostPort(hostport)
	host = asciiLower(strings.TrimSuffix(host, "."))
	if !validHost(host) {
		return false
	}
	for _, p := range patterns {
		ph, pp := SplitHostPort(p)
		ph = asciiLower(ph)
		if pp == "" {
			pp = "443"
		}
		if port != "" && pp != port {
			continue
		}
		if strings.HasPrefix(ph, "*.") {
			if strings.HasSuffix(host, ph[1:]) && len(host) > len(ph)-1 {
				return true
			}
			continue
		}
		if ph == host {
			return true
		}
	}
	return false
}

// validHost reports whether host is an IP literal or contains only
// letters, digits, '.', '-', and '_'.
func validHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for i := 0; i < len(host); i++ {
		switch c := host[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// asciiLower lowercases ASCII letters only, leaving other bytes unchanged,
// so no non-ASCII rune can case-fold onto an ASCII hostname.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// SplitHostPort splits "host:port", tolerating a missing port and IPv6 brackets.
func SplitHostPort(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return strings.Trim(s, "[]"), ""
}
