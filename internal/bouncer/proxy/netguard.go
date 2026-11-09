package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// reservedNets are special-purpose ranges the net.IP predicates miss.
var reservedNets = []*net.IPNet{
	mustCIDR("0.0.0.0/8"),      // "this network"
	mustCIDR("100.64.0.0/10"),  // CGNAT and overlay networks
	mustCIDR("192.0.0.0/24"),   // IETF protocol assignments
	mustCIDR("198.18.0.0/15"),  // benchmarking
	mustCIDR("240.0.0.0/4"),    // reserved, including broadcast
	mustCIDR("64:ff9b:1::/48"), // local-use NAT64
}

// nat64 is the well-known NAT64 prefix, which embeds an IPv4 address in its
// last four bytes.
var nat64 = mustCIDR("64:ff9b::/96")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// nonPublic reports whether ip is an address an agent must not reach
// through a tunnel by default: the host itself, its LAN, link-local
// (including cloud metadata endpoints), CGNAT/overlay ranges, and the like.
// A NAT64 address is judged by the IPv4 address it embeds, so
// 64:ff9b::a9fe:a9fe cannot reach a metadata endpoint.
func nonPublic(ip net.IP) bool {
	if ip.To4() == nil && nat64.Contains(ip) {
		return nonPublic(net.IP(ip.To16()[12:16]))
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// publicDialer refuses non-public destinations. The check runs on the
// address actually being connected to, after DNS resolution, so a name that
// resolves (or re-resolves) to an internal address is caught too.
func publicDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("dial address: %w", err)
			}
			if ip := net.ParseIP(host); ip == nil || nonPublic(ip) {
				return fmt.Errorf("%w: %s", errNonPublic, host)
			}
			return nil
		},
	}
}

type nonPublicError struct{}

func (nonPublicError) Error() string {
	return "destination is a loopback, private, link-local or reserved address (set allow_private: true on the profile to permit)"
}

var errNonPublic error = nonPublicError{}

// tunnelDial dials an unmatched host for a profile.
func (s *Server) tunnelDial(ctx context.Context, allowPrivate bool, addr string) (net.Conn, error) {
	d := s.Dialer
	if !allowPrivate {
		d = publicDialer()
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	return c, nil
}

// tunnelTransport forwards plain-HTTP requests to unmatched hosts.
func (s *Server) tunnelTransport(allowPrivate bool) http.RoundTripper {
	s.tunnelOnce.Do(func() {
		t := NewTransport()
		t.DialContext = publicDialer().DialContext
		s.publicTransport = t
	})
	if allowPrivate {
		return s.Transport
	}
	return s.publicTransport
}
