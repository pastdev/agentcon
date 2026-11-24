package approval

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"

	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

// Display makes request-derived text safe to show a human deciding on it:
// control characters, terminal escapes and invisible formatting (bidi
// overrides, zero-width characters) are shown escaped rather than
// interpreted, and text beyond limit runes is cut off with a visible marker,
// so a request can't disguise or bury what's being approved.
func Display(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit {
			fmt.Fprintf(&b, "… [%d more characters]", len([]rune(s))-limit)
			break
		}
		n++
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// DisplayASCII is Display for values where look-alike characters matter: a
// backslash is written as \\, other printable ASCII as is, and every other
// rune as \uXXXX or \UXXXXXXXX. Two different strings within limit never
// render the same, so a confusable letter from another script stays
// visible. Text beyond limit runes is cut off with a visible marker.
func DisplayASCII(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit {
			fmt.Fprintf(&b, "… [%d more characters]", len([]rune(s))-limit)
			break
		}
		n++
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r >= ' ' && r <= '~':
			b.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}

// needsASCII reports whether DisplayASCII renders s differently from s.
func needsASCII(s string) bool {
	for _, r := range s {
		if r == '\\' || r < ' ' || r > '~' {
			return true
		}
	}
	return false
}

// ClaimSummary renders a requested claim on one line as type=value, with
// the value through DisplayASCII and cut at limit runes. cut reports whether
// the value was cut.
func ClaimSummary(c claims.Claim, limit int) (s string, cut bool) {
	return DisplayASCII(c.Type, claims.MaxTypeLength) + "=" + DisplayASCII(c.Value, limit), len([]rune(c.Value)) > limit
}

// Bounds on how much of a session's claims a claim prompt shows.
const (
	displayClaimValue  = 120
	displayClaimValues = 10
)

// ClaimLines describes a claim prompt for a terminal: the requested claim,
// then the session's current claims grouped by type. Each line starts with
// indent and ends with a newline. The requested claim is shown in full.
// When it has a backslash or non-ASCII, a second line shows it through
// DisplayASCII, so a look-alike letter from another script is visible. The
// current claims are context, so long values and long lists are cut off
// visibly.
func ClaimLines(p prompt.Pending, indent string) string {
	var b strings.Builder
	if p.Claim != nil {
		// A valid value is at most MaxValueBytes bytes, so at most that many
		// runes: this limit never cuts one.
		fmt.Fprintf(&b, "%sclaim: %s=%s\n", indent,
			Display(p.Claim.Type, claims.MaxTypeLength), Display(p.Claim.Value, claims.MaxValueBytes))
		if needsASCII(p.Claim.Value) {
			escaped, _ := ClaimSummary(*p.Claim, claims.MaxValueBytes)
			fmt.Fprintf(&b, "%sclaim (escaped): %s\n", indent, escaped)
		}
	}
	if len(p.SessionClaims) == 0 {
		fmt.Fprintf(&b, "%ssession claims: none\n", indent)
		return b.String()
	}
	fmt.Fprintf(&b, "%ssession claims:\n", indent)
	for _, t := range slices.Sorted(maps.Keys(p.SessionClaims)) {
		vs := p.SessionClaims[t]
		shown := make([]string, 0, min(len(vs), displayClaimValues))
		for _, v := range vs[:min(len(vs), displayClaimValues)] {
			shown = append(shown, Display(v, displayClaimValue))
		}
		line := strings.Join(shown, ", ")
		if more := len(vs) - len(shown); more > 0 {
			line += fmt.Sprintf(", … [%d more]", more)
		}
		fmt.Fprintf(&b, "%s  %s: %s\n", indent, Display(t, 64), line)
	}
	return b.String()
}
