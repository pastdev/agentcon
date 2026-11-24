package approval

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

func TestDisplay(t *testing.T) {
	type testCase struct {
		in          string
		max         int
		want        string
		wantSuffix  string
		wantMaxRune int
		escapeCtrl  bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := Display(tc.in, tc.max)
		if tc.escapeCtrl {
			assert.False(t, strings.ContainsAny(got, "\x1b\r\u202e\u200b"), "control characters survived: %q", got)
			assert.Contains(t, got, `\u001b`)
			return
		}
		if tc.wantSuffix != "" {
			assert.True(t, strings.HasSuffix(got, tc.wantSuffix), "suffix of %q", got)
			assert.LessOrEqual(t, len([]rune(got)), tc.wantMaxRune)
			return
		}
		assert.Equal(t, tc.want, got)
	}

	t.Run("escapes control characters", func(t *testing.T) {
		tester(t, testCase{
			in:         "GET /x\x1b[2K\rGET /harmless\u202e\u200b",
			max:        200,
			escapeCtrl: true,
		})
	})
	t.Run("truncates a long string", func(t *testing.T) {
		tester(t, testCase{
			in:          strings.Repeat("a", 500),
			max:         100,
			wantSuffix:  "… [400 more characters]",
			wantMaxRune: 130,
		})
	})
	t.Run("leaves plain text unchanged", func(t *testing.T) {
		tester(t, testCase{
			in:   "ssh agent@sandbox exec: ls -la",
			max:  200,
			want: "ssh agent@sandbox exec: ls -la",
		})
	})
}

func TestDisplayASCII(t *testing.T) {
	type testCase struct {
		in    string
		limit int
		want  string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, DisplayASCII(tc.in, tc.limit))
	}

	t.Run("leaves printable ASCII unchanged", func(t *testing.T) {
		tester(t, testCase{in: "gitlab.example.com/group/other", limit: 100, want: "gitlab.example.com/group/other"})
	})
	t.Run("escapes a look-alike letter", func(t *testing.T) {
		tester(t, testCase{in: "gitlab.example.com/gr\u043eup/other", limit: 100, want: `gitlab.example.com/gr\u043eup/other`})
	})
	t.Run("escapes a backslash, so an escape typed literally differs", func(t *testing.T) {
		tester(t, testCase{in: `gr\u043eup`, limit: 100, want: `gr\\u043eup`})
	})
	t.Run("escapes control characters and runes above U+FFFF", func(t *testing.T) {
		tester(t, testCase{in: "a\tb\U0001F600", limit: 100, want: `a\u0009b\U0001f600`})
	})
	t.Run("cuts off at limit runes", func(t *testing.T) {
		tester(t, testCase{in: "abcdef", limit: 3, want: "abc… [3 more characters]"})
	})
}

func TestClaimSummary(t *testing.T) {
	type testCase struct {
		claim   claims.Claim
		limit   int
		want    string
		wantCut bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, cut := ClaimSummary(tc.claim, tc.limit)
		assert.Equal(t, tc.want, got)
		assert.Equal(t, tc.wantCut, cut)
	}

	t.Run("escapes a look-alike letter", func(t *testing.T) {
		tester(t, testCase{
			claim: claims.Claim{Type: "repository", Value: "g/gr\u043eup"},
			limit: 80,
			want:  `repository=g/gr\u043eup`,
		})
	})
	t.Run("reports a cut value", func(t *testing.T) {
		tester(t, testCase{
			claim:   claims.Claim{Type: "t", Value: "abcdef"},
			limit:   3,
			want:    "t=abc… [3 more characters]",
			wantCut: true,
		})
	})
}

func TestClaimLines(t *testing.T) {
	type testCase struct {
		p    prompt.Pending
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, ClaimLines(tc.p, "  "))
	}
	many := make([]string, 12)
	for i := range many {
		many[i] = fmt.Sprintf("v%02d", i)
	}

	t.Run("groups current claims by type", func(t *testing.T) {
		tester(t, testCase{
			p: prompt.Pending{
				Claim:         &claims.Claim{Type: "repository", Value: "g/c"},
				SessionClaims: claims.Set{"ticket": {"T-1"}, "repository": {"g/a", "g/b"}},
			},
			want: "  claim: repository=g/c\n  session claims:\n    repository: g/a, g/b\n    ticket: T-1\n",
		})
	})
	t.Run("no current claims", func(t *testing.T) {
		tester(t, testCase{
			p:    prompt.Pending{Claim: &claims.Claim{Type: "repository", Value: "g/c"}, SessionClaims: claims.Set{}},
			want: "  claim: repository=g/c\n  session claims: none\n",
		})
	})
	t.Run("shows a maximum-length requested value in full", func(t *testing.T) {
		base := strings.Repeat("v", claims.MaxValueBytes-1)
		a := ClaimLines(prompt.Pending{Claim: &claims.Claim{Type: "repository", Value: base + "a"}, SessionClaims: claims.Set{}}, "")
		b := ClaimLines(prompt.Pending{Claim: &claims.Claim{Type: "repository", Value: base + "b"}, SessionClaims: claims.Set{}}, "")
		assert.Contains(t, a, "claim: repository="+base+"a\n")
		assert.Contains(t, b, "claim: repository="+base+"b\n")
		assert.NotEqual(t, a, b)
		assert.NotContains(t, a, "more characters")
	})
	t.Run("adds an escaped line for a look-alike letter", func(t *testing.T) {
		tester(t, testCase{
			p: prompt.Pending{
				Claim:         &claims.Claim{Type: "repository", Value: "gitlab.example.com/gr\u043eup/other"},
				SessionClaims: claims.Set{},
			},
			want: "  claim: repository=gitlab.example.com/gr\u043eup/other\n" +
				"  claim (escaped): repository=gitlab.example.com/gr\\u043eup/other\n" +
				"  session claims: none\n",
		})
	})
	t.Run("adds an escaped line for a backslash", func(t *testing.T) {
		tester(t, testCase{
			p:    prompt.Pending{Claim: &claims.Claim{Type: "t", Value: `a\u043e`}, SessionClaims: claims.Set{}},
			want: "  claim: t=a\\u043e\n  claim (escaped): t=a\\\\u043e\n  session claims: none\n",
		})
	})
	t.Run("cuts off long current values", func(t *testing.T) {
		long := strings.Repeat("v", 200)
		tester(t, testCase{
			p:    prompt.Pending{Claim: &claims.Claim{Type: "t", Value: "x"}, SessionClaims: claims.Set{"t": {long}}},
			want: "  claim: t=x\n  session claims:\n    t: " + strings.Repeat("v", 120) + "… [80 more characters]\n",
		})
	})
	t.Run("cuts off long lists and escapes invisible characters", func(t *testing.T) {
		tester(t, testCase{
			p: prompt.Pending{
				Claim:         &claims.Claim{Type: "repository", Value: "g/\u202eevil"},
				SessionClaims: claims.Set{"repository": many},
			},
			want: "  claim: repository=g/\\u202eevil\n" +
				"  claim (escaped): repository=g/\\u202eevil\n  session claims:\n" +
				"    repository: v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, … [2 more]\n",
		})
	})
}
