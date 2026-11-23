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
			want: "  claim: repository=g/\\u202eevil\n  session claims:\n" +
				"    repository: v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, … [2 more]\n",
		})
	})
}
