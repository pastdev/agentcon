package approval

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
