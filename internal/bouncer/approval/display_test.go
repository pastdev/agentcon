package approval

import (
	"strings"
	"testing"
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
			if strings.ContainsAny(got, "\x1b\r‮​") || !strings.Contains(got, `\u001b`) {
				t.Fatalf("control characters survived: %q", got)
			}
			return
		}
		if tc.wantSuffix != "" {
			if !strings.HasSuffix(got, tc.wantSuffix) || len([]rune(got)) > tc.wantMaxRune {
				t.Fatalf("not truncated: %q", got)
			}
			return
		}
		if got != tc.want {
			t.Fatal("plain text altered")
		}
	}

	t.Run("escapes control characters", func(t *testing.T) {
		tester(t, testCase{
			in:         "GET /x\x1b[2K\rGET /harmless‮​",
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
