package host

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckPromptable(t *testing.T) {
	type testCase struct {
		policy  string
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		err := CheckPromptable([]byte(tc.policy))
		if tc.wantErr == "" {
			require.NoError(t, err)
			return
		}
		require.ErrorContains(t, err, tc.wantErr)
	}
	bitwarden := func(password string) string {
		return `bitwarden:
  work:
    email: user@example.com
` + password + `  unused:
    email: unused@example.com
credentials:
  bw:
    token:
      source: bitwarden
      account: work
      item: GitLab
      path: $.login.password
`
	}

	t.Run("allows bitwarden when run can answer", func(t *testing.T) {
		tester(t, testCase{policy: bitwarden("")})
	})
	t.Run("refuses an account nothing can unlock", func(t *testing.T) {
		tester(t, testCase{policy: "prompts: {cli: false}\n" + bitwarden(""), wantErr: "bitwarden accounts work have no password"})
	})
	t.Run("allows an account password without the cli", func(t *testing.T) {
		tester(t, testCase{policy: "prompts: {cli: false}\n" + bitwarden("    password: {source: env, env: BW_MASTER}\n")})
	})
	t.Run("allows no cli without bitwarden", func(t *testing.T) {
		tester(t, testCase{policy: "prompts: {cli: false}\n"})
	})
}
