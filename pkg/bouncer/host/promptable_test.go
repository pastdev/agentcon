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
	bitwarden := func(extra string) string {
		return `credentials:
  bw:
    token:
      source: bitwarden
      email: user@example.com
      item: GitLab
      path: $.login.password
` + extra
	}

	t.Run("allows bitwarden when run can answer", func(t *testing.T) {
		tester(t, testCase{policy: bitwarden("")})
	})
	t.Run("refuses bitwarden nothing can unlock", func(t *testing.T) {
		tester(t, testCase{policy: "prompts: {cli: false}\n" + bitwarden(""), wantErr: "credentials bw use bitwarden without password_env"})
	})
	t.Run("allows password_env without the cli", func(t *testing.T) {
		tester(t, testCase{policy: "prompts: {cli: false}\n" + bitwarden("      password_env: BW_MASTER\n")})
	})
	t.Run("allows no cli without bitwarden", func(t *testing.T) {
		tester(t, testCase{policy: "prompts: {cli: false}\n"})
	})
}
