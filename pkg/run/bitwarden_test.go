package run

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/mgmt"
)

func TestCompleteBitwardenUnlock(t *testing.T) {
	errNeedCode := &mgmt.NeedCodeError{Method: "authenticator app"}
	errInvalidTOTP := fmt.Errorf("bitwarden: Invalid TOTP code")
	errBadPassword := errors.New("bitwarden: incorrect master password")

	type unlockStep struct {
		code string
		err  error
	}
	type testCase struct {
		steps   []unlockStep
		codes   []string
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		n := 0
		unlock := func(_ string, code string) error {
			if n >= len(tc.steps) {
				t.Fatalf("extra unlock code %q", code)
			}
			step := tc.steps[n]
			n++
			if code != step.code {
				t.Fatalf("unlock %d code %q want %q", n, code, step.code)
			}
			return step.err
		}
		prompt := 0
		err := completeBitwardenUnlock(unlock, "pw", func(method string) (string, error) {
			if prompt >= len(tc.codes) {
				t.Fatal("extra prompt")
			}
			if method != "" && method != "authenticator app" {
				t.Fatalf("method %q", method)
			}
			code := tc.codes[prompt]
			prompt++
			return code, nil
		})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if n != len(tc.steps) {
			t.Fatalf("unlocks %d want %d", n, len(tc.steps))
		}
		if prompt != len(tc.codes) {
			t.Fatalf("prompts %d want %d", prompt, len(tc.codes))
		}
	}

	t.Run("need code then totp", func(t *testing.T) {
		tester(t, testCase{
			steps: []unlockStep{
				{code: "", err: errNeedCode},
				{code: "123456"},
			},
			codes: []string{"123456"},
		})
	})

	t.Run("retries invalid totp", func(t *testing.T) {
		tester(t, testCase{
			steps: []unlockStep{
				{code: "", err: errNeedCode},
				{code: "000000", err: errInvalidTOTP},
				{code: "123456"},
			},
			codes: []string{"000000", "123456"},
		})
	})

	t.Run("retries need code", func(t *testing.T) {
		tester(t, testCase{
			steps: []unlockStep{
				{code: "", err: errNeedCode},
				{code: "000000", err: errNeedCode},
				{code: "123456"},
			},
			codes: []string{"000000", "123456"},
		})
	})

	t.Run("wrong password", func(t *testing.T) {
		tester(t, testCase{
			steps: []unlockStep{
				{code: "", err: errBadPassword},
			},
			wantErr: errBadPassword.Error(),
		})
	})
}
