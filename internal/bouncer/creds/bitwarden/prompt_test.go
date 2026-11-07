package bitwarden

import (
	"errors"
	"testing"
)

func TestTwoFactorCode(t *testing.T) {
	type testCase struct {
		p       *StaticPrompter
		want    string
		wantErr bool
		method  string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := tc.p.TwoFactorCode("user@example.com", "authenticator app")
		if tc.wantErr {
			var need *NeedCodeError
			if !errors.As(err, &need) || need.Method != tc.method {
				t.Fatalf("got %v", err)
			}
			return
		}
		if err != nil || got != tc.want {
			t.Fatalf("got %q %v", got, err)
		}
	}

	t.Run("returns need code when no code is set", func(t *testing.T) {
		tester(t, testCase{
			p:       &StaticPrompter{Password: "pw"},
			wantErr: true,
			method:  "authenticator app",
		})
	})
	t.Run("returns a supplied code once", func(t *testing.T) {
		tester(t, testCase{
			p:    &StaticPrompter{Password: "pw", Code: "123456"},
			want: "123456",
		})
	})
	t.Run("returns need code after the one-shot code is used", func(t *testing.T) {
		p := &StaticPrompter{Password: "pw", Code: "123456"}
		_, err := p.TwoFactorCode("user@example.com", "authenticator app")
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{p: p, wantErr: true, method: "authenticator app"})
	})
}
