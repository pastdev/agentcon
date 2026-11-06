package bitwarden

import (
	"errors"
	"testing"
)

func TestStaticPrompterNeedCode(t *testing.T) {
	p := &StaticPrompter{Password: "pw"}
	_, err := p.TwoFactorCode("user@example.com", "authenticator app")
	var need *NeedCodeError
	if !errors.As(err, &need) || need.Method != "authenticator app" {
		t.Fatalf("got %v", err)
	}
	p.Code = "123456"
	got, err := p.TwoFactorCode("user@example.com", "authenticator app")
	if err != nil || got != "123456" {
		t.Fatalf("got %q %v", got, err)
	}
	_, err = p.TwoFactorCode("user@example.com", "authenticator app")
	if !errors.As(err, &need) {
		t.Fatalf("expected one-shot code, got %v", err)
	}
}
