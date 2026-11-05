package run

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/mgmt"
)

const testAuthenticator = "authenticator app"

func TestCompleteBitwardenUnlockNeedCode(t *testing.T) {
	var codes []string
	unlock := func(_ string, code string) error {
		codes = append(codes, code)
		if code == "" {
			return &mgmt.NeedCodeError{Method: testAuthenticator}
		}
		if code != "123456" {
			return fmt.Errorf("bitwarden: Invalid TOTP code")
		}
		return nil
	}
	prompts := 0
	err := completeBitwardenUnlock(unlock, "pw", func(method string) (string, error) {
		prompts++
		if method != testAuthenticator {
			t.Fatalf("method %q", method)
		}
		return "123456", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if prompts != 1 || strings.Join(codes, ",") != ",123456" {
		t.Fatalf("codes %v prompts %d", codes, prompts)
	}
}

func TestCompleteBitwardenUnlockRetriesInvalidTOTP(t *testing.T) {
	n := 0
	unlock := func(_ string, code string) error {
		if code == "" {
			return &mgmt.NeedCodeError{Method: testAuthenticator}
		}
		n++
		if n == 1 {
			return fmt.Errorf("bitwarden: Invalid TOTP code")
		}
		return nil
	}
	codes := []string{"000000", "123456"}
	err := completeBitwardenUnlock(unlock, "pw", func(string) (string, error) {
		if len(codes) == 0 {
			t.Fatal("extra prompt")
		}
		c := codes[0]
		codes = codes[1:]
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCompleteBitwardenUnlockRetriesNeedCode(t *testing.T) {
	n := 0
	unlock := func(_ string, code string) error {
		n++
		if code == "" || code == "000000" {
			return &mgmt.NeedCodeError{Method: testAuthenticator}
		}
		if code != "123456" {
			t.Fatalf("code %q", code)
		}
		return nil
	}
	codes := []string{"000000", "123456"}
	err := completeBitwardenUnlock(unlock, "pw", func(string) (string, error) {
		if len(codes) == 0 {
			t.Fatal("extra prompt")
		}
		c := codes[0]
		codes = codes[1:]
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("unlocks %d", n)
	}
}

func TestCompleteBitwardenUnlockWrongPassword(t *testing.T) {
	err := completeBitwardenUnlock(func(string, string) error {
		return errors.New("bitwarden: incorrect master password")
	}, "pw", func(string) (string, error) {
		t.Fatal("prompted for code")
		return "", nil
	})
	if err == nil || !strings.Contains(err.Error(), "incorrect master password") {
		t.Fatalf("got %v", err)
	}
}
