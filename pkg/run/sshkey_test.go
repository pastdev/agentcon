package run

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const (
	testSSHPass     = "correct horse"
	testSSHPassBad  = "nope"
	testSSHCredName = "deploy"
)

func testSSHPEM(t *testing.T, passphrase string) (plain, encrypted string, pub ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plainBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(plainBlock)), string(pem.EncodeToMemory(encBlock)), signer.PublicKey()
}

func TestUnlockSSHKey(t *testing.T) {
	plain, encrypted, pub := testSSHPEM(t, testSSHPass)

	type testCase struct {
		pem     string
		prompts []string
		wantErr string
		wantPub ssh.PublicKey
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		n := 0
		got, err := unlockSSHKey(tc.pem, func(name string) (string, error) {
			if name != testSSHCredName {
				t.Fatalf("prompt name %q", name)
			}
			if n >= len(tc.prompts) {
				t.Fatal("extra prompt")
			}
			pass := tc.prompts[n]
			n++
			return pass, nil
		}, testSSHCredName)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if n != len(tc.prompts) {
			t.Fatalf("prompts %d want %d", n, len(tc.prompts))
		}
		if tc.wantPub == nil {
			if got != tc.pem {
				t.Fatalf("rewrote non-key %q", got)
			}
			return
		}
		signer, err := ssh.ParsePrivateKey([]byte(got + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if signer.PublicKey().Type() != tc.wantPub.Type() {
			t.Fatalf("pub type %s", signer.PublicKey().Type())
		}
	}

	t.Run("plain key", func(t *testing.T) {
		tester(t, testCase{pem: plain, wantPub: pub})
	})
	t.Run("not a key", func(t *testing.T) {
		tester(t, testCase{pem: testFromFile})
	})
	t.Run("encrypted key", func(t *testing.T) {
		tester(t, testCase{
			pem:     encrypted,
			prompts: []string{testSSHPass},
			wantPub: pub,
		})
	})
	t.Run("retries bad passphrase", func(t *testing.T) {
		tester(t, testCase{
			pem:     encrypted,
			prompts: []string{testSSHPassBad, testSSHPass},
			wantPub: pub,
		})
	})
	t.Run("rejects after attempts", func(t *testing.T) {
		tester(t, testCase{
			pem:     encrypted,
			prompts: []string{testSSHPassBad, testSSHPassBad, testSSHPassBad},
			wantErr: "passphrase rejected",
		})
	})
}

func TestUnlockHostSSHKeys(t *testing.T) {
	plain, encrypted, _ := testSSHPEM(t, testSSHPass)
	sshKey := testSSHCredName + ".private_key"
	values := map[string]string{
		testCredTok: encrypted,
		sshKey:      encrypted,
		"other":     plain,
	}
	err := unlockHostSSHKeys(values, map[string]struct{}{sshKey: {}}, func(name string) (string, error) {
		if name != sshKey {
			t.Fatalf("prompted for %q", name)
		}
		return testSSHPass, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if values[testCredTok] != encrypted {
		t.Fatal("unlocked a file that is not an ssh credential")
	}
	_, err = ssh.ParsePrivateKey([]byte(values[sshKey] + "\n"))
	if err != nil {
		t.Fatalf("unlocked: %v", err)
	}
}

func TestSSHKeyCredentialNames(t *testing.T) {
	got, err := sshKeyCredentialNames([]byte(`
credentials:
  deploy:
    private_key:
      source: file
      file: /tmp/id
  tok:
    token:
      source: file
      file: /tmp/token
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[testSSHCredName+".private_key"]; !ok || len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}
