package run

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func testSSHPEM(t *testing.T, passphrase string) (plain, encrypted string, pub ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	plainBlock, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(plainBlock)), string(pem.EncodeToMemory(encBlock)), signer.PublicKey()
}

func TestUnlockSSHKey(t *testing.T) {
	plain, encrypted, pub := testSSHPEM(t, "correct horse")

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
			require.Equal(t, "deploy", name)
			require.Less(t, n, len(tc.prompts), "extra prompt")
			pass := tc.prompts[n]
			n++
			return pass, nil
		}, "deploy")
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Len(t, tc.prompts, n, "prompts")
		if tc.wantPub == nil {
			assert.Equal(t, tc.pem, got, "rewrote non-key")
			return
		}
		signer, err := ssh.ParsePrivateKey([]byte(got + "\n"))
		require.NoError(t, err)
		assert.Equal(t, tc.wantPub.Type(), signer.PublicKey().Type())
	}

	t.Run("plain key", func(t *testing.T) {
		tester(t, testCase{pem: plain, wantPub: pub})
	})
	t.Run("not a key", func(t *testing.T) {
		tester(t, testCase{pem: "not a key"})
	})
	t.Run("encrypted key", func(t *testing.T) {
		tester(t, testCase{
			pem:     encrypted,
			prompts: []string{"correct horse"},
			wantPub: pub,
		})
	})
	t.Run("retries bad passphrase", func(t *testing.T) {
		tester(t, testCase{
			pem:     encrypted,
			prompts: []string{"nope", "correct horse"},
			wantPub: pub,
		})
	})
	t.Run("rejects after attempts", func(t *testing.T) {
		tester(t, testCase{
			pem:     encrypted,
			prompts: []string{"nope", "nope", "nope"},
			wantErr: "passphrase rejected",
		})
	})
}

func TestUnlockHostSSHKeys(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		plain, encrypted, _ := testSSHPEM(t, "correct horse")
		sshKey := "deploy.private_key"
		values := map[string]string{
			"tok":   encrypted,
			sshKey:  encrypted,
			"other": plain,
		}
		err := unlockHostSSHKeys(values, map[string]struct{}{sshKey: {}}, func(name string) (string, error) {
			require.Equal(t, sshKey, name)
			return "correct horse", nil
		})
		require.NoError(t, err)
		assert.Equal(t, encrypted, values["tok"], "unlocked a file that is not an ssh credential")
		_, err = ssh.ParsePrivateKey([]byte(values[sshKey] + "\n"))
		assert.NoError(t, err, "unlocked")
	}

	t.Run("unlocks only ssh credential keys", func(t *testing.T) {
		tester(t)
	})
}

func TestSSHKeyCredentialNames(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
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
		require.NoError(t, err)
		assert.Equal(t, map[string]struct{}{"deploy.private_key": {}}, got)
	}

	t.Run("returns private_key slot names", func(t *testing.T) {
		tester(t)
	})
}
