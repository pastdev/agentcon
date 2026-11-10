package creds

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

func TestParseProvided(t *testing.T) {
	type testCase struct {
		in      string
		wantErr bool
		echo    string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := ParseProvided(strings.NewReader(tc.in))
		if tc.wantErr {
			require.Error(t, err)
			if tc.echo != "" {
				assert.NotContains(t, err.Error(), tc.echo, "error echoes input")
			}
			return
		}
		require.NoError(t, err)
		require.Equal(t, "glpat-abc: #not a comment 'quoted'", got["gitlab"])
		require.Equal(t, "ghp_nospace", got["github"])
		store := NewStore(map[string]*config.Credential{
			"gitlab":     {Name: "gitlab", Token: &config.ValueSource{Source: "keyring"}},
			"deploy-key": {Name: "deploy-key", PrivateKey: &config.ValueSource{Source: "provided"}},
			"other":      {Name: "other", Token: &config.ValueSource{Source: "provided"}},
		})
		store.SetProvided(map[string]string{
			config.ProvidedKey("gitlab", config.SlotToken):          got["gitlab"],
			config.ProvidedKey("deploy-key", config.SlotPrivateKey): got["deploy-key"],
		})
		v, err := store.Get(context.Background(), "gitlab")
		require.NoError(t, err)
		assert.Equal(t, got["gitlab"], v.Token, "provided value should override keyring")
		signers, err := store.SSHSigners(context.Background(), "deploy-key")
		require.NoError(t, err)
		assert.Len(t, signers, 1, "multi-line key via base64")
		assert.Equal(t, []string{config.ProvidedKey("other", config.SlotToken)}, store.MissingProvided())
		_, err = store.Get(context.Background(), "other")
		require.ErrorContains(t, err, "no value provided")
	}

	t.Run("parses tokens and a multi-line key", func(t *testing.T) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		block, err := ssh.MarshalPrivateKey(k, "")
		require.NoError(t, err)
		keyPEM := pem.EncodeToMemory(block)
		in := "# generated\n" +
			"gitlab: glpat-abc: #not a comment 'quoted'\n" +
			"\n" +
			"github:ghp_nospace\r\n" +
			"deploy-key:: " + base64.StdEncoding.EncodeToString(keyPEM) + "\n"
		tester(t, testCase{in: in})
	})
	t.Run("rejects a duplicate name", func(t *testing.T) {
		tester(t, testCase{in: "a: 1\na: 2\n", wantErr: true})
	})
	t.Run("rejects an empty value", func(t *testing.T) {
		tester(t, testCase{in: "a: \n", wantErr: true})
	})
	t.Run("rejects a line with no colon", func(t *testing.T) {
		tester(t, testCase{in: "just-a-secret\n", wantErr: true, echo: "just-a-secret"})
	})
	t.Run("rejects a bad name", func(t *testing.T) {
		tester(t, testCase{in: "bad name: x\n", wantErr: true})
	})
	t.Run("rejects bad base64", func(t *testing.T) {
		tester(t, testCase{in: "a:: !!!\n", wantErr: true})
	})
}

func TestSSHSigners(t *testing.T) {
	type testCase struct {
		src   string
		pem   string
		wantN int
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		store := NewStore(map[string]*config.Credential{
			"deploy": {Name: "deploy", PrivateKey: &config.ValueSource{Source: tc.src}},
		})
		store.SetProvided(map[string]string{
			config.ProvidedKey("deploy", config.SlotPrivateKey): tc.pem,
		})
		signers, err := store.SSHSigners(context.Background(), "deploy")
		require.NoError(t, err)
		assert.Len(t, signers, tc.wantN)
	}

	t.Run("overlays a provided key on an ssh-agent source", func(t *testing.T) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		block, err := ssh.MarshalPrivateKey(k, "")
		require.NoError(t, err)
		keyPEM := strings.TrimRight(string(pem.EncodeToMemory(block)), "\n")
		tester(t, testCase{src: "ssh-agent", pem: keyPEM, wantN: 1})
	})
}
