package creds

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

func TestParseProvided(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(k, "")
	keyPEM := pem.EncodeToMemory(block)
	in := "# generated\n" +
		"gitlab: glpat-abc: #not a comment 'quoted'\n" +
		"\n" +
		"github:ghp_nospace\r\n" +
		"deploy-key:: " + base64.StdEncoding.EncodeToString(keyPEM) + "\n"
	got, err := ParseProvided(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if got["gitlab"] != "glpat-abc: #not a comment 'quoted'" || got["github"] != "ghp_nospace" {
		t.Fatalf("%q", got)
	}
	store := NewStore(map[string]*config.Credential{
		"gitlab":     {Name: "gitlab", Token: &config.ValueSource{Source: "keyring"}},
		"deploy-key": {Name: "deploy-key", PrivateKey: &config.ValueSource{Source: "provided"}},
		"other":      {Name: "other", Token: &config.ValueSource{Source: "provided"}},
	})
	store.SetProvided(map[string]string{
		config.ProvidedKey("gitlab", config.SlotToken):          got["gitlab"],
		config.ProvidedKey("deploy-key", config.SlotPrivateKey): got["deploy-key"],
	})
	if v, err := store.Get(context.Background(), "gitlab"); err != nil || v.Token != got["gitlab"] {
		t.Fatalf("provided value should override keyring: %+v %v", v, err)
	}
	if signers, err := store.SSHSigners(context.Background(), "deploy-key"); err != nil || len(signers) != 1 {
		t.Fatalf("multi-line key via base64: %v", err)
	}
	if m := store.MissingProvided(); len(m) != 1 || m[0] != config.ProvidedKey("other", config.SlotToken) {
		t.Fatalf("missing: %v", m)
	}
	if _, err := store.Get(context.Background(), "other"); err == nil || !strings.Contains(err.Error(), "no value provided") {
		t.Fatalf("err = %v", err)
	}
}

func TestSSHSignersProvidedOverlayOnAgent(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(k, "")
	keyPEM := strings.TrimRight(string(pem.EncodeToMemory(block)), "\n")
	store := NewStore(map[string]*config.Credential{
		"deploy": {Name: "deploy", PrivateKey: &config.ValueSource{Source: "ssh-agent"}},
	})
	store.SetProvided(map[string]string{
		config.ProvidedKey("deploy", config.SlotPrivateKey): keyPEM,
	})
	signers, err := store.SSHSigners(context.Background(), "deploy")
	if err != nil || len(signers) != 1 {
		t.Fatalf("signers %v %v", signers, err)
	}
}

func TestParseProvidedErrors(t *testing.T) {
	for name, in := range map[string]string{
		"duplicate":  "a: 1\na: 2\n",
		"empty":      "a: \n",
		"no colon":   "just-a-secret\n",
		"bad name":   "bad name: x\n",
		"bad base64": "a:: !!!\n",
	} {
		_, err := ParseProvided(strings.NewReader(in))
		if err == nil {
			t.Errorf("%s: expected error", name)
		} else if strings.Contains(err.Error(), "just-a-secret") {
			t.Errorf("%s: error echoes input: %v", name, err)
		}
	}
}
