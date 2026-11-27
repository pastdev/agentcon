package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const signerCreds = `
credentials:
  sign-a:
    allow: [internal]
    private_key: {source: provided}
    password: {source: provided}
  sign-b:
    allow: [internal]
    private_key: {source: provided}
  plain:
    allow: [agent, subrequest]
    token: {source: provided}
`

func TestParseSigner(t *testing.T) {
	type testCase struct {
		yaml    string
		wantErr string
		check   func(*testing.T, *Config)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		cfg, err := Parse([]byte(tc.yaml), "/tmp/cfg/config.yaml")
		if tc.wantErr != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			return
		}
		require.NoError(t, err)
		if tc.check != nil {
			tc.check(t, cfg)
		}
	}
	signerProfile := func(keys string) string {
		return signerCreds + `
profiles:
  p:
    http:
      - name: signing
        hosts: [signer.bouncer.internal]
        signer:
          openpgp:
            keys:
` + keys
	}

	t.Run("normalizes key ids", func(t *testing.T) {
		tester(t, testCase{
			yaml: signerProfile(`              - {id: 0x7c44826b7b1878a0, credential: sign-a}
              - {id: c26e02ce599b53ff, credential: sign-b}
`),
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				keys := cfg.Profiles["p"].HTTP[0].Signer.OpenPGP.Keys
				assert.Equal(t, "7C44826B7B1878A0", keys[0].ID)
				assert.Equal(t, "C26E02CE599B53FF", keys[1].ID)
				assert.Equal(t, "signing", cfg.Profiles["p"].SignerService().Name)
			},
		})
	})
	t.Run("refuses an unknown credential", func(t *testing.T) {
		tester(t, testCase{
			yaml:    signerProfile("              - {id: 7C44826B7B1878A0, credential: nope}\n"),
			wantErr: `unknown credential "nope"`,
		})
	})
	t.Run("refuses a credential that is not internal", func(t *testing.T) {
		tester(t, testCase{
			yaml:    signerProfile("              - {id: 7C44826B7B1878A0, credential: plain}\n"),
			wantErr: "must be allow: [internal]",
		})
	})
	t.Run("refuses a bad key id", func(t *testing.T) {
		tester(t, testCase{
			yaml:    signerProfile("              - {id: 7C44826B, credential: sign-a}\n"),
			wantErr: "want 16, 40, or 64 hex digits",
		})
	})
	t.Run("refuses a repeated key", func(t *testing.T) {
		tester(t, testCase{
			yaml: signerProfile(`              - {id: 0123456789ABCDEF0123456789ABCDEF01234567, credential: sign-a}
              - {id: 89abcdef01234567, credential: sign-b}
`),
			wantErr: "repeats keys[0]",
		})
	})
	t.Run("refuses empty keys", func(t *testing.T) {
		tester(t, testCase{
			yaml:    strings.TrimSuffix(signerProfile(""), "            keys:\n") + "            keys: []\n",
			wantErr: "keys is required",
		})
	})
	for _, field := range []string{"credentials: [plain]", "allow_upgrade: true", "insecure: true"} {
		t.Run("refuses a signer with "+field, func(t *testing.T) {
			tester(t, testCase{
				yaml: signerCreds + `
profiles:
  p:
    http:
      - name: signing
        hosts: [signer.bouncer.internal]
        ` + field + `
        signer:
          openpgp:
            keys: [{id: 7C44826B7B1878A0, credential: sign-a}]
`,
				wantErr: "signer service may not set",
			})
		})
	}
	t.Run("refuses a signing credential with another slot", func(t *testing.T) {
		tester(t, testCase{
			yaml: `
credentials:
  sign-a:
    allow: [internal]
    private_key: {source: provided}
    token: {source: provided}
profiles:
  p:
    http:
      - name: signing
        hosts: [signer.bouncer.internal]
        signer:
          openpgp:
            keys: [{id: 7C44826B7B1878A0, credential: sign-a}]
`,
			wantErr: "takes only private_key and password",
		})
	})
	t.Run("refuses a signing credential from ssh-agent", func(t *testing.T) {
		tester(t, testCase{
			yaml: `
credentials:
  sign-a:
    allow: [internal]
    private_key: {source: ssh-agent}
profiles:
  p:
    http:
      - name: signing
        hosts: [signer.bouncer.internal]
        signer:
          openpgp:
            keys: [{id: 7C44826B7B1878A0, credential: sign-a}]
`,
			wantErr: "ssh-agent cannot hold an OpenPGP key",
		})
	})
	t.Run("refuses two signers in a resolved profile", func(t *testing.T) {
		tester(t, testCase{
			yaml: signerCreds + `
profiles:
  base:
    http:
      - name: signing
        hosts: [signer.bouncer.internal]
        signer:
          openpgp:
            keys: [{id: 7C44826B7B1878A0, credential: sign-a}]
  child:
    extends: base
    http:
      - name: signing-2
        hosts: [signer2.bouncer.internal]
        signer:
          openpgp:
            keys: [{id: 7C44826B7B1878A0, credential: sign-a}]
`,
			wantErr: "more than one signer service",
		})
	})
	t.Run("refuses a wildcard signer host", func(t *testing.T) {
		tester(t, testCase{
			yaml: signerCreds + `
profiles:
  p:
    http:
      - name: signing
        hosts: ["*.bouncer.internal"]
        signer:
          openpgp:
            keys: [{id: 7C44826B7B1878A0, credential: sign-a}]
`,
			wantErr: "must be exact names",
		})
	})
	t.Run("signer url uses the first host", func(t *testing.T) {
		tester(t, testCase{
			yaml: signerCreds + `
profiles:
  p:
    http:
      - name: signing
        hosts: [Signer.Bouncer.Internal, other.internal]
        signer:
          openpgp:
            keys: [{id: 7C44826B7B1878A0, credential: sign-a}]
  none: {}
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, "https://signer.bouncer.internal/openpgp/sign", cfg.Profiles["p"].SignerService().SignerURL())
				assert.Empty(t, cfg.Profiles["none"].SignerService().SignerURL())
			},
		})
	})
	t.Run("refuses an internal credential on an http service", func(t *testing.T) {
		tester(t, testCase{
			yaml: signerCreds + `
profiles:
  p:
    http:
      - name: gh
        hosts: [github.com]
        credentials: [sign-a]
`,
			wantErr: `credential "sign-a" is internal and is never sent`,
		})
	})
	t.Run("refuses an internal credential on an ssh service", func(t *testing.T) {
		tester(t, testCase{
			yaml: signerCreds + `
profiles:
  p:
    ssh:
      - name: gh
        hosts: [github.com]
        credential: sign-b
`,
			wantErr: `credential "sign-b" must allow agent`,
		})
	})
	t.Run("refuses an internal credential with export_env", func(t *testing.T) {
		tester(t, testCase{
			yaml: `
credentials:
  sign-a:
    allow: [internal]
    private_key: {source: provided}
    export_env: [GPG_KEY]
`,
			wantErr: "export_env requires allow agent",
		})
	})
}

func TestKeyIDsMatch(t *testing.T) {
	type testCase struct {
		a, b string
		want bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, KeyIDsMatch(tc.a, tc.b))
	}
	v4 := "0123456789ABCDEF0123456789ABCDEF01234567"
	v6 := strings.Repeat("ABCDEF0123456789", 4)

	t.Run("equal long ids", func(t *testing.T) {
		tester(t, testCase{a: "89ABCDEF01234567", b: "89ABCDEF01234567", want: true})
	})
	t.Run("v4 fingerprint and its long id", func(t *testing.T) {
		tester(t, testCase{a: v4, b: "89ABCDEF01234567", want: true})
	})
	t.Run("long id and v4 fingerprint", func(t *testing.T) {
		tester(t, testCase{a: "89ABCDEF01234567", b: v4, want: true})
	})
	t.Run("v6 fingerprint and its long id", func(t *testing.T) {
		tester(t, testCase{a: v6, b: "ABCDEF0123456789", want: true})
	})
	t.Run("v4 fingerprint and the wrong long id", func(t *testing.T) {
		tester(t, testCase{a: v4, b: "0123456789ABCDEF", want: false})
	})
	t.Run("different fingerprints", func(t *testing.T) {
		tester(t, testCase{a: v4, b: strings.Repeat("0", 40), want: false})
	})
}

func TestNormalizeKeyID(t *testing.T) {
	type testCase struct {
		in, want string
		wantErr  bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := NormalizeKeyID(tc.in)
		if tc.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("lowercase with 0x", func(t *testing.T) {
		tester(t, testCase{in: "0x7c44826b7b1878a0", want: "7C44826B7B1878A0"})
	})
	t.Run("gpg subkey bang", func(t *testing.T) {
		tester(t, testCase{in: "7C44826B7B1878A0!", want: "7C44826B7B1878A0"})
	})
	t.Run("short key id", func(t *testing.T) {
		tester(t, testCase{in: "7B1878A0", wantErr: true})
	})
	t.Run("email", func(t *testing.T) {
		tester(t, testCase{in: "Agent <agent@example.com>", wantErr: true})
	})
	t.Run("non-hex", func(t *testing.T) {
		tester(t, testCase{in: "7C44826B7B1878AZ", wantErr: true})
	})
}
