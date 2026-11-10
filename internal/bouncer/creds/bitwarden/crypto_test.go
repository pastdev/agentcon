package bitwarden

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

func TestDeriveIdentity(t *testing.T) {
	type testCase struct {
		email      string
		password   string
		params     kdfParams
		wantHash   string
		wantEnc    string
		wantMac    string
		argonCheck bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		id, err := deriveIdentity(tc.email, tc.password, tc.params)
		require.NoError(t, err)
		if tc.wantHash != "" {
			assert.Equal(t, tc.wantHash, base64.StdEncoding.EncodeToString(id.passwordHash))
		}
		if tc.wantEnc != "" {
			assert.Equal(t, tc.wantEnc, hex.EncodeToString(id.keys.enc))
		}
		if tc.wantMac != "" {
			assert.Equal(t, tc.wantMac, hex.EncodeToString(id.keys.mac))
		}
		if tc.argonCheck {
			sum := sha256.Sum256([]byte(tc.email))
			master := argon2.IDKey([]byte(tc.password), sum[:], 1, 8*1024, 1, 32)
			require.Equal(t, "957117176630530b004986b6971e959b78da576af89d4c4eebae54a7df001d3f", hex.EncodeToString(master), "argon2 vector drifted")
			k, err := keysFromMaterial(master)
			require.NoError(t, err)
			assert.Equal(t, k, id.keys, "argon2 identity was not stretched with HKDF")
		}
	}

	t.Run("matches an independent pbkdf2 vector", func(t *testing.T) {
		tester(t, testCase{
			email:    "user@example.com",
			password: "correct horse battery staple",
			params:   kdfParams{kind: kdfPBKDF2, iterations: 1000},
			wantHash: "8vx9APjb5Q1wtLcQUtQiEautn2Wd5oBGzkZeyYe9tV4=",
			wantEnc:  "a9737f1c8acc561ea1243e4884b3e6e2d29f40db8eaa86627a25f690541f410c",
			wantMac:  "33609f2687de4539dc4038091a460dc9146eb68f1c7bc01d6816fa69c5711cc5",
		})
	})
	t.Run("stretches argon2 with hkdf", func(t *testing.T) {
		tester(t, testCase{
			email:      "user@example.com",
			password:   "password",
			params:     kdfParams{kind: kdfArgon2id, iterations: 1, memory: 8, parallelism: 1},
			argonCheck: true,
		})
	})
}

func TestDecryptString(t *testing.T) {
	type testCase struct {
		material   []byte
		plain      string
		wrongKey   []byte
		wantBadMAC bool
		wantSplit  bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		k, err := keysFromMaterial(tc.material)
		require.NoError(t, err)
		if tc.wantSplit {
			assert.Len(t, k.enc, 32)
			assert.Equal(t, tc.material[32:], k.mac)
			return
		}
		enc, err := encryptSymmetric(k, []byte(tc.plain))
		require.NoError(t, err)
		if tc.wantBadMAC {
			other, err := keysFromMaterial(tc.wrongKey)
			require.NoError(t, err)
			_, err = decryptString(other, enc)
			require.ErrorIs(t, err, errBadMAC)
			return
		}
		got, err := decryptString(k, enc)
		require.NoError(t, err)
		assert.Equal(t, tc.plain, got)
	}

	t.Run("round-trips a secret", func(t *testing.T) {
		tester(t, testCase{material: bytes.Repeat([]byte{7}, 32), plain: "secret-token"})
	})
	t.Run("rejects a ciphertext with a bad mac", func(t *testing.T) {
		tester(t, testCase{
			material:   bytes.Repeat([]byte{7}, 32),
			plain:      "secret-token",
			wrongKey:   bytes.Repeat([]byte{8}, 32),
			wantBadMAC: true,
		})
	})
	t.Run("splits 64-byte material into enc and mac keys", func(t *testing.T) {
		tester(t, testCase{material: bytes.Repeat([]byte{9}, 64), wantSplit: true})
	})
}

func TestEndpoints(t *testing.T) {
	type testCase struct {
		server  string
		wantAPI string
		wantID  string
		wantErr bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		api, id, err := endpoints(tc.server)
		if tc.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.wantAPI, api)
		assert.Equal(t, tc.wantID, id)
	}

	t.Run("uses the default cloud endpoints", func(t *testing.T) {
		tester(t, testCase{server: "", wantAPI: "https://api.bitwarden.com", wantID: "https://identity.bitwarden.com"})
	})
	t.Run("uses the eu cloud endpoints", func(t *testing.T) {
		tester(t, testCase{server: "https://vault.bitwarden.eu/", wantAPI: "https://api.bitwarden.eu", wantID: "https://identity.bitwarden.eu"})
	})
	t.Run("uses self-hosted api and identity paths", func(t *testing.T) {
		tester(t, testCase{server: "https://vault.example.com/bw", wantAPI: "https://vault.example.com/bw/api", wantID: "https://vault.example.com/bw/identity"})
	})
	t.Run("rejects userinfo in the server url", func(t *testing.T) {
		tester(t, testCase{server: "https://user:pass@vault.example.com", wantErr: true}) //nolint:gosec // fake credentials the test expects to be rejected
	})
}

func TestDecodeBW(t *testing.T) {
	type testCase struct {
		body []byte
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		var res preloginResponse
		err := decodeBW(tc.body, &res)
		require.NoError(t, err)
		assert.Equal(t, preloginResponse{KDF: 1, KDFIterations: 3, KDFParallel: 4}, res)
	}

	t.Run("decodes pascal-case prelogin json", func(t *testing.T) {
		tester(t, testCase{body: []byte(`{"Kdf":"1","KdfIterations":3,"KdfMemory":null,"KdfParallelism":4}`)})
	})
}
