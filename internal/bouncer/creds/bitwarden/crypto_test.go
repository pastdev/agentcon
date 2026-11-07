package bitwarden

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

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
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantHash != "" {
			if got := base64.StdEncoding.EncodeToString(id.passwordHash); got != tc.wantHash {
				t.Fatalf("password hash %s", got)
			}
		}
		if tc.wantEnc != "" && hex.EncodeToString(id.keys.enc) != tc.wantEnc {
			t.Fatalf("enc key %x", id.keys.enc)
		}
		if tc.wantMac != "" && hex.EncodeToString(id.keys.mac) != tc.wantMac {
			t.Fatalf("mac key %x", id.keys.mac)
		}
		if tc.argonCheck {
			sum := sha256.Sum256([]byte(tc.email))
			master := argon2.IDKey([]byte(tc.password), sum[:], 1, 8*1024, 1, 32)
			if hex.EncodeToString(master) != "957117176630530b004986b6971e959b78da576af89d4c4eebae54a7df001d3f" {
				t.Fatalf("argon2 vector drifted: %x", master)
			}
			k, err := keysFromMaterial(master)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(id.keys.enc, k.enc) || !bytes.Equal(id.keys.mac, k.mac) {
				t.Fatal("argon2 identity was not stretched with HKDF")
			}
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
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantSplit {
			if len(k.enc) != 32 || !bytes.Equal(k.mac, tc.material[32:]) {
				t.Fatalf("split: %x %v", k.mac, err)
			}
			return
		}
		enc, err := encryptSymmetric(k, []byte(tc.plain))
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantBadMAC {
			other, err := keysFromMaterial(tc.wrongKey)
			if err != nil {
				t.Fatal(err)
			}
			_, err = decryptString(other, enc)
			if !errors.Is(err, errBadMAC) {
				t.Fatalf("err = %v", err)
			}
			return
		}
		got, err := decryptString(k, enc)
		if err != nil || got != tc.plain {
			t.Fatalf("got %q, %v", got, err)
		}
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
			if err == nil {
				t.Fatal("expected userinfo to be rejected")
			}
			return
		}
		if err != nil || api != tc.wantAPI || id != tc.wantID {
			t.Fatalf("%s %s %v", api, id, err)
		}
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
		tester(t, testCase{server: "https://user:pass@vault.example.com", wantErr: true})
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
		if err != nil {
			t.Fatal(err)
		}
		if res.KDF != 1 || res.KDFIterations != 3 || res.KDFMemory != 0 || res.KDFParallel != 4 {
			t.Fatalf("%+v", res)
		}
	}

	t.Run("decodes pascal-case prelogin json", func(t *testing.T) {
		tester(t, testCase{body: []byte(`{"Kdf":"1","KdfIterations":3,"KdfMemory":null,"KdfParallelism":4}`)})
	})
}
