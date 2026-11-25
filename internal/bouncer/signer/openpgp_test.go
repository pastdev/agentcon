package signer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

const testCommit = "tree 9bedf67800b2923982bdf60c89c57ce6986c4c5b\n" +
	"author A <a@example.com> 1764000000 +0000\n" +
	"committer A <a@example.com> 1764000000 +0000\n\nmsg\n"

// fakeCreds serves slot values and counts fetches.
type fakeCreds struct {
	mu      sync.Mutex
	creds   map[string]*config.Credential
	values  map[string]string
	fail    error
	fetches int
}

func (f *fakeCreds) Credential(name string) (*config.Credential, bool) {
	c, ok := f.creds[name]
	return c, ok
}

func (f *fakeCreds) GetSlot(_ context.Context, name, slot string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	if f.fail != nil {
		return "", f.fail
	}
	v, ok := f.values[name+"."+slot]
	if !ok {
		return "", fmt.Errorf("credential %q has no %s", name, slot)
	}
	return v, nil
}

type testKey struct {
	public      *pgp.Key
	armored     string
	fingerprint string
	encSubkeyID string
}

var (
	keysOnce sync.Once
	keys     map[string]testKey
)

// generated returns a cached key: "locked" has passphrase "hunter2", "plain"
// has none.
func generated(t *testing.T, name string) testKey {
	t.Helper()
	keysOnce.Do(func() {
		keys = map[string]testKey{}
		for _, n := range []string{"locked", "plain"} {
			k, err := pgp.PGP().KeyGeneration().AddUserId("Agent "+n, n+"@example.com").New().GenerateKey()
			require.NoError(t, err)
			pub, err := k.ToPublic()
			require.NoError(t, err)
			armoredKey := k
			if n == "locked" {
				armoredKey, err = pgp.PGP().LockKey(k, []byte("hunter2"))
				require.NoError(t, err)
			}
			a, err := armoredKey.Armor()
			require.NoError(t, err)
			tk := testKey{public: pub, armored: a, fingerprint: strings.ToUpper(k.GetFingerprint())}
			for _, sub := range k.GetEntity().Subkeys {
				tk.encSubkeyID = fmt.Sprintf("%016X", sub.PublicKey.KeyId)
			}
			keys[n] = tk
		}
	})
	return keys[name]
}

func credsFor(k testKey, pass string, ttl time.Duration) *fakeCreds {
	cred := &config.Credential{Name: "sign", Internal: true, PrivateKey: &config.ValueSource{Source: "provided"}, Cache: &config.Duration{D: ttl}}
	values := map[string]string{"sign.private_key": k.armored}
	if pass != "" {
		cred.Password = &config.ValueSource{Source: "provided"}
		values["sign.password"] = pass
	}
	return &fakeCreds{creds: map[string]*config.Credential{"sign": cred}, values: values}
}

func TestOpenPGPSign(t *testing.T) {
	type testCase struct {
		key     string
		pass    string
		id      func(testKey) string
		fail    error
		wantErr error
		wantMsg string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		k := generated(t, tc.key)
		fc := credsFor(k, tc.pass, time.Minute)
		fc.fail = tc.fail
		id := k.fingerprint
		if tc.id != nil {
			id = tc.id(k)
		}
		o := &OpenPGP{Creds: fc}
		sig, err := o.Sign(t.Context(), config.OpenPGPKey{ID: id, Credential: "sign"}, []byte(testCommit))
		if tc.wantErr != nil {
			require.ErrorIs(t, err, tc.wantErr)
			assert.Contains(t, err.Error(), tc.wantMsg)
			assert.Nil(t, sig)
			return
		}
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(sig.Armored), "-----BEGIN PGP SIGNATURE-----"), string(sig.Armored))
		assert.NotContains(t, string(sig.Armored), "Version:")
		assert.Equal(t, k.fingerprint, sig.Fingerprint)
		assert.NotZero(t, sig.KeyAlgo)
		assert.NotZero(t, sig.Hash)
		assert.WithinDuration(t, time.Now(), sig.Created, time.Minute)

		v, err := pgp.PGP().Verify().VerificationKey(k.public).New()
		require.NoError(t, err)
		res, err := v.VerifyDetached([]byte(testCommit), sig.Armored, pgp.Armor)
		require.NoError(t, err)
		require.NoError(t, res.SignatureError())
		res, err = v.VerifyDetached([]byte(testCommit+"tampered"), sig.Armored, pgp.Armor)
		require.NoError(t, err)
		require.Error(t, res.SignatureError())
	}

	t.Run("passphrase-protected key by fingerprint", func(t *testing.T) {
		tester(t, testCase{key: "locked", pass: "hunter2"})
	})
	t.Run("passphrase-protected key by long id", func(t *testing.T) {
		tester(t, testCase{key: "locked", pass: "hunter2", id: func(k testKey) string { return config.LongKeyID(k.fingerprint) }})
	})
	t.Run("unprotected key without password", func(t *testing.T) {
		tester(t, testCase{key: "plain"})
	})
	t.Run("wrong passphrase", func(t *testing.T) {
		tester(t, testCase{key: "locked", pass: "wrong", wantErr: ErrKey, wantMsg: "passphrase rejected"})
	})
	t.Run("protected key without password", func(t *testing.T) {
		tester(t, testCase{key: "locked", wantErr: ErrKey, wantMsg: "has no password"})
	})
	t.Run("configured id does not match the key", func(t *testing.T) {
		tester(t, testCase{key: "plain", id: func(testKey) string { return "0123456789ABCDEF" }, wantErr: ErrKey, wantMsg: "not 0123456789ABCDEF"})
	})
	t.Run("encryption subkey cannot sign", func(t *testing.T) {
		tester(t, testCase{key: "plain", id: func(k testKey) string { return k.encSubkeyID }, wantErr: ErrKey, wantMsg: "cannot sign"})
	})
	t.Run("credential unavailable", func(t *testing.T) {
		tester(t, testCase{key: "plain", fail: errors.New("vault locked"), wantErr: ErrUnavailable, wantMsg: "vault locked"})
	})
}

// twoSigningSubkeys returns an armored key whose primary key can sign and
// which has an older and a newer signing subkey, and the subkeys'
// fingerprints, oldest first.
func twoSigningSubkeys(t *testing.T) (armored, primary string, subkeys []string) {
	t.Helper()
	created := time.Unix(1764000000, 0)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return created }}
	e, err := openpgp.NewEntity("Agent", "", "agent@example.com", cfg)
	require.NoError(t, err)
	for range 2 {
		created = created.Add(time.Hour)
		err = e.AddSigningSubkey(cfg)
		require.NoError(t, err)
	}
	k, err := pgp.NewKeyFromEntity(e)
	require.NoError(t, err)
	armored, err = k.Armor()
	require.NoError(t, err)
	for _, sub := range e.Subkeys {
		if sub.PublicKey.PubKeyAlgo == packet.PubKeyAlgoEdDSA {
			subkeys = append(subkeys, fingerprint(sub.PublicKey))
		}
	}
	require.Len(t, subkeys, 2)
	return armored, fingerprint(e.PrimaryKey), subkeys
}

func TestOpenPGPSigningKeySelection(t *testing.T) {
	armored, primary, subkeys := twoSigningSubkeys(t)
	type testCase struct {
		id   string
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		fc := credsFor(testKey{armored: armored}, "", time.Minute)
		o := &OpenPGP{Creds: fc, Now: func() time.Time { return time.Unix(1764100000, 0) }}
		sig, err := o.Sign(t.Context(), config.OpenPGPKey{ID: tc.id, Credential: "sign"}, []byte(testCommit))
		require.NoError(t, err)
		assert.Equal(t, tc.want, sig.Fingerprint)
	}

	t.Run("older subkey by fingerprint signs with that subkey", func(t *testing.T) {
		tester(t, testCase{id: subkeys[0], want: subkeys[0]})
	})
	t.Run("older subkey by long id signs with that subkey", func(t *testing.T) {
		tester(t, testCase{id: config.LongKeyID(subkeys[0]), want: subkeys[0]})
	})
	t.Run("newer subkey signs with that subkey", func(t *testing.T) {
		tester(t, testCase{id: subkeys[1], want: subkeys[1]})
	})
	t.Run("primary id signs with the newest signing subkey", func(t *testing.T) {
		tester(t, testCase{id: primary, want: subkeys[1]})
	})
}

func TestOpenPGPCache(t *testing.T) {
	k := generated(t, "locked")
	type testCase struct {
		ttl        time.Duration
		advance    time.Duration
		change     bool
		wantUnlock bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		fc := credsFor(k, "hunter2", tc.ttl)
		now := time.Unix(1764000000, 0)
		o := &OpenPGP{Creds: fc, Now: func() time.Time { return now }}
		key := config.OpenPGPKey{ID: k.fingerprint, Credential: "sign"}
		first, err := o.key(t.Context(), key)
		require.NoError(t, err)
		now = now.Add(tc.advance)
		if tc.change {
			// Same key, re-armored: different credential bytes.
			fc.values["sign.private_key"] += "\n"
		}
		second, err := o.key(t.Context(), key)
		require.NoError(t, err)
		if tc.wantUnlock {
			assert.NotSame(t, first, second)
			return
		}
		assert.Same(t, first, second)
	}

	t.Run("reuses the unlocked key within ttl", func(t *testing.T) {
		tester(t, testCase{ttl: time.Minute, advance: 30 * time.Second})
	})
	t.Run("unlocks again after ttl", func(t *testing.T) {
		tester(t, testCase{ttl: time.Minute, advance: 2 * time.Minute, wantUnlock: true})
	})
	t.Run("unlocks again when the credential changes", func(t *testing.T) {
		tester(t, testCase{ttl: time.Minute, change: true, wantUnlock: true})
	})
	t.Run("cache 0s never reuses", func(t *testing.T) {
		tester(t, testCase{ttl: 0, wantUnlock: true})
	})
}
