// Package signer is the in-process terminal handler of a signer service. It
// signs git objects with OpenPGP keys held in internal credentials.
package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// Signature is a detached, armored OpenPGP signature and the facts git's
// status line reports about it.
type Signature struct {
	Armored     []byte
	Fingerprint string
	KeyAlgo     int
	Hash        int
	Created     time.Time
}

// Signer signs payload with the configured key.
type Signer interface {
	Sign(ctx context.Context, key config.OpenPGPKey, payload []byte) (*Signature, error)
}

// ErrUnavailable means the key's credential could not be fetched.
var ErrUnavailable = errors.New("signing key unavailable")

// ErrKey means the credential does not hold a usable key with the
// configured ID.
var ErrKey = errors.New("signing key unusable")

// Credentials is the part of the credential store the signer uses.
type Credentials interface {
	Credential(name string) (*config.Credential, bool)
	GetSlot(ctx context.Context, name, slot string) (string, error)
}

type cachedKey struct {
	digest  [sha256.Size]byte
	key     *unlockedKey
	expires time.Time
	timer   *time.Timer
}

// unlockedKey is an unlocked key and the key ID go-crypto signs with: 0
// lets it pick the newest valid signing key, as gpg does for a primary key
// ID, and a subkey's ID pins exactly that subkey.
type unlockedKey struct {
	key   *pgp.Key
	keyID uint64
}

// OpenPGP signs with keys fetched from Credentials. An unlocked key is kept
// for its credential's cache TTL and evicted when the TTL ends, when the
// credential's values change, or on Reset.
type OpenPGP struct {
	Creds Credentials
	// Now is the clock for reuse decisions. Nil means time.Now. Eviction at
	// expiry runs on a real timer.
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]*cachedKey
}

// Reset evicts every unlocked key. The daemon calls it on each config load,
// so a changed or removed credential leaves nothing behind.
func (o *OpenPGP) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for name, c := range o.cache {
		c.timer.Stop()
		delete(o.cache, name)
	}
}

// Cached reports how many unlocked keys are held.
func (o *OpenPGP) Cached() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.cache)
}

// store caches key for ttl, replacing and stopping any previous entry, and
// evicts it when ttl ends unless a newer entry has replaced it.
func (o *OpenPGP) store(name string, digest [sha256.Size]byte, key *unlockedKey, now time.Time, ttl time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cache == nil {
		o.cache = map[string]*cachedKey{}
	}
	if old, ok := o.cache[name]; ok {
		old.timer.Stop()
	}
	entry := &cachedKey{digest: digest, key: key, expires: now.Add(ttl)}
	entry.timer = time.AfterFunc(ttl, func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.cache[name] == entry {
			delete(o.cache, name)
		}
	})
	o.cache[name] = entry
}

func (o *OpenPGP) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Sign implements Signer.
func (o *OpenPGP) Sign(ctx context.Context, k config.OpenPGPKey, payload []byte) (*Signature, error) {
	key, err := o.key(ctx, k)
	if err != nil {
		return nil, err
	}
	now := o.now()
	cfg := profile.Default().SignConfig()
	cfg.Time = func() time.Time { return now }
	cfg.SigningKeyId = key.keyID
	var raw bytes.Buffer
	err = openpgp.DetachSign(&raw, []*openpgp.Entity{key.key.GetEntity()}, bytes.NewReader(payload), cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	return describe(raw.Bytes())
}

// key returns the unlocked key for k, from the cache when its credential
// values are unchanged.
func (o *OpenPGP) key(ctx context.Context, k config.OpenPGPKey) (*unlockedKey, error) {
	cred, ok := o.Creds.Credential(k.Credential)
	if !ok {
		return nil, fmt.Errorf("%w: unknown credential %q", ErrUnavailable, k.Credential)
	}
	armoredKey, err := o.Creds.GetSlot(ctx, k.Credential, config.SlotPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	var pass string
	if cred.Password != nil {
		pass, err = o.Creds.GetSlot(ctx, k.Credential, config.SlotPassword)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
	}
	digest := sha256.Sum256([]byte(k.ID + "\x00" + armoredKey + "\x00" + pass))
	now := o.now()
	o.mu.Lock()
	if c, ok := o.cache[k.Credential]; ok && c.digest == digest && now.Before(c.expires) {
		o.mu.Unlock()
		return c.key, nil
	}
	o.mu.Unlock()

	locked, err := unlock(armoredKey, pass)
	if err != nil {
		return nil, err
	}
	keyID, err := checkID(locked, k.ID, now)
	if err != nil {
		return nil, err
	}
	key := &unlockedKey{key: locked, keyID: keyID}
	if ttl := cred.CacheTTL(); ttl > 0 {
		o.store(k.Credential, digest, key, now, ttl)
	}
	return key, nil
}

func unlock(armoredKey, pass string) (*pgp.Key, error) {
	locked, err := pgp.NewKeyFromArmored(armoredKey)
	if err != nil {
		return nil, fmt.Errorf("%w: not an armored OpenPGP key", ErrKey)
	}
	if !locked.IsPrivate() {
		return nil, fmt.Errorf("%w: not a private key", ErrKey)
	}
	isLocked, err := locked.IsLocked()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	if !isLocked {
		return locked, nil
	}
	if pass == "" {
		return nil, fmt.Errorf("%w: key is passphrase-protected and the credential has no password", ErrKey)
	}
	key, err := locked.Unlock([]byte(pass))
	if err != nil {
		return nil, fmt.Errorf("%w: passphrase rejected", ErrKey)
	}
	return key, nil
}

// checkID confirms the key's primary key, or one of its valid signing
// subkeys, has the configured ID, and returns the key ID to sign with. A
// primary key ID returns 0, so the newest valid signing key signs, as with
// gpg -u <primary>. A subkey ID returns that subkey, as with gpg -u <subkey>!.
func checkID(key *pgp.Key, id string, now time.Time) (uint64, error) {
	e := key.GetEntity()
	if config.KeyIDsMatch(id, fingerprint(e.PrimaryKey)) {
		return 0, nil
	}
	for _, sub := range e.Subkeys {
		if !config.KeyIDsMatch(id, fingerprint(sub.PublicKey)) {
			continue
		}
		if _, ok := e.SigningKeyById(now, sub.PublicKey.KeyId, nil); ok {
			return sub.PublicKey.KeyId, nil
		}
		return 0, fmt.Errorf("%w: subkey %s cannot sign", ErrKey, id)
	}
	return 0, fmt.Errorf("%w: credential holds key %s, not %s", ErrKey, fingerprint(e.PrimaryKey), id)
}

func fingerprint(pk *packet.PublicKey) string {
	return strings.ToUpper(fmt.Sprintf("%x", pk.Fingerprint))
}

// describe armors a binary signature, without the Version and Comment
// headers gpg would not add, and reads back the signature packet for the
// status line.
func describe(raw []byte) (*Signature, error) {
	var armored bytes.Buffer
	w, err := armor.Encode(&armored, "PGP SIGNATURE", nil)
	if err != nil {
		return nil, fmt.Errorf("%w: armor signature: %w", ErrKey, err)
	}
	_, err = w.Write(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: armor signature: %w", ErrKey, err)
	}
	err = w.Close()
	if err != nil {
		return nil, fmt.Errorf("%w: armor signature: %w", ErrKey, err)
	}
	armored.WriteByte('\n')
	p, err := packet.Read(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: read signature: %w", ErrKey, err)
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf("%w: read signature: unexpected packet %T", ErrKey, p)
	}
	hashID, ok := openpgp.HashToHashId(sig.Hash)
	if !ok {
		return nil, fmt.Errorf("%w: unknown signature hash %v", ErrKey, sig.Hash)
	}
	out := &Signature{
		Armored: armored.Bytes(),
		KeyAlgo: int(sig.PubKeyAlgo),
		Hash:    int(hashID),
		Created: sig.CreationTime,
	}
	switch {
	case len(sig.IssuerFingerprint) > 0:
		out.Fingerprint = strings.ToUpper(fmt.Sprintf("%x", sig.IssuerFingerprint))
	case sig.IssuerKeyId != nil:
		out.Fingerprint = fmt.Sprintf("%016X", *sig.IssuerKeyId)
	}
	return out, nil
}
