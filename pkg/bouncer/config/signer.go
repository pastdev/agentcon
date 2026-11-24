package config

import (
	"fmt"
	"strings"
)

// SourceSSHAgent is the credential source that signs with keys in the
// host's ssh-agent.
const SourceSSHAgent = "ssh-agent"

// SignerPath is the only path an OpenPGP signer service answers.
const SignerPath = "/openpgp/sign"

// Signer makes an http service a pseudo service: its terminal handler runs
// inside bouncer instead of forwarding upstream.
type Signer struct {
	OpenPGP *OpenPGPSigner `yaml:"openpgp"`
}

// OpenPGPSigner signs git objects with one of its keys.
type OpenPGPSigner struct {
	Keys []OpenPGPKey `yaml:"keys"`
}

// OpenPGPKey maps a key ID to the internal credential holding that key.
type OpenPGPKey struct {
	// ID is a 16-hex long key ID or a 40-hex (v4) or 64-hex (v6)
	// fingerprint. Init stores it normalized.
	ID string `yaml:"id"`
	// Credential names an internal credential with private_key and an
	// optional password (the passphrase).
	Credential string `yaml:"credential"`
}

// NormalizeKeyID returns an OpenPGP key ID or fingerprint in upper-case hex
// without a 0x prefix or a trailing "!". It accepts 16, 40, or 64 hex digits.
func NormalizeKeyID(s string) (string, error) {
	id := strings.TrimSpace(s)
	id = strings.TrimSuffix(id, "!")
	if strings.HasPrefix(id, "0x") || strings.HasPrefix(id, "0X") {
		id = id[2:]
	}
	id = strings.ToUpper(id)
	switch len(id) {
	case 16, 40, 64:
	default:
		return "", fmt.Errorf("key id %q: want 16, 40, or 64 hex digits", s)
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'A' || r > 'F') {
			return "", fmt.Errorf("key id %q: want 16, 40, or 64 hex digits", s)
		}
	}
	return id, nil
}

// LongKeyID returns the 16-hex key ID of a normalized ID or fingerprint. A
// v4 key ID is the low 64 bits of its fingerprint, and a v6 key ID is the
// high 64 bits.
func LongKeyID(id string) string {
	switch len(id) {
	case 40:
		return id[24:]
	case 64:
		return id[:16]
	}
	return id
}

// KeyIDsMatch reports whether two normalized IDs name the same key. A long
// key ID matches a fingerprint it derives from.
func KeyIDsMatch(a, b string) bool {
	if a == b {
		return true
	}
	if len(a) == 16 || len(b) == 16 {
		return LongKeyID(a) == LongKeyID(b)
	}
	return false
}

// Key returns the configured key matching a normalized ID, or nil.
func (s *OpenPGPSigner) Key(id string) *OpenPGPKey {
	for i := range s.Keys {
		if KeyIDsMatch(s.Keys[i].ID, id) {
			return &s.Keys[i]
		}
	}
	return nil
}

func (c *Config) validateSigner(s *Service) error {
	if s.Signer.OpenPGP == nil {
		return fmt.Errorf("signer: openpgp is required")
	}
	if s.Credential != "" {
		return fmt.Errorf("signer service may not set credential")
	}
	if s.Inject != nil {
		return fmt.Errorf("signer service may not set inject")
	}
	if s.AllowUpgrade {
		return fmt.Errorf("signer service may not set allow_upgrade")
	}
	if s.Insecure {
		return fmt.Errorf("signer service may not set insecure")
	}
	for _, h := range s.Hosts {
		if strings.Contains(h, "*") {
			return fmt.Errorf("signer service hosts must be exact names, not %q", h)
		}
	}
	keys := s.Signer.OpenPGP.Keys
	if len(keys) == 0 {
		return fmt.Errorf("signer openpgp: keys is required")
	}
	for i := range keys {
		k := &keys[i]
		id, err := NormalizeKeyID(k.ID)
		if err != nil {
			return fmt.Errorf("signer openpgp keys[%d]: %w", i, err)
		}
		k.ID = id
		for j := range i {
			if KeyIDsMatch(keys[j].ID, id) {
				return fmt.Errorf("signer openpgp keys[%d]: key %s repeats keys[%d]", i, id, j)
			}
		}
		err = c.validateSigningCredential(k.Credential)
		if err != nil {
			return fmt.Errorf("signer openpgp keys[%d]: %w", i, err)
		}
	}
	return nil
}

func (c *Config) validateSigningCredential(name string) error {
	if name == "" {
		return fmt.Errorf("credential is required")
	}
	cr, ok := c.Credentials[name]
	if !ok {
		return fmt.Errorf("unknown credential %q", name)
	}
	if !cr.Internal {
		return fmt.Errorf("credential %q must set internal: true", name)
	}
	if cr.PrivateKey == nil {
		return fmt.Errorf("credential %q needs private_key", name)
	}
	if cr.PrivateKey.Source == SourceSSHAgent {
		return fmt.Errorf("credential %q: private_key source ssh-agent cannot hold an OpenPGP key", name)
	}
	for _, slot := range cr.Slots() {
		switch slot.Name {
		case SlotPrivateKey, SlotPassword:
		default:
			return fmt.Errorf("credential %q: a signing credential takes only private_key and password, not %s", name, slot.Name)
		}
	}
	return nil
}

// validateSigners refuses a resolved profile with more than one signer
// service, so the agent's signer URL is unambiguous.
func (c *Config) validateSigners() error {
	for name := range c.Profiles {
		rp, err := c.ResolvedProfile(name)
		if err != nil {
			return err
		}
		var found string
		for _, s := range rp.HTTP {
			if s.Signer == nil {
				continue
			}
			if found != "" {
				return fmt.Errorf("profile %q: more than one signer service (%q and %q)", name, found, s.Name)
			}
			found = s.Name
		}
	}
	return nil
}

// SignerURL is the URL the agent sends signing requests to: the service's
// first host and SignerPath.
func (s *Service) SignerURL() string {
	if s == nil || s.Signer == nil || len(s.Hosts) == 0 {
		return ""
	}
	return "https://" + s.Hosts[0] + SignerPath
}

// SignerService returns the profile's signer service, or nil.
func (p *Profile) SignerService() *Service {
	for _, s := range p.HTTP {
		if s.Signer != nil {
			return s
		}
	}
	return nil
}
