package ca

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/x509roots/fallback/bundle"
)

const bundleFile = "ca-bundle.pem"

// BundlePEM returns the combined bundle bytes, generating the file if needed.
func (a *Authority) BundlePEM() ([]byte, error) {
	b, err := os.ReadFile(a.BundlePath())
	if err == nil {
		return b, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read ca bundle: %w", err)
	}
	err = a.WriteBundle()
	if err != nil {
		return nil, fmt.Errorf("write ca bundle: %w", err)
	}
	b, err = os.ReadFile(a.BundlePath())
	if err != nil {
		return nil, fmt.Errorf("read ca bundle: %w", err)
	}
	return b, nil
}

// BundlePath is a PEM file with the system roots plus the bouncer CA. Tools
// whose CA variable replaces (rather than extends) the trust store, such as
// SSL_CERT_FILE or GIT_SSL_CAINFO, are pointed at it so tunneled hosts keep
// validating normally.
func (a *Authority) BundlePath() string { return filepath.Join(a.dir, bundleFile) }

// WriteBundle regenerates the combined bundle.
func (a *Authority) WriteBundle() error {
	roots := systemRootsPEM()
	var buf bytes.Buffer
	buf.Write(a.certPEM)
	buf.WriteByte('\n')
	buf.Write(roots)
	return os.WriteFile(a.BundlePath(), buf.Bytes(), 0o644)
}

var linuxBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// systemRootsPEM returns the OS trust store as PEM where it can be read,
// falling back to the Mozilla bundle.
func systemRootsPEM() []byte {
	switch runtime.GOOS {
	case "darwin":
		var out bytes.Buffer
		for _, kc := range []string{
			"/System/Library/Keychains/SystemRootCertificates.keychain",
			"/Library/Keychains/System.keychain",
		} {
			b, err := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", kc).Output()
			if err == nil {
				out.Write(b)
			}
		}
		if out.Len() > 0 {
			return out.Bytes()
		}
	case "windows":
		// No portable PEM export; use the Mozilla bundle below.
	default:
		for _, f := range linuxBundles {
			if b, err := os.ReadFile(f); err == nil && len(b) > 0 {
				return b
			}
		}
	}
	var out bytes.Buffer
	for r := range bundle.Roots() {
		if r.Constraint != nil {
			continue
		}
		pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: r.Certificate})
	}
	return out.Bytes()
}
