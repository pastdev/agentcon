package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoXCryptoOpenPGP keeps golang.org/x/crypto/openpgp out of the binary.
// It is deprecated and unmaintained (Go advisory GO-2026-5932). The bouncer
// signer uses github.com/ProtonMail/go-crypto through GopenPGP instead.
func TestNoXCryptoOpenPGP(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	out, err := exec.Command(goBin, "list", "-deps", ".").Output() //nolint:gosec // fixed go list invocation
	require.NoError(t, err)
	var bad []string
	for _, pkg := range strings.Fields(string(out)) {
		if pkg == "golang.org/x/crypto/openpgp" || strings.HasPrefix(pkg, "golang.org/x/crypto/openpgp/") {
			bad = append(bad, pkg)
		}
	}
	assert.Empty(t, bad, "agentcon must not import golang.org/x/crypto/openpgp")
	assert.Contains(t, strings.Fields(string(out)), "github.com/ProtonMail/gopenpgp/v3/crypto", "the guard should see the signer's dependencies")
}
