package ca

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestLoadOrCreate(t *testing.T) {
	type testCase struct {
		dir string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		a, err := LoadOrCreate(tc.dir)
		require.NoError(t, err)
		b, err := LoadOrCreate(tc.dir)
		require.NoError(t, err)
		assert.True(t, b.Cert().Equal(a.Cert()), "CA changed on reload")
	}

	t.Run("reloads the same CA from disk", func(t *testing.T) {
		tester(t, testCase{dir: t.TempDir()})
	})
}

func TestLeaf(t *testing.T) {
	type testCase struct {
		host      string
		fillCache bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		a, err := LoadOrCreate(t.TempDir())
		require.NoError(t, err)
		if tc.fillCache {
			for i := 0; i < maxLeaves+50; i++ {
				_, err := a.Leaf(fmt.Sprintf("h%d.example.com", i))
				require.NoError(t, err)
			}
			assert.LessOrEqual(t, len(a.leaves), maxLeaves)
			return
		}
		leaf, err := a.Leaf(tc.host)
		require.NoError(t, err)
		c, err := x509.ParseCertificate(leaf.Certificate[0])
		require.NoError(t, err)
		pool := x509.NewCertPool()
		pool.AddCert(a.Cert())
		_, err = c.Verify(x509.VerifyOptions{DNSName: tc.host, Roots: pool})
		require.NoError(t, err)
	}

	t.Run("verifies a leaf against the CA", func(t *testing.T) {
		tester(t, testCase{host: "gitlab.com"})
	})
	t.Run("bounds the leaf cache", func(t *testing.T) {
		tester(t, testCase{fillCache: true})
	})
}

func TestWriteBundle(t *testing.T) {
	type testCase struct{}
	tester := func(t *testing.T, _ testCase) {
		t.Helper()
		a, err := LoadOrCreate(t.TempDir())
		require.NoError(t, err)
		err = a.WriteBundle()
		require.NoError(t, err)
		data, err := os.ReadFile(a.BundlePath())
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(data), 10000, "bundle suspiciously small")
	}

	t.Run("writes a bundle large enough to include system roots", func(t *testing.T) {
		tester(t, testCase{})
	})
}

func TestSSHHostSigner(t *testing.T) {
	type testCase struct {
		host    string
		check   string
		wantErr bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		a, err := LoadOrCreate(t.TempDir())
		require.NoError(t, err)
		s, err := a.SSHHostSigner(tc.host)
		require.NoError(t, err)
		cert := s.PublicKey().(*ssh.Certificate)
		checker := &ssh.CertChecker{IsHostAuthority: func(k ssh.PublicKey, _ string) bool {
			return string(k.Marshal()) == string(a.sshCA.PublicKey().Marshal())
		}}
		err = checker.CheckHostKey(tc.check+":22", nil, cert)
		if tc.wantErr {
			require.Error(t, err, "cert should not be valid for another host")
			return
		}
		require.NoError(t, err)
	}

	t.Run("signs a host cert valid for that host", func(t *testing.T) {
		tester(t, testCase{host: "gitlab.com", check: "gitlab.com"})
	})
	t.Run("rejects the cert for another host", func(t *testing.T) {
		tester(t, testCase{host: "gitlab.com", check: "github.com", wantErr: true})
	})
}

func TestSSHKnownHostsLine(t *testing.T) {
	type testCase struct {
		hosts      []string
		wantPrefix string
		wantEmpty  bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		a, err := LoadOrCreate(t.TempDir())
		require.NoError(t, err)
		line := a.SSHKnownHostsLine(tc.hosts)
		if tc.wantEmpty {
			assert.Empty(t, line, "no hosts should trust nothing")
			return
		}
		assert.True(t, strings.HasPrefix(line, tc.wantPrefix), "%q", line)
	}

	t.Run("scopes cert-authority to the given hosts", func(t *testing.T) {
		tester(t, testCase{
			hosts:      []string{"gitlab.com", "*.dev.internal"},
			wantPrefix: "@cert-authority gitlab.com,[gitlab.com]:*,*.dev.internal,[*.dev.internal]:* ssh-ed25519 ",
		})
	})
	t.Run("trusts nothing when no hosts are given", func(t *testing.T) {
		tester(t, testCase{wantEmpty: true})
	})
}
