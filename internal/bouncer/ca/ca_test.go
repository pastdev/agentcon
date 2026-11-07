package ca

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLoadOrCreate(t *testing.T) {
	type testCase struct {
		dir string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		a, err := LoadOrCreate(tc.dir)
		if err != nil {
			t.Fatal(err)
		}
		b, err := LoadOrCreate(tc.dir)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Cert().Equal(a.Cert()) {
			t.Fatal("CA changed on reload")
		}
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
		if err != nil {
			t.Fatal(err)
		}
		if tc.fillCache {
			for i := 0; i < maxLeaves+50; i++ {
				_, err := a.Leaf(fmt.Sprintf("h%d.example.com", i))
				if err != nil {
					t.Fatal(err)
				}
			}
			if n := len(a.leaves); n > maxLeaves {
				t.Fatalf("leaf cache grew to %d", n)
			}
			return
		}
		leaf, err := a.Leaf(tc.host)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(a.Cert())
		_, err = c.Verify(x509.VerifyOptions{DNSName: tc.host, Roots: pool})
		if err != nil {
			t.Fatal(err)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		err = a.WriteBundle()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(a.BundlePath())
		if err != nil {
			t.Fatal(err)
		}
		if len(data) < 10000 {
			t.Fatalf("bundle suspiciously small: %d bytes", len(data))
		}
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
		if err != nil {
			t.Fatal(err)
		}
		s, err := a.SSHHostSigner(tc.host)
		if err != nil {
			t.Fatal(err)
		}
		cert := s.PublicKey().(*ssh.Certificate)
		checker := &ssh.CertChecker{IsHostAuthority: func(k ssh.PublicKey, _ string) bool {
			return string(k.Marshal()) == string(a.sshCA.PublicKey().Marshal())
		}}
		err = checker.CheckHostKey(tc.check+":22", nil, cert)
		if tc.wantErr {
			if err == nil {
				t.Fatal("cert should not be valid for another host")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		line := a.SSHKnownHostsLine(tc.hosts)
		if tc.wantEmpty {
			if line != "" {
				t.Fatal("no hosts should trust nothing")
			}
			return
		}
		if !strings.HasPrefix(line, tc.wantPrefix) {
			t.Fatalf("%q", line)
		}
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
