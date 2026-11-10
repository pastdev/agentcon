package run

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeTestFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, b, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrepareSidecarImage(t *testing.T) {
	type testCase struct {
		caFiles    []string
		policy     PullPolicy
		missing    bool
		existsErr  error
		wantStock  bool
		wantBuild  bool
		wantParent bool
		wantErr    string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		rt := &captureRuntime{missing: tc.missing, existsErr: tc.existsErr}
		image, err := prepareSidecarImage(context.Background(), rt, tc.caFiles, tc.policy, io.Discard)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if rt.build.Tags != nil {
				t.Fatalf("built %v after an error", rt.build.Tags)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantStock != (image == sidecarImage) {
			t.Fatalf("image = %s", image)
		}
		if !tc.wantStock && !strings.HasPrefix(image, sidecarTrustRepo+":") {
			t.Fatalf("image = %s", image)
		}
		built := rt.build.Tags != nil
		if tc.wantBuild != built {
			t.Fatalf("built = %v, want %v", built, tc.wantBuild)
		}
		if built {
			if len(rt.build.Tags) != 1 || rt.build.Tags[0] != image {
				t.Fatalf("tags %v, image %s", rt.build.Tags, image)
			}
			if rt.build.PullParent != tc.wantParent {
				t.Fatalf("PullParent = %v", rt.build.PullParent)
			}
			if string(rt.build.Files["Dockerfile"]) != sidecarDockerfile {
				t.Fatalf("Dockerfile %q", rt.build.Files["Dockerfile"])
			}
			if len(rt.build.Files) != 1+len(tc.caFiles) {
				t.Fatalf("files %d, want %d", len(rt.build.Files), 1+len(tc.caFiles))
			}
		}
	}

	dir := t.TempDir()
	ca := writeTestFile(t, dir, "ca.pem", testCertPEM(t, "inspection"))
	chain := writeTestFile(t, dir, "chain.txt", append(append(
		[]byte("subject=root\n"), testCertPEM(t, "root")...), testCertPEM(t, "issuing")...))
	key := writeTestFile(t, dir, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("k")}))
	empty := writeTestFile(t, dir, "empty.pem", []byte("not pem\n"))
	broken := writeTestFile(t, dir, "broken.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))

	t.Run("uses the stock image without ca files", func(t *testing.T) {
		tester(t, testCase{wantStock: true})
	})
	t.Run("pulls the stock image when missing", func(t *testing.T) {
		rt := &captureRuntime{missing: true}
		_, err := prepareSidecarImage(context.Background(), rt, nil, PullMissing, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if len(rt.pulled) != 1 || rt.pulled[0] != sidecarImage {
			t.Fatalf("pulled %v", rt.pulled)
		}
	})
	t.Run("builds a missing derived image", func(t *testing.T) {
		tester(t, testCase{caFiles: []string{ca, chain}, missing: true, wantBuild: true})
	})
	t.Run("reuses a present derived image", func(t *testing.T) {
		tester(t, testCase{caFiles: []string{ca}})
	})
	t.Run("never still builds a missing derived image", func(t *testing.T) {
		tester(t, testCase{caFiles: []string{ca}, policy: PullNever, missing: true, wantBuild: true})
	})
	t.Run("always rebuilds and refreshes the base", func(t *testing.T) {
		tester(t, testCase{caFiles: []string{ca}, policy: PullAlways, wantBuild: true, wantParent: true})
	})
	t.Run("reports a failed check", func(t *testing.T) {
		tester(t, testCase{caFiles: []string{ca}, existsErr: errors.New("daemon down"), wantErr: "daemon down"})
	})
	t.Run("refuses a missing file", func(t *testing.T) {
		tester(t, testCase{caFiles: []string{filepath.Join(dir, "nope.pem")}, missing: true, wantErr: "nope.pem"})
	})
	t.Run("refuses a non-certificate block", func(t *testing.T) {
		tester(t, testCase{caFiles: []string{ca, key}, missing: true, wantErr: key + `: pem block "PRIVATE KEY"`})
	})
	t.Run("refuses a file without certificates", func(t *testing.T) {
		tester(t, testCase{caFiles: []string{empty}, missing: true, wantErr: empty + ": no PEM certificates"})
	})
	t.Run("refuses an unparsable certificate", func(t *testing.T) {
		tester(t, testCase{caFiles: []string{broken}, missing: true, wantErr: broken + ": parse certificate"})
	})
}

func TestSidecarImageTag(t *testing.T) {
	dir := t.TempDir()
	a := writeTestFile(t, dir, "a.pem", testCertPEM(t, "a"))
	b := writeTestFile(t, dir, "b.pem", testCertPEM(t, "b"))
	tag := func(files ...string) string {
		t.Helper()
		rt := &captureRuntime{missing: true}
		image, err := prepareSidecarImage(context.Background(), rt, files, PullMissing, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		return image
	}

	t.Run("is stable for the same files", func(t *testing.T) {
		first, second := tag(a, b), tag(a, b)
		if first != second {
			t.Fatalf("tag changed between runs: %s, %s", first, second)
		}
	})
	t.Run("changes with the certificate set", func(t *testing.T) {
		if tag(a) == tag(a, b) {
			t.Fatal("adding a file kept the tag")
		}
		if tag(a) == tag(b) {
			t.Fatal("different files share a tag")
		}
	})
}
