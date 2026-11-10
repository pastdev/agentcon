package run

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/pastdev/agentcon/pkg/container"
)

const (
	// sidecarTrustRepo names images that add CA files to sidecarImage. The
	// tag is a hash of the build context, so each certificate set is built
	// once.
	sidecarTrustRepo = "agentcon/bouncer-sidecar"
	// sidecarDockerfile installs ca/ into the system trust at build time,
	// because the sidecar runs as the user's UID and cannot update it later.
	sidecarDockerfile = "FROM " + sidecarImage + "\n" +
		"COPY ca/ /etc/pki/ca-trust/source/anchors/\n" +
		"RUN update-ca-trust extract\n"
)

// prepareSidecarImage returns the image the sidecar runs. Without caFiles it
// is sidecarImage, fetched as policy allows. With caFiles it is sidecarImage
// plus their trust, built when missing or when policy is PullAlways.
func prepareSidecarImage(
	ctx context.Context,
	rt container.Runtime,
	caFiles []string,
	policy PullPolicy,
	out io.Writer,
) (string, error) {
	if len(caFiles) == 0 {
		err := ensureImage(ctx, rt, sidecarImage, policy, out)
		if err != nil {
			return "", err
		}
		return sidecarImage, nil
	}

	files, err := sidecarContext(caFiles)
	if err != nil {
		return "", err
	}
	tag := sidecarTrustRepo + ":" + contextHash(files)
	if policy != PullAlways {
		exists, err := rt.ImageExists(ctx, tag)
		if err != nil {
			return "", fmt.Errorf("check image: %w", err)
		}
		if exists {
			return tag, nil
		}
	}
	err = rt.Build(ctx, container.Build{
		Files:      files,
		Dockerfile: "Dockerfile",
		Tags:       []string{tag},
		Output:     out,
		PullParent: policy == PullAlways,
	})
	if err != nil {
		return "", fmt.Errorf("build %s: %w", tag, err)
	}
	return tag, nil
}

// sidecarContext is the in-memory build context for sidecarDockerfile. Each
// CA file must hold only PEM certificates.
func sidecarContext(caFiles []string) (map[string][]byte, error) {
	files := map[string][]byte{"Dockerfile": []byte(sidecarDockerfile)}
	for i, path := range caFiles {
		b, err := os.ReadFile(path) //nolint:gosec // path from operator config
		if err != nil {
			return nil, fmt.Errorf("ca file: %w", err)
		}
		err = checkCertificates(b)
		if err != nil {
			return nil, fmt.Errorf("ca file %s: %w", path, err)
		}
		files[fmt.Sprintf("ca/%03d.pem", i)] = b
	}
	return files, nil
}

// checkCertificates accepts PEM data holding one or more certificates and no
// other PEM blocks. Text between blocks is ignored.
func checkCertificates(b []byte) error {
	count := 0
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("pem block %q is not a certificate", block.Type)
		}
		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse certificate: %w", err)
		}
		count++
	}
	if count == 0 {
		return errors.New("no PEM certificates")
	}
	return nil
}

// contextHash is a short, stable hash of a build context.
func contextHash(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", name, len(files[name]))
		_, _ = h.Write(files[name])
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
