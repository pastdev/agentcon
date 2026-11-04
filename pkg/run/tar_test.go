package run

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestTarFilesCreatesParentDirs(t *testing.T) {
	caPath := tarName(agentCACertPath)
	buf, err := tarFiles(map[string][]byte{
		caPath: []byte("cert"),
	}, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	tr := tar.NewReader(buf)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		found[hdr.Name] = true
		if hdr.Name == caPath {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, []byte("cert")) {
				t.Fatalf("payload %q", data)
			}
		}
	}
	for _, name := range []string{"opt/", tarName(optDir) + "/", caPath} {
		if !found[name] {
			t.Fatalf("missing %s in %v", name, found)
		}
	}
}
