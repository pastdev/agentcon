package run

import (
	"archive/tar"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTarFiles(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		caPath := tarName(agentCACertPath)
		buf, err := tarFiles(map[string][]byte{
			caPath: []byte("cert"),
		}, nil, 0, 0)
		require.NoError(t, err)
		found := map[string]bool{}
		tr := tar.NewReader(buf)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
			found[hdr.Name] = true
			if hdr.Name == caPath {
				data, err := io.ReadAll(tr)
				require.NoError(t, err)
				assert.Equal(t, "cert", string(data))
			}
		}
		for _, name := range []string{"opt/", tarName(optDir) + "/", caPath} {
			assert.True(t, found[name], "missing %s in %v", name, found)
		}
	}

	t.Run("creates parent dirs", func(t *testing.T) {
		tester(t)
	})
}
