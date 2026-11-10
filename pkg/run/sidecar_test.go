package run

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSidecarPayload(t *testing.T) {
	type testCase struct {
		policy  []byte
		tsFiles map[string]string
		token   string
		wantCfg string
		wantTS  string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		bin := filepath.Join(t.TempDir(), "agentcon")
		err := os.WriteFile(bin, []byte("#!/bin/true"), 0o600)
		require.NoError(t, err)
		var buf bytes.Buffer
		err = WriteSidecarPayload(&buf, tc.policy, tc.tsFiles, bin, tc.token)
		require.NoError(t, err)

		found := map[string][]byte{}
		tr := tar.NewReader(&buf)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
			if hdr.Typeflag == tar.TypeDir {
				continue
			}
			data, err := io.ReadAll(tr)
			require.NoError(t, err)
			found[hdr.Name] = data
		}
		assert.Contains(t, found, tarName(sidecarBinPath))
		assert.Equal(t, tc.token+"\n", string(found[tarName(sidecarStatePath)+"/admin-token"]))
		assert.Contains(t, string(found[tarName(sidecarConfigPath)]), tc.wantCfg)
		assert.Contains(t, found, tarName(sidecarHome)+"/ts/"+tc.wantTS)
	}

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "deny.ts")
	err := os.WriteFile(src, []byte("export {}"), 0o600)
	require.NoError(t, err)

	t.Run("packs folder layout", func(t *testing.T) {
		tester(t, testCase{
			policy:  []byte("filter: ts/filters/deny.ts\n"),
			tsFiles: map[string]string{"filters/deny.ts": src},
			token:   "tok123",
			wantCfg: "filter: ts/filters/deny.ts",
			wantTS:  "filters/deny.ts",
		})
	})
	t.Run("sets uid and gid", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "agentcon")
		err := os.WriteFile(bin, []byte("#!/bin/true"), 0o600)
		require.NoError(t, err)
		var buf bytes.Buffer
		err = writeSidecarPayload(&buf, []byte("listen: 127.0.0.1:8228\n"), nil, bin, "tok", 1000, 1001)
		require.NoError(t, err)
		tr := tar.NewReader(&buf)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 1000, hdr.Uid, hdr.Name)
			assert.Equal(t, 1001, hdr.Gid, hdr.Name)
		}
	})
}

func TestWriteAgentPayload(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		bin := filepath.Join(t.TempDir(), "agentcon")
		err := os.WriteFile(bin, []byte("#!/bin/true"), 0o600)
		require.NoError(t, err)
		var buf bytes.Buffer
		err = writeAgentPayload(&buf, bin, "CERT", "BUNDLE", "known-hosts\n", 1000, 1001)
		require.NoError(t, err)
		found := map[string][]byte{}
		tr := tar.NewReader(&buf)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
			assert.Equal(t, 1000, hdr.Uid, hdr.Name)
			assert.Equal(t, 1001, hdr.Gid, hdr.Name)
			if hdr.Typeflag == tar.TypeDir {
				continue
			}
			data, err := io.ReadAll(tr)
			require.NoError(t, err)
			found[hdr.Name] = data
		}
		assert.Equal(t, "#!/bin/true", string(found[tarName(agentBinPath)]))
		assert.Equal(t, "CERT", string(found[tarName(agentCACertPath)]))
		assert.Equal(t, "BUNDLE", string(found[tarName(agentCABundlePath)]))
		assert.Equal(t, "known-hosts\n", string(found[tarName(agentKnownHosts)]))
		cfg := string(found[tarName(agentSSHConfig)])
		assert.Contains(t, cfg, agentBinPath)
		assert.Contains(t, cfg, agentKnownHosts)
	}

	t.Run("packs ssh files with owner", func(t *testing.T) {
		tester(t)
	})
}
