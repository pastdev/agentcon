package run

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
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
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		err = WriteSidecarPayload(&buf, tc.policy, tc.tsFiles, bin, tc.token)
		if err != nil {
			t.Fatal(err)
		}

		found := map[string][]byte{}
		tr := tar.NewReader(&buf)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if hdr.Typeflag == tar.TypeDir {
				continue
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			found[hdr.Name] = data
		}
		if _, ok := found[tarName(sidecarBinPath)]; !ok {
			t.Fatal("missing binary")
		}
		tokenName := tarName(sidecarStatePath) + "/admin-token"
		if string(found[tokenName]) != tc.token+"\n" {
			t.Fatalf("token %q", found[tokenName])
		}
		cfgName := tarName(sidecarConfigPath)
		if !bytes.Contains(found[cfgName], []byte(tc.wantCfg)) {
			t.Fatalf("config %s", found[cfgName])
		}
		tsName := tarName(sidecarHome) + "/ts/" + tc.wantTS
		if _, ok := found[tsName]; !ok {
			t.Fatalf("missing filter, have %v", keys(found))
		}
	}

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "deny.ts")
	err := os.WriteFile(src, []byte("export {}"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

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
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		err = writeSidecarPayload(&buf, []byte("listen: 127.0.0.1:8228\n"), nil, bin, "tok", 1000, 1001)
		if err != nil {
			t.Fatal(err)
		}
		tr := tar.NewReader(&buf)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if hdr.Uid != 1000 || hdr.Gid != 1001 {
				t.Fatalf("%s uid/gid %d:%d", hdr.Name, hdr.Uid, hdr.Gid)
			}
		}
	})
}

func TestWriteAgentPayload(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		bin := filepath.Join(t.TempDir(), "agentcon")
		err := os.WriteFile(bin, []byte("#!/bin/true"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		err = writeAgentPayload(&buf, bin, "CERT", "BUNDLE", "known-hosts\n", 1000, 1001)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string][]byte{}
		tr := tar.NewReader(&buf)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if hdr.Uid != 1000 || hdr.Gid != 1001 {
				t.Fatalf("%s uid/gid %d:%d", hdr.Name, hdr.Uid, hdr.Gid)
			}
			if hdr.Typeflag == tar.TypeDir {
				continue
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			found[hdr.Name] = data
		}
		if string(found[tarName(agentBinPath)]) != "#!/bin/true" {
			t.Fatalf("binary %q", found[tarName(agentBinPath)])
		}
		if string(found[tarName(agentCACertPath)]) != "CERT" {
			t.Fatalf("ca %q", found[tarName(agentCACertPath)])
		}
		if string(found[tarName(agentCABundlePath)]) != "BUNDLE" {
			t.Fatalf("bundle %q", found[tarName(agentCABundlePath)])
		}
		if string(found[tarName(agentKnownHosts)]) != "known-hosts\n" {
			t.Fatalf("known_hosts %q", found[tarName(agentKnownHosts)])
		}
		cfg := string(found[tarName(agentSSHConfig)])
		if !bytes.Contains([]byte(cfg), []byte(agentBinPath)) {
			t.Fatalf("ssh config missing binary path: %s", cfg)
		}
		if !bytes.Contains([]byte(cfg), []byte(agentKnownHosts)) {
			t.Fatalf("ssh config missing known_hosts path: %s", cfg)
		}
	}

	t.Run("packs ssh files with owner", func(t *testing.T) {
		tester(t)
	})
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
