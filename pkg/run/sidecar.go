package run

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"strings"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
)

type tarFS struct {
	tw   *tar.Writer
	seen map[string]bool
	uid  int
	gid  int
}

func (f *tarFS) WriteFile(name string, data []byte, perm os.FileMode) error {
	return f.writeBytes(name, data, int64(perm))
}

func (f *tarFS) header(name string, mode, size int64) *tar.Header {
	return &tar.Header{
		Name: name,
		Mode: mode,
		Size: size,
		Uid:  f.uid,
		Gid:  f.gid,
	}
}

// WriteSidecarPayload streams the sidecar filesystem into w as a tar archive.
func WriteSidecarPayload(w io.Writer, policy []byte, tsFiles map[string]string, binaryPath, token string) error {
	return writeSidecarPayload(w, policy, tsFiles, binaryPath, token, 0, 0)
}

func writeSidecarPayload(w io.Writer, policy []byte, tsFiles map[string]string, binaryPath, token string, uid, gid int) error {
	tw := tar.NewWriter(w)
	tfs := &tarFS{tw: tw, seen: map[string]bool{}, uid: uid, gid: gid}
	prefix := strings.TrimPrefix(sidecarHome, "/")
	err := bouncercfg.WriteLayout(bouncercfg.Prefix(tfs, prefix), policy, tsFiles)
	if err != nil {
		return fmt.Errorf("write sidecar layout: %w", err)
	}
	err = tfs.WriteFile(prefix+"/state/admin-token", []byte(token+"\n"), 0o600)
	if err != nil {
		return fmt.Errorf("write admin token: %w", err)
	}
	err = tfs.writePath(prefix+"/bin/agentcon", binaryPath, 0o755)
	if err != nil {
		return fmt.Errorf("write sidecar binary: %w", err)
	}
	err = tw.Close()
	if err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	return nil
}

func writeAgentPayload(w io.Writer, binaryPath, certPEM, bundlePEM, knownHosts string, uid, gid int) error {
	tw := tar.NewWriter(w)
	tfs := &tarFS{tw: tw, seen: map[string]bool{}, uid: uid, gid: gid}
	err := tfs.writePath(tarName(agentBinPath), binaryPath, 0o755)
	if err != nil {
		return fmt.Errorf("write agent binary: %w", err)
	}
	if certPEM != "" {
		err = tfs.WriteFile(tarName(agentCACertPath), []byte(certPEM), 0o644)
		if err != nil {
			return fmt.Errorf("write ca: %w", err)
		}
	}
	if bundlePEM != "" {
		err = tfs.WriteFile(tarName(agentCABundlePath), []byte(bundlePEM), 0o644)
		if err != nil {
			return fmt.Errorf("write ca bundle: %w", err)
		}
	}
	err = tfs.WriteFile(tarName(agentKnownHosts), []byte(knownHosts), 0o644)
	if err != nil {
		return fmt.Errorf("write known_hosts: %w", err)
	}
	err = tfs.WriteFile(tarName(agentSSHConfig), []byte(fmt.Sprintf(`Host *
  ProxyCommand "%s" bouncer ssh-connect %%h %%p %%r
  UserKnownHostsFile "%s"
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  IdentityAgent none
  IdentitiesOnly yes
  PubkeyAuthentication no
  ForwardAgent no
`, agentBinPath, agentKnownHosts)), 0o644)
	if err != nil {
		return fmt.Errorf("write ssh config: %w", err)
	}
	err = tw.Close()
	if err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	return nil
}

func tarName(abs string) string {
	return strings.TrimPrefix(abs, "/")
}

func (f *tarFS) writeBytes(name string, data []byte, mode int64) error {
	err := writeTarDirs(f.tw, name, f.seen, f.uid, f.gid)
	if err != nil {
		return err
	}
	err = f.tw.WriteHeader(f.header(name, mode, int64(len(data))))
	if err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	_, err = f.tw.Write(data)
	if err != nil {
		return fmt.Errorf("tar write %s: %w", name, err)
	}
	return nil
}

func (f *tarFS) writePath(name, path string, mode int64) error {
	err := writeTarDirs(f.tw, name, f.seen, f.uid, f.gid)
	if err != nil {
		return err
	}
	//nolint:gosec // packing a host overlay or the agentcon binary
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	err = f.tw.WriteHeader(f.header(name, mode, info.Size()))
	if err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	_, err = io.Copy(f.tw, file)
	if err != nil {
		return fmt.Errorf("tar write %s: %w", name, err)
	}
	return nil
}
