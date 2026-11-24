package host

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/pastdev/agentcon/pkg/bouncer/envexport"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
)

// AgentLayout is where the agent container finds bouncer files. The paths
// are Linux paths inside the agent container, on every host OS.
type AgentLayout struct {
	// Binary is the agentcon executable that ssh_config runs as its
	// ProxyCommand.
	Binary string
	// CACert is the bouncer CA alone.
	CACert string
	// CABundle is the system roots plus the bouncer CA.
	CABundle string
	// SSHConfig is the ssh_config that routes ssh through the bouncer.
	SSHConfig string
	// KnownHosts trusts the bouncer SSH CA.
	KnownHosts string
	// GitSign is a one-line wrapper around "agentcon bouncer git-sign" for
	// git's gpg.openpgp.program, which takes a single executable path.
	GitSign string
	// SSHClient is the ssh executable already in the agent image. It is not
	// part of the payload.
	SSHClient string
}

// DefaultAgentLayout is the layout agentcon uses.
func DefaultAgentLayout() AgentLayout {
	return AgentLayout{
		Binary:     "/opt/agentcon/bin/agentcon",
		CACert:     "/opt/agentcon/ca.pem",
		CABundle:   "/opt/agentcon/ca-bundle.pem",
		SSHConfig:  "/opt/agentcon/ssh/config",
		KnownHosts: "/opt/agentcon/ssh/known_hosts",
		GitSign:    "/opt/agentcon/bin/git-sign",
		SSHClient:  "/usr/bin/ssh",
	}
}

// Normalize fills empty fields from DefaultAgentLayout and validates the
// result. Each path must be absolute, equal to its path.Clean form, and use
// only A-Z a-z 0-9 . _ - + / @, so ssh_config, ProxyCommand, and
// GIT_SSH_COMMAND need no escaping. The five payload files must be distinct,
// and none may lie inside another.
func (l AgentLayout) Normalize() (AgentLayout, error) {
	d := DefaultAgentLayout()
	fields := []struct {
		name    string
		value   *string
		def     string
		payload bool
	}{
		{"binary", &l.Binary, d.Binary, true},
		{"ca cert", &l.CACert, d.CACert, true},
		{"ca bundle", &l.CABundle, d.CABundle, true},
		{"ssh config", &l.SSHConfig, d.SSHConfig, true},
		{"known hosts", &l.KnownHosts, d.KnownHosts, true},
		{"git sign", &l.GitSign, d.GitSign, true},
		{"ssh client", &l.SSHClient, d.SSHClient, false},
	}
	var payload []string
	for _, f := range fields {
		if *f.value == "" {
			*f.value = f.def
		}
		err := checkAgentPath(*f.value)
		if err != nil {
			return AgentLayout{}, fmt.Errorf("agent layout %s: %w", f.name, err)
		}
		if f.payload {
			payload = append(payload, *f.value)
		}
	}
	for i, a := range payload {
		for _, b := range payload[i+1:] {
			if a == b {
				return AgentLayout{}, fmt.Errorf("agent layout: %s is used twice", a)
			}
			if strings.HasPrefix(b, a+"/") || strings.HasPrefix(a, b+"/") {
				return AgentLayout{}, fmt.Errorf("agent layout: %s and %s overlap", a, b)
			}
		}
	}
	return l, nil
}

func checkAgentPath(p string) error {
	if !path.IsAbs(p) {
		return fmt.Errorf("%q is not absolute", p)
	}
	if p == "/" {
		return fmt.Errorf("%q is the root directory", p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("%q is not clean (want %q)", p, path.Clean(p))
	}
	for _, r := range p {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-+/@", r)
		if !ok {
			return fmt.Errorf("%q has a character outside A-Z a-z 0-9 . _ - + / @", p)
		}
	}
	return nil
}

// AgentPayload is what WriteAgentPayload packs.
type AgentPayload struct {
	// Layout is normalized before use. The zero value is
	// DefaultAgentLayout.
	Layout AgentLayout
	// Binary is the host path of a Linux agentcon executable that matches
	// the agent container's architecture.
	Binary string
	// Trust is the daemon's CA material, from mgmt.Client.Trust.
	Trust mgmt.Trust
	// UID and GID own every packed file and directory.
	UID, GID int
}

// WriteAgentPayload streams the agent's bouncer files into w as a tar
// archive rooted at /, ready to copy into the agent container.
func WriteAgentPayload(w io.Writer, p AgentPayload) error {
	l, err := p.Layout.Normalize()
	if err != nil {
		return err
	}
	tw := &tarWriter{tw: tar.NewWriter(w), seen: map[string]bool{}, uid: p.UID, gid: p.GID}
	err = tw.writePath(l.Binary, p.Binary, 0o755)
	if err != nil {
		return fmt.Errorf("write agent binary: %w", err)
	}
	if p.Trust.CertPEM != "" {
		err = tw.writeBytes(l.CACert, []byte(p.Trust.CertPEM))
		if err != nil {
			return fmt.Errorf("write ca: %w", err)
		}
	}
	if p.Trust.BundlePEM != "" {
		err = tw.writeBytes(l.CABundle, []byte(p.Trust.BundlePEM))
		if err != nil {
			return fmt.Errorf("write ca bundle: %w", err)
		}
	}
	err = tw.writeBytes(l.KnownHosts, []byte(p.Trust.SSHKnownHosts))
	if err != nil {
		return fmt.Errorf("write known_hosts: %w", err)
	}
	err = tw.writeBytes(l.SSHConfig, []byte(fmt.Sprintf(`Host *
  ProxyCommand "%s" bouncer ssh-connect %%h %%p %%r
  UserKnownHostsFile "%s"
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  IdentityAgent none
  IdentitiesOnly yes
  PubkeyAuthentication no
  ForwardAgent no
`, l.Binary, l.KnownHosts)))
	if err != nil {
		return fmt.Errorf("write ssh config: %w", err)
	}
	err = tw.writeFile(l.GitSign, []byte(fmt.Sprintf("#!/usr/bin/env bash\nexec \"%s\" bouncer git-sign \"$@\"\n", l.Binary)), 0o755)
	if err != nil {
		return fmt.Errorf("write git-sign: %w", err)
	}
	err = tw.tw.Close()
	if err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	return nil
}

// AgentEnv is the agent container environment for session s, as NAME=value
// pairs. proxyAddr and sshAddr are the sidecar's proxy and SSH listeners as
// the agent reaches them, such as 10.1.0.2:8228.
func AgentEnv(l AgentLayout, s mgmt.NewSession, proxyAddr, sshAddr string) ([]string, error) {
	l, err := l.Normalize()
	if err != nil {
		return nil, err
	}
	env := envexport.Build(envexport.Params{
		ProxyAddr:    proxyAddr,
		SSHAddr:      sshAddr,
		Token:        s.Token,
		SessionID:    s.ID,
		CACert:       l.CACert,
		CABundle:     l.CABundle,
		SSHCommand:   fmt.Sprintf(`"%s" -F "%s"`, l.SSHClient, l.SSHConfig),
		SignerURL:    s.SignerURL,
		Placeholders: s.Placeholders,
	})
	out := make([]string, 0, len(env.Vars))
	for _, kv := range env.Vars {
		out = append(out, kv[0]+"="+kv[1])
	}
	return out, nil
}

// tarWriter packs absolute Linux paths, adding parent directories once.
type tarWriter struct {
	tw   *tar.Writer
	seen map[string]bool
	uid  int
	gid  int
}

func (t *tarWriter) writeDirs(name string) error {
	var parts []string
	for dir := path.Dir(name); dir != "/"; dir = path.Dir(dir) {
		parts = append([]string{dir}, parts...)
	}
	for _, d := range parts {
		if t.seen[d] {
			continue
		}
		t.seen[d] = true
		err := t.tw.WriteHeader(&tar.Header{
			Name:     strings.TrimPrefix(d, "/") + "/",
			Mode:     0o755,
			Typeflag: tar.TypeDir,
			Uid:      t.uid,
			Gid:      t.gid,
		})
		if err != nil {
			return fmt.Errorf("tar dir %s: %w", d, err)
		}
	}
	return nil
}

func (t *tarWriter) header(name string, mode, size int64) *tar.Header {
	return &tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: mode, Size: size, Uid: t.uid, Gid: t.gid}
}

// writeBytes packs a world-readable file.
func (t *tarWriter) writeBytes(name string, data []byte) error {
	return t.writeFile(name, data, 0o644)
}

// writeFile packs data with mode.
func (t *tarWriter) writeFile(name string, data []byte, mode int64) error {
	err := t.writeDirs(name)
	if err != nil {
		return err
	}
	err = t.tw.WriteHeader(t.header(name, mode, int64(len(data))))
	if err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	_, err = t.tw.Write(data)
	if err != nil {
		return fmt.Errorf("tar write %s: %w", name, err)
	}
	return nil
}

func (t *tarWriter) writePath(name, hostPath string, mode int64) error {
	err := t.writeDirs(name)
	if err != nil {
		return err
	}
	//nolint:gosec // packing the agentcon binary the caller chose
	file, err := os.Open(hostPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", hostPath, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", hostPath, err)
	}
	err = t.tw.WriteHeader(t.header(name, mode, info.Size()))
	if err != nil {
		return fmt.Errorf("tar header %s: %w", name, err)
	}
	_, err = io.Copy(t.tw, file)
	if err != nil {
		return fmt.Errorf("tar write %s: %w", name, err)
	}
	return nil
}
