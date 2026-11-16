package host

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentLayoutNormalize(t *testing.T) {
	type testCase struct {
		layout  AgentLayout
		want    AgentLayout
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := tc.layout.Normalize()
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			assert.Equal(t, AgentLayout{}, got)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}
	withDefaults := func(f func(*AgentLayout)) AgentLayout {
		l := DefaultAgentLayout()
		f(&l)
		return l
	}

	t.Run("fills an empty layout with the defaults", func(t *testing.T) {
		tester(t, testCase{want: DefaultAgentLayout()})
	})
	t.Run("keeps set fields and fills the rest", func(t *testing.T) {
		tester(t, testCase{
			layout: AgentLayout{Binary: "/usr/local/libexec/host-tool/agentcon", SSHClient: "/usr/local/bin/ssh"},
			want: withDefaults(func(l *AgentLayout) {
				l.Binary = "/usr/local/libexec/host-tool/agentcon"
				l.SSHClient = "/usr/local/bin/ssh"
			}),
		})
	})
	t.Run("rejects a relative path", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{CACert: "opt/ca.pem"}, wantErr: `agent layout ca cert: "opt/ca.pem" is not absolute`})
	})
	t.Run("rejects traversal", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{SSHConfig: "/opt/x/../../etc/ssh/ssh_config"}, wantErr: "is not clean"})
	})
	t.Run("rejects a trailing slash", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{KnownHosts: "/opt/x/"}, wantErr: "is not clean"})
	})
	t.Run("rejects the root directory", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{Binary: "/"}, wantErr: "is the root directory"})
	})
	t.Run("rejects characters that need quoting", func(t *testing.T) {
		for _, p := range []string{"/opt/my tool/ca.pem", `/opt/x"y`, "/opt/$HOME", "/opt/a;b"} {
			tester(t, testCase{layout: AgentLayout{CACert: p}, wantErr: "has a character outside"})
		}
	})
	t.Run("checks paths as linux paths on every host", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{CACert: `C:\agent\ca.pem`}, wantErr: "is not absolute"})
	})
	t.Run("checks the ssh client too", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{SSHClient: "ssh"}, wantErr: "agent layout ssh client"})
	})
	t.Run("rejects two payload files at one path", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{CABundle: "/opt/agentcon/ca.pem"}, wantErr: "/opt/agentcon/ca.pem is used twice"})
	})
	t.Run("rejects a payload file inside another", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{CACert: "/opt/agentcon/bin/agentcon/ca.pem"}, wantErr: "overlap"})
	})
	t.Run("allows the ssh client anywhere", func(t *testing.T) {
		tester(t, testCase{
			layout: AgentLayout{SSHClient: "/opt/agentcon/bin/agentcon"},
			want:   withDefaults(func(l *AgentLayout) { l.SSHClient = "/opt/agentcon/bin/agentcon" }),
		})
	})
}

func TestWriteAgentPayload(t *testing.T) {
	type testCase struct {
		layout     AgentLayout
		wantFiles  map[string]string
		configPath string
		wantConfig []string
		wantErr    string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		bin := filepath.Join(t.TempDir(), "agentcon")
		err := os.WriteFile(bin, []byte("#!/bin/true"), 0o600)
		require.NoError(t, err)
		var buf bytes.Buffer
		err = WriteAgentPayload(&buf, AgentPayload{
			Layout: tc.layout,
			Binary: bin,
			Trust:  mgmt.Trust{CertPEM: "CERT", BundlePEM: "BUNDLE", SSHKnownHosts: "known-hosts\n"},
			UID:    1000,
			GID:    1001,
		})
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			assert.Zero(t, buf.Len(), "nothing is written for an invalid layout")
			return
		}
		require.NoError(t, err)
		found := map[string]string{}
		tr := tar.NewReader(&buf)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
			assert.Equal(t, 1000, hdr.Uid, hdr.Name)
			assert.Equal(t, 1001, hdr.Gid, hdr.Name)
			assert.False(t, strings.HasPrefix(hdr.Name, "/"), "tar names are relative: %s", hdr.Name)
			if hdr.Typeflag == tar.TypeDir {
				continue
			}
			data, err := io.ReadAll(tr)
			require.NoError(t, err)
			found[hdr.Name] = string(data)
		}
		for name, want := range tc.wantFiles {
			assert.Equal(t, want, found[name], name)
		}
		for _, want := range tc.wantConfig {
			assert.Contains(t, found[tc.configPath], want)
		}
	}

	t.Run("packs the default layout with owner", func(t *testing.T) {
		tester(t, testCase{
			wantFiles: map[string]string{
				"opt/agentcon/bin/agentcon":    "#!/bin/true",
				"opt/agentcon/ca.pem":          "CERT",
				"opt/agentcon/ca-bundle.pem":   "BUNDLE",
				"opt/agentcon/ssh/known_hosts": "known-hosts\n",
			},
			configPath: "opt/agentcon/ssh/config",
			wantConfig: []string{
				`ProxyCommand "/opt/agentcon/bin/agentcon" bouncer ssh-connect %h %p %r`,
				`UserKnownHostsFile "/opt/agentcon/ssh/known_hosts"`,
			},
		})
	})
	t.Run("packs a custom layout", func(t *testing.T) {
		tester(t, testCase{
			layout: AgentLayout{
				Binary:     "/usr/libexec/host-tool/agentcon",
				SSHConfig:  "/etc/host-tool/ssh_config",
				KnownHosts: "/etc/host-tool/known_hosts",
			},
			wantFiles: map[string]string{
				"usr/libexec/host-tool/agentcon": "#!/bin/true",
				"opt/agentcon/ca.pem":            "CERT",
				"etc/host-tool/known_hosts":      "known-hosts\n",
			},
			configPath: "etc/host-tool/ssh_config",
			wantConfig: []string{
				`ProxyCommand "/usr/libexec/host-tool/agentcon" bouncer ssh-connect %h %p %r`,
				`UserKnownHostsFile "/etc/host-tool/known_hosts"`,
			},
		})
	})
	t.Run("refuses an invalid layout", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{Binary: "relative/agentcon"}, wantErr: "is not absolute"})
	})
}

func TestAgentEnv(t *testing.T) {
	type testCase struct {
		layout  AgentLayout
		want    map[string]string
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		session := mgmt.NewSession{
			SessionRecord: mgmt.SessionRecord{ID: "deadbeef", Token: "tok"},
			Placeholders:  map[string]string{"GH_TOKEN": "placeholder"},
		}
		env, err := AgentEnv(tc.layout, session, "10.1.0.2:8228", "10.1.0.2:8229")
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			assert.Nil(t, env)
			return
		}
		require.NoError(t, err)
		got := map[string]string{}
		for _, e := range env {
			k, v, ok := strings.Cut(e, "=")
			require.True(t, ok, "env %q", e)
			got[k] = v
		}
		for k, want := range tc.want {
			assert.Equal(t, want, got[k], k)
		}
	}

	t.Run("uses the default layout", func(t *testing.T) {
		tester(t, testCase{want: map[string]string{
			"GIT_SSH_COMMAND":     `"/usr/bin/ssh" -F "/opt/agentcon/ssh/config"`,
			"SSL_CERT_FILE":       "/opt/agentcon/ca-bundle.pem",
			"NODE_EXTRA_CA_CERTS": "/opt/agentcon/ca.pem",
			"BOUNCER_PROXY":       "http://10.1.0.2:8228",
			"BOUNCER_SSH_ADDR":    "10.1.0.2:8229",
			"BOUNCER_SESSION_ID":  "deadbeef",
			"GH_TOKEN":            "placeholder",
		}})
	})
	t.Run("uses a custom layout", func(t *testing.T) {
		tester(t, testCase{
			layout: AgentLayout{SSHConfig: "/etc/host-tool/ssh_config", SSHClient: "/usr/local/bin/ssh", CABundle: "/etc/host-tool/bundle.pem"},
			want: map[string]string{
				"GIT_SSH_COMMAND": `"/usr/local/bin/ssh" -F "/etc/host-tool/ssh_config"`,
				"SSL_CERT_FILE":   "/etc/host-tool/bundle.pem",
			},
		})
	})
	t.Run("refuses an invalid layout", func(t *testing.T) {
		tester(t, testCase{layout: AgentLayout{SSHClient: "/usr/bin/ssh -v"}, wantErr: "has a character outside"})
	})
}
