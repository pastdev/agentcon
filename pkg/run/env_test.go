package run

import (
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
)

func TestHostEnvCreds(t *testing.T) {
	type testCase struct {
		policy  string
		extra   []string
		setenv  map[string]string
		want    map[string]string
		wantErr []string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		for k, v := range tc.setenv {
			t.Setenv(k, v)
		}
		got, err := hostEnvCreds([]byte(tc.policy), tc.extra)
		if len(tc.wantErr) > 0 {
			if err == nil {
				t.Fatal("expected error")
			}
			for _, s := range tc.wantErr {
				if !strings.Contains(err.Error(), s) {
					t.Fatalf("got %v, want %q", err, s)
				}
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("got %v", got)
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Fatalf("got %v", got)
			}
		}
	}

	t.Run("reads from the process environment", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: env
      env: SMOKE_TOKEN
`,
			setenv: map[string]string{"SMOKE_TOKEN": "from-os"},
			want:   map[string]string{"SMOKE_TOKEN": "from-os"},
		})
	})
	t.Run("lets extra pairs win over the process environment", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: env
      env: SMOKE_TOKEN
`,
			setenv: map[string]string{"SMOKE_TOKEN": "from-os"},
			extra:  []string{"SMOKE_TOKEN=from-extra"},
			want:   map[string]string{"SMOKE_TOKEN": "from-extra"},
		})
	})
	t.Run("reports every missing env slot", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  tok:
    token:
      source: env
      env: SMOKE_TOKEN
  other:
    token:
      source: env
      env: OTHER_TOKEN
`,
			setenv:  map[string]string{"SMOKE_TOKEN": ""},
			wantErr: []string{"SMOKE_TOKEN", "OTHER_TOKEN"},
		})
	})
	t.Run("skips non-env sources", func(t *testing.T) {
		tester(t, testCase{
			policy: `
credentials:
  bw:
    token:
      source: bitwarden
      email: user@example.com
      item: GitLab
      path: $.login.password
`,
			extra: []string{"UNUSED=1"},
			want:  map[string]string{},
		})
	})
}

func TestParseEnvPairs(t *testing.T) {
	tester := func(t *testing.T, pairs []string, wantErr string) {
		t.Helper()
		_, err := parseEnvPairs(pairs)
		if wantErr == "" {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("got %v", err)
		}
	}

	t.Run("rejects a bare name", func(t *testing.T) {
		tester(t, []string{"NOVALUE"}, "NAME=value")
	})
}

func TestBouncerSidecarSpec(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		spec := bouncerSidecarSpec(
			Request{
				Image:             testImage,
				User:              testUser,
				Context:           "git",
				Project:           "github.com/pastdev/agentcon",
				Slug:              testSlug,
				SidecarExtraHosts: []string{testExtraHost},
				SidecarEnv:        []string{"SMOKE_TOKEN=should-not-appear"},
			},
			map[string]string{labelRole: roleBouncer},
			externalNet{name: "ext-net", subnet: "10.2.0.0/16", hostPort: 18228, controlAddr: "127.0.0.1:18228"},
			"agent-net",
			"10.1.0.0/16",
		)
		if spec.Name != "agentcon-github-com-pastdev-agentcon-deadbeef-bouncer" {
			t.Fatalf("name %q", spec.Name)
		}
		if spec.Image != sidecarImage {
			t.Fatalf("image %q", spec.Image)
		}
		if len(spec.Entrypoint) != 1 || spec.Entrypoint[0] != sidecarBinPath {
			t.Fatalf("entrypoint %v", spec.Entrypoint)
		}
		if len(spec.Args) < 2 || spec.Args[0] != roleBouncer || spec.Args[1] != "serve" {
			t.Fatalf("args %v", spec.Args)
		}
		if len(spec.ExtraHosts) != 1 || spec.ExtraHosts[0] != testExtraHost {
			t.Fatalf("extra hosts %v", spec.ExtraHosts)
		}
		if spec.Networks[0] != "ext-net" || spec.Networks[1] != "agent-net" {
			t.Fatalf("networks %v", spec.Networks)
		}
		if spec.Ports[0].HostPort != "18228" || spec.Ports[0].ContainerPort != defaultProxyPort {
			t.Fatalf("ports %+v", spec.Ports)
		}
		want := map[string]string{
			"AGENT_NETWORK":      "10.1.0.0/16",
			"MANAGEMENT_NETWORK": "10.2.0.0/16",
			"MANAGEMENT_PORT":    defaultProxyPort,
		}
		got := map[string]string{}
		for _, e := range spec.Env {
			k, v, ok := strings.Cut(e, "=")
			if !ok {
				t.Fatalf("env %q", e)
			}
			if k == "SMOKE_TOKEN" {
				t.Fatal("secret in container env")
			}
			got[k] = v
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("%s=%q want %q", k, got[k], v)
			}
		}
	}

	t.Run("uses serve as pid 1 and omits secrets", func(t *testing.T) {
		tester(t)
	})
}

func TestBouncerAgentEnv(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		env := bouncerAgentEnv(daemon.NewSession{SessionRecord: daemon.SessionRecord{Token: "tok"}}, "10.1.0.2")
		got := map[string]string{}
		for _, e := range env {
			k, v, ok := strings.Cut(e, "=")
			if !ok {
				t.Fatalf("env %q", e)
			}
			got[k] = v
		}
		want := `"` + agentSSHClient + `" -F "` + agentSSHConfig + `"`
		if got["GIT_SSH_COMMAND"] != want {
			t.Fatalf("GIT_SSH_COMMAND=%q want %q", got["GIT_SSH_COMMAND"], want)
		}
		if strings.Contains(got["GIT_SSH_COMMAND"], agentBinPath) {
			t.Fatalf("GIT_SSH_COMMAND should invoke ssh, not agentcon: %q", got["GIT_SSH_COMMAND"])
		}
	}

	t.Run("sets GIT_SSH_COMMAND to ssh -F", func(t *testing.T) {
		tester(t)
	})
}
