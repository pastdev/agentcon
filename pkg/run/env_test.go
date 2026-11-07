package run

import (
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
)

const (
	testSmokeEnv  = "SMOKE_TOKEN"
	testOtherEnv  = "OTHER_TOKEN"
	testFromOS    = "from-os"
	testFromExtra = "from-extra"
	testFromFile  = "from-file"
	testCredTok   = "tok"
	testEnvPolicy = `
credentials:
  tok:
    token:
      source: env
      env: SMOKE_TOKEN
`
)

func TestHostEnvCredsFromOS(t *testing.T) {
	t.Setenv(testSmokeEnv, testFromOS)
	got, err := hostEnvCreds([]byte(testEnvPolicy), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got[testSmokeEnv] != testFromOS {
		t.Fatalf("got %v", got)
	}
}

func TestHostEnvCredsExtraWins(t *testing.T) {
	t.Setenv(testSmokeEnv, testFromOS)
	got, err := hostEnvCreds([]byte(testEnvPolicy), []string{testSmokeEnv + "=" + testFromExtra})
	if err != nil {
		t.Fatal(err)
	}
	if got[testSmokeEnv] != testFromExtra {
		t.Fatalf("got %v", got)
	}
}

func TestHostEnvCredsMissing(t *testing.T) {
	t.Setenv(testSmokeEnv, "")
	_, err := hostEnvCreds([]byte(`
credentials:
  tok:
    token:
      source: env
      env: SMOKE_TOKEN
  other:
    token:
      source: env
      env: OTHER_TOKEN
`), nil)
	if err == nil || !strings.Contains(err.Error(), testOtherEnv) || !strings.Contains(err.Error(), testSmokeEnv) {
		t.Fatalf("got %v", err)
	}
}

func TestHostEnvCredsSkipsOtherSources(t *testing.T) {
	got, err := hostEnvCreds([]byte(`
credentials:
  bw:
    token:
      source: bitwarden
      email: user@example.com
      item: GitLab
      path: $.login.password
`), []string{"UNUSED=1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestParseEnvPairsRejectsBareName(t *testing.T) {
	_, err := parseEnvPairs([]string{"NOVALUE"})
	if err == nil || !strings.Contains(err.Error(), "NAME=value") {
		t.Fatalf("got %v", err)
	}
}

func TestBouncerSidecarSpecServeIsPID1(t *testing.T) {
	spec := bouncerSidecarSpec(
		Request{
			Image:             testImage,
			User:              testUser,
			Context:           "git",
			Project:           "github.com/pastdev/agentcon",
			Slug:              testSlug,
			SidecarExtraHosts: []string{testExtraHost},
			SidecarEnv:        []string{testSmokeEnv + "=should-not-appear"},
		},
		map[string]string{labelRole: roleBouncer},
		"ext-net",
		"agent-net",
		"10.1.0.0/16",
		"10.2.0.0/16",
		18228,
	)
	if spec.Name != "agentcon-github-com-pastdev-agentcon-deadbeef-bouncer" {
		t.Fatalf("name %q", spec.Name)
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
		if k == testSmokeEnv {
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

func TestBouncerAgentEnvGitSSHCommand(t *testing.T) {
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
