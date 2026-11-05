package run

import (
	"strings"
	"testing"
)

const (
	testSmokeEnv  = "SMOKE_TOKEN"
	testOtherEnv  = "OTHER_TOKEN"
	testFromOS    = "from-os"
	testFromExtra = "from-extra"
	testEnvPolicy = `
credentials:
  tok:
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
    source: env
    env: SMOKE_TOKEN
  other:
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
    source: bitwarden
    bitwarden:
      email: user@example.com
      item: GitLab
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
			SidecarExtraHosts: []string{testExtraHost},
			SidecarEnv:        []string{testSmokeEnv + "=should-not-appear"},
		},
		map[string]string{"agentcon.role": "bouncer"},
		"ext-net",
		"agent-net",
		"10.1.0.0/16",
		"10.2.0.0/16",
		18228,
	)
	if len(spec.Entrypoint) != 1 || spec.Entrypoint[0] != sidecarBinPath {
		t.Fatalf("entrypoint %v", spec.Entrypoint)
	}
	if len(spec.Args) < 2 || spec.Args[0] != "bouncer" || spec.Args[1] != "serve" {
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
