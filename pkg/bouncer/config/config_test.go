package config

import (
	"strings"
	"testing"
)

const (
	testHostGitLab     = "gitlab.com"
	testHostKube       = "kube.example.com"
	testHostGitHubStar = "*.github.com"
	testHostExampleTLS = "example.com:8443"
)

func TestHostMatches(t *testing.T) {
	cases := []struct {
		pats []string
		host string
		want bool
	}{
		{[]string{testHostGitLab}, testHostGitLab, true},
		{[]string{testHostKube}, "Kube.example.com:443", true},
		{[]string{testHostKube}, "Åube.example.com", false},
		{[]string{testHostGitLab}, "GITLAB.COM", true},
		{[]string{testHostGitLab}, "GitLab.com:443", true},
		{[]string{testHostGitLab}, "evilgitlab.com", false},
		{[]string{testHostGitHubStar}, "api.github.com", true},
		{[]string{testHostGitHubStar}, "github.com", false},
		{[]string{testHostGitHubStar}, "a.b.github.com", true},
		{[]string{testHostExampleTLS}, "example.com:443", false},
		{[]string{testHostExampleTLS}, testHostExampleTLS, true},
		{[]string{testHostGitLab}, "gitlab.com:80", false},
		{[]string{testHostGitLab}, "gitlab.com:8443", false},
		{[]string{testHostGitLab}, testHostGitLab, true},
		{[]string{testHostKube}, "Kube.example.com:443", true},
		{[]string{testHostKube}, "Åube.example.com", false},
		{[]string{testHostGitLab}, "GITLAB.COM", true},
	}
	for _, c := range cases {
		if got := HostMatches(c.pats, c.host); got != c.want {
			t.Errorf("HostMatches(%v, %q) = %v, want %v", c.pats, c.host, got, c.want)
		}
	}
}

func TestParseAndExtends(t *testing.T) {
	cfg, err := Parse([]byte(`
credentials:
  gl:
    token: {source: keyring}
profiles:
  base:
    unmatched: deny
    filters: [a.ts]
    http:
      - name: gitlab
        hosts: [gitlab.com]
        credential: gl
        rules:
          - action: allow
            gitlab_project: Group/Proj
  child:
    extends: base
    filters:
      - path: b.ts
        config: {x: 1}
    http:
      - name: gitlab
        hosts: [gitlab.com]
        credential: gl
`), "/tmp/cfg/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := cfg.ResolvedProfile("child")
	if err != nil {
		t.Fatal(err)
	}
	if p.UnmatchedMode() != UnmatchedDeny {
		t.Errorf("unmatched not inherited: %q", p.Unmatched)
	}
	if len(p.Filters) != 2 || p.Filters[0].Path != "/tmp/cfg/a.ts" || p.Filters[1].Config["x"] != 1 {
		t.Errorf("filters: %+v", p.Filters)
	}
	if len(p.HTTP) != 1 || len(p.HTTP[0].Rules) != 0 {
		t.Errorf("child http should override parent: %+v", p.HTTP)
	}
	if got := cfg.Profiles["base"].HTTP[0].Rules[0].GitLabProject.Path; got != "group/proj" {
		t.Errorf("project path not normalized: %q", got)
	}
	if cfg.Profiles["base"].HTTP[0].DefaultAction() != ActionDeny {
		t.Error("service with rules should default to deny")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte("profiles:\n  p:\n    servics: []\n"), "x.yaml"); err == nil {
		t.Fatal("expected error for misspelled field")
	}
	if _, err := Parse([]byte("profiles:\n  p:\n    services: []\n"), "x.yaml"); err == nil {
		t.Fatal("expected error for old services key")
	}
}

func TestBitwardenCredential(t *testing.T) {
	cfg, err := Parse([]byte(`
credentials:
  gl:
    token:
      source: bitwarden
      email: User@Example.com
      item: GitLab
      path: $.login.password
`), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src := cfg.Credentials["gl"].Token
	if src == nil || src.Item != "GitLab" || src.Email != "User@Example.com" || src.Path != "$.login.password" {
		t.Fatalf("%+v", src)
	}
	if _, err := Parse([]byte("credentials:\n  gl:\n    token: {source: bitwarden, email: a@b.c}\n"), "x.yaml"); err == nil {
		t.Fatal("expected missing item to fail")
	}
	if _, err := Parse([]byte("credentials:\n  gl:\n    token: {source: bitwarden, email: a@b.c, item: GitLab}\n"), "x.yaml"); err == nil {
		t.Fatal("expected missing path to fail")
	}
}

func TestCredentialSlots(t *testing.T) {
	cfg, err := Parse([]byte(`
credentials:
  deploy:
    private_key:
      source: file
      file: /tmp/id
  gl:
    username:
      source: bitwarden
      email: User@Example.com
      item: GitLab
      path: $.login.username
    password:
      source: bitwarden
      email: User@Example.com
      item: GitLab
      path: $.login.password
`), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Credentials["deploy"].PrivateKey == nil || !strings.HasSuffix(cfg.Credentials["deploy"].PrivateKey.File, "id") {
		t.Fatalf("file %v", cfg.Credentials["deploy"].PrivateKey)
	}
	if got := cfg.Credentials["gl"].Password.Path; got != "$.login.password" {
		t.Fatalf("path %q", got)
	}
	if _, err := Parse([]byte("credentials:\n  gl: {}\n"), "x.yaml"); err == nil {
		t.Fatal("expected empty credential to fail")
	}
	if _, err := Parse([]byte("credentials:\n  gl:\n    token: {source: ssh-agent}\n"), "x.yaml"); err == nil {
		t.Fatal("expected ssh-agent on token to fail")
	}
}

func TestRuleFilters(t *testing.T) {
	cfg, err := Parse([]byte(`
credentials:
  gl:
    token: {source: keyring}
profiles:
  p:
    http:
      - name: gitlab
        hosts: [gitlab.com]
        credential: gl
        rules:
          - action: allow
            git: {}
            filters:
              - path: protect.ts
                config: {branches: [main]}
`), "/tmp/cfg/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Profiles["p"].HTTP[0].Rules[0].Filters
	if len(got) != 1 || got[0].Path != "/tmp/cfg/protect.ts" || got[0].Config["branches"].([]any)[0] != "main" {
		t.Fatalf("filters %+v", got)
	}
	if _, err := Parse([]byte(`
credentials:
  gl:
    token: {source: keyring}
profiles:
  p:
    http:
      - name: gitlab
        hosts: [gitlab.com]
        credential: gl
        rules:
          - action: deny
            path: /x
            filters: [protect.ts]
`), "x.yaml"); err == nil {
		t.Fatal("expected deny+filters to fail")
	}
}

func TestGitHubRepoConfig(t *testing.T) {
	cfg, err := Parse([]byte(`
credentials:
  gh:
    token: {source: keyring}
profiles:
  p:
    http:
      - name: github
        hosts: [github.com]
        credential: gh
        rules:
          - action: allow
            github_repo: [Octo/Hello]
            github_subpaths: ["/pulls/**"]
`), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Profiles["p"].HTTP[0].Rules[0]
	if len(r.GitHubRepo) != 1 || r.GitHubRepo[0] != "octo/hello" {
		t.Fatalf("repo %v", r.GitHubRepo)
	}
	if len(r.GitHubSubpaths) != 1 || r.GitHubSubpaths[0] != "pulls/**" {
		t.Fatalf("subpaths %v", r.GitHubSubpaths)
	}
	if _, err := Parse([]byte(`
credentials:
  gh:
    token: {source: keyring}
profiles:
  p:
    http:
      - name: github
        hosts: [github.com]
        credential: gh
        rules:
          - action: allow
            github_repo: octo/hello
`), "x.yaml"); err == nil {
		t.Fatal("expected scalar github_repo to fail")
	}
	if _, err := Parse([]byte(`
credentials:
  gh:
    token: {source: keyring}
profiles:
  p:
    http:
      - name: github
        hosts: [github.com]
        credential: gh
        rules:
          - action: allow
            github_subpaths: ["pulls/**"]
`), "x.yaml"); err == nil {
		t.Fatal("expected github_subpaths without github_repo to fail")
	}
}

func TestAnonymousProfileNeedsLoopback(t *testing.T) {
	base := "anonymous_profile: p\nprofiles:\n  p: {}\n"
	if _, err := Parse([]byte(base), "c.yaml"); err != nil {
		t.Fatalf("default loopback listen rejected: %v", err)
	}
	for _, listen := range []string{"0.0.0.0:8228", "192.168.1.5:8228", ":8228"} {
		if _, err := Parse([]byte("listen: "+listen+"\n"+base), "c.yaml"); err == nil {
			t.Errorf("listen %s with anonymous_profile accepted", listen)
		}
	}
}
