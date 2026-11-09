package config

import (
	"strings"
	"testing"
)

func TestHostMatches(t *testing.T) {
	type testCase struct {
		pats []string
		host string
		want bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := HostMatches(tc.pats, tc.host)
		if got != tc.want {
			t.Fatalf("HostMatches(%v, %q) = %v, want %v", tc.pats, tc.host, got, tc.want)
		}
	}

	t.Run("matches gitlab.com", func(t *testing.T) {
		tester(t, testCase{pats: []string{"gitlab.com"}, host: "gitlab.com", want: true})
	})
	t.Run("matches kube host case-insensitively with port", func(t *testing.T) {
		tester(t, testCase{pats: []string{"kube.example.com"}, host: "Kube.example.com:443", want: true})
	})
	t.Run("rejects a lookalike unicode host", func(t *testing.T) {
		tester(t, testCase{pats: []string{"kube.example.com"}, host: "Åube.example.com", want: false})
	})
	t.Run("matches GITLAB.COM", func(t *testing.T) {
		tester(t, testCase{pats: []string{"gitlab.com"}, host: "GITLAB.COM", want: true})
	})
	t.Run("matches GitLab.com with https port", func(t *testing.T) {
		tester(t, testCase{pats: []string{"gitlab.com"}, host: "GitLab.com:443", want: true})
	})
	t.Run("rejects evilgitlab.com", func(t *testing.T) {
		tester(t, testCase{pats: []string{"gitlab.com"}, host: "evilgitlab.com", want: false})
	})
	for _, host := range []string{"evil.example#.github.com", "evil.example?.github.com", "evil.example/.github.com", "u@evil.example.github.com", "evil.example%23.github.com", "evil.example\\.github.com"} {
		t.Run("rejects smuggled host "+host, func(t *testing.T) {
			tester(t, testCase{pats: []string{"*.github.com"}, host: host + ":443", want: false})
		})
	}
	t.Run("matches an IPv6 literal", func(t *testing.T) {
		tester(t, testCase{pats: []string{"[::1]:8443"}, host: "[::1]:8443", want: true})
	})
	t.Run("matches a github wildcard subdomain", func(t *testing.T) {
		tester(t, testCase{pats: []string{"*.github.com"}, host: "api.github.com", want: true})
	})
	t.Run("does not match github.com against a subdomain wildcard", func(t *testing.T) {
		tester(t, testCase{pats: []string{"*.github.com"}, host: "github.com", want: false})
	})
	t.Run("matches a nested github subdomain", func(t *testing.T) {
		tester(t, testCase{pats: []string{"*.github.com"}, host: "a.b.github.com", want: true})
	})
	t.Run("rejects the wrong port on an explicit host:port pattern", func(t *testing.T) {
		tester(t, testCase{pats: []string{"example.com:8443"}, host: "example.com:443", want: false})
	})
	t.Run("matches an explicit host:port pattern", func(t *testing.T) {
		tester(t, testCase{pats: []string{"example.com:8443"}, host: "example.com:8443", want: true})
	})
	t.Run("rejects gitlab.com:80 against a host-only pattern", func(t *testing.T) {
		tester(t, testCase{pats: []string{"gitlab.com"}, host: "gitlab.com:80", want: false})
	})
	t.Run("rejects gitlab.com:8443 against a host-only pattern", func(t *testing.T) {
		tester(t, testCase{pats: []string{"gitlab.com"}, host: "gitlab.com:8443", want: false})
	})
}

func TestParse(t *testing.T) {
	type testCase struct {
		yaml    string
		path    string
		wantErr bool
		check   func(*testing.T, *Config)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		cfg, err := Parse([]byte(tc.yaml), tc.path)
		if tc.wantErr {
			if err == nil {
				t.Fatal("expected error")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if tc.check != nil {
			tc.check(t, cfg)
		}
	}

	t.Run("inherits unmatched and merges filters", func(t *testing.T) {
		tester(t, testCase{
			path: "/tmp/cfg/config.yaml",
			yaml: `
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
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				p, err := cfg.ResolvedProfile("child")
				if err != nil {
					t.Fatal(err)
				}
				if p.UnmatchedMode() != UnmatchedDeny {
					t.Fatalf("unmatched not inherited: %q", p.Unmatched)
				}
				if len(p.Filters) != 2 || p.Filters[0].Path != "/tmp/cfg/a.ts" || p.Filters[1].Config["x"] != 1 {
					t.Fatalf("filters: %+v", p.Filters)
				}
				if len(p.HTTP) != 1 || len(p.HTTP[0].Rules) != 0 {
					t.Fatalf("child http should override parent: %+v", p.HTTP)
				}
				if got := cfg.Profiles["base"].HTTP[0].Rules[0].GitLabProject.Path; got != "group/proj" {
					t.Fatalf("project path not normalized: %q", got)
				}
				if cfg.Profiles["base"].HTTP[0].DefaultAction() != ActionDeny {
					t.Fatal("service with rules should default to deny")
				}
			},
		})
	})
	t.Run("rejects a misspelled field", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "profiles:\n  p:\n    servics: []\n",
			path:    "x.yaml",
			wantErr: true,
		})
	})
	t.Run("rejects the old services key", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "profiles:\n  p:\n    services: []\n",
			path:    "x.yaml",
			wantErr: true,
		})
	})
	t.Run("parses a bitwarden token slot", func(t *testing.T) {
		tester(t, testCase{
			path: "x.yaml",
			yaml: `
credentials:
  gl:
    token:
      source: bitwarden
      email: User@Example.com
      item: GitLab
      path: $.login.password
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				src := cfg.Credentials["gl"].Token
				if src == nil || src.Item != "GitLab" || src.Email != "User@Example.com" || src.Path != "$.login.password" {
					t.Fatalf("%+v", src)
				}
			},
		})
	})
	t.Run("requires bitwarden item", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "credentials:\n  gl:\n    token: {source: bitwarden, email: a@b.c}\n",
			path:    "x.yaml",
			wantErr: true,
		})
	})
	t.Run("requires bitwarden path", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "credentials:\n  gl:\n    token: {source: bitwarden, email: a@b.c, item: GitLab}\n",
			path:    "x.yaml",
			wantErr: true,
		})
	})
	t.Run("parses private_key and login slots", func(t *testing.T) {
		tester(t, testCase{
			path: "x.yaml",
			yaml: `
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
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Credentials["deploy"].PrivateKey == nil || !strings.HasSuffix(cfg.Credentials["deploy"].PrivateKey.File, "id") {
					t.Fatalf("file %v", cfg.Credentials["deploy"].PrivateKey)
				}
				if got := cfg.Credentials["gl"].Password.Path; got != "$.login.password" {
					t.Fatalf("path %q", got)
				}
			},
		})
	})
	t.Run("rejects an empty credential", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "credentials:\n  gl: {}\n",
			path:    "x.yaml",
			wantErr: true,
		})
	})
	t.Run("rejects ssh-agent on a token slot", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "credentials:\n  gl:\n    token: {source: ssh-agent}\n",
			path:    "x.yaml",
			wantErr: true,
		})
	})
	t.Run("parses rule filters", func(t *testing.T) {
		tester(t, testCase{
			path: "/tmp/cfg/config.yaml",
			yaml: `
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
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				got := cfg.Profiles["p"].HTTP[0].Rules[0].Filters
				if len(got) != 1 || got[0].Path != "/tmp/cfg/protect.ts" || got[0].Config["branches"].([]any)[0] != "main" {
					t.Fatalf("filters %+v", got)
				}
			},
		})
	})
	t.Run("rejects filters on a deny rule", func(t *testing.T) {
		tester(t, testCase{
			path: "x.yaml",
			yaml: `
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
`,
			wantErr: true,
		})
	})
	t.Run("normalizes github_repo and subpaths", func(t *testing.T) {
		tester(t, testCase{
			path: "x.yaml",
			yaml: `
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
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				r := cfg.Profiles["p"].HTTP[0].Rules[0]
				if len(r.GitHubRepo) != 1 || r.GitHubRepo[0] != "octo/hello" {
					t.Fatalf("repo %v", r.GitHubRepo)
				}
				if len(r.GitHubSubpaths) != 1 || r.GitHubSubpaths[0] != "pulls/**" {
					t.Fatalf("subpaths %v", r.GitHubSubpaths)
				}
			},
		})
	})
	t.Run("rejects a scalar github_repo", func(t *testing.T) {
		tester(t, testCase{
			path: "x.yaml",
			yaml: `
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
`,
			wantErr: true,
		})
	})
	t.Run("rejects github_subpaths without github_repo", func(t *testing.T) {
		tester(t, testCase{
			path: "x.yaml",
			yaml: `
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
`,
			wantErr: true,
		})
	})
	t.Run("allows anonymous_profile on loopback", func(t *testing.T) {
		tester(t, testCase{
			path: "c.yaml",
			yaml: "anonymous_profile: p\nprofiles:\n  p: {}\n",
		})
	})
	t.Run("rejects anonymous_profile on a public listen", func(t *testing.T) {
		base := "anonymous_profile: p\nprofiles:\n  p: {}\n"
		for _, listen := range []string{"0.0.0.0:8228", "192.168.1.5:8228", ":8228"} {
			t.Run(listen, func(t *testing.T) {
				tester(t, testCase{
					path:    "c.yaml",
					yaml:    "listen: " + listen + "\n" + base,
					wantErr: true,
				})
			})
		}
	})
}
