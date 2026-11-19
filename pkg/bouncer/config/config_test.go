package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		assert.Equal(t, tc.want, got, "HostMatches(%v, %q)", tc.pats, tc.host)
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
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
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
				require.NoError(t, err)
				assert.Equal(t, UnmatchedDeny, p.UnmatchedMode(), "unmatched not inherited")
				require.Len(t, p.Filters, 2)
				assert.Equal(t, "/tmp/cfg/a.ts", p.Filters[0].Path)
				assert.Equal(t, 1, p.Filters[1].Config["x"])
				require.Len(t, p.HTTP, 1)
				assert.Empty(t, p.HTTP[0].Rules, "child http should override parent")
				assert.Equal(t, "group/proj", cfg.Profiles["base"].HTTP[0].Rules[0].GitLabProject.Path)
				assert.Equal(t, ActionDeny, cfg.Profiles["base"].HTTP[0].DefaultAction())
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
bitwarden:
  work:
    email: User@Example.com
credentials:
  gl:
    token:
      source: bitwarden
      account: work
      item: GitLab
      path: $.login.password
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				src := cfg.Credentials["gl"].Token
				require.NotNil(t, src)
				assert.Equal(t, "GitLab", src.Item)
				require.NotNil(t, src.Bitwarden)
				assert.Equal(t, "work", src.Bitwarden.Name)
				assert.Equal(t, "User@Example.com", src.Bitwarden.Email)
				assert.Equal(t, "$.login.password", src.Path)
			},
		})
	})
	t.Run("requires bitwarden item", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "bitwarden:\n  w: {email: a@b.c}\ncredentials:\n  gl:\n    token: {source: bitwarden, account: w}\n",
			path:    "x.yaml",
			wantErr: true,
		})
	})
	t.Run("requires bitwarden path", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "bitwarden:\n  w: {email: a@b.c}\ncredentials:\n  gl:\n    token: {source: bitwarden, account: w, item: GitLab}\n",
			path:    "x.yaml",
			wantErr: true,
		})
	})
	t.Run("parses private_key and login slots", func(t *testing.T) {
		tester(t, testCase{
			path: "x.yaml",
			yaml: `
bitwarden:
  work:
    email: User@Example.com
credentials:
  deploy:
    private_key:
      source: file
      file: /tmp/id
  gl:
    username:
      source: bitwarden
      account: work
      item: GitLab
      path: $.login.username
    password:
      source: bitwarden
      account: work
      item: GitLab
      path: $.login.password
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				require.NotNil(t, cfg.Credentials["deploy"].PrivateKey)
				assert.True(t, strings.HasSuffix(cfg.Credentials["deploy"].PrivateKey.File, "id"), "file %v", cfg.Credentials["deploy"].PrivateKey.File)
				assert.Equal(t, "$.login.password", cfg.Credentials["gl"].Password.Path)
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
				require.Len(t, got, 1)
				assert.Equal(t, "/tmp/cfg/protect.ts", got[0].Path)
				assert.Equal(t, []any{"main"}, got[0].Config["branches"])
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
				assert.Equal(t, []string{"octo/hello"}, r.GitHubRepo)
				assert.Equal(t, []string{"pulls/**"}, r.GitHubSubpaths)
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

func TestBitwardenAccounts(t *testing.T) {
	type testCase struct {
		yaml    string
		want    []string
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		cfg, err := Parse([]byte(tc.yaml), "/tmp/cfg/x.yaml")
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		var got []string
		for _, a := range BitwardenAccounts(cfg.Credentials) {
			got = append(got, a.Name)
		}
		assert.Equal(t, tc.want, got)
	}
	slot := func(account string) string {
		return "      source: bitwarden\n      account: " + account + "\n      item: GitLab\n      path: $.login.password\n"
	}

	t.Run("lists used accounts once, sorted", func(t *testing.T) {
		tester(t, testCase{
			yaml: `
bitwarden:
  work: {email: work@example.com, password: {source: env, env: BW_WORK}}
  home: {email: home@example.com, password: {source: command, command: [rbw, get, master]}}
  unused: {email: unused@example.com}
credentials:
  a:
    username:
` + slot("work") + `    password:
` + slot("work") + `  b:
    token:
` + slot("home"),
			want: []string{"home", "work"},
		})
	})
	t.Run("resolves a file password against the config dir", func(t *testing.T) {
		cfg, err := Parse([]byte("bitwarden:\n  w: {email: a@b.c, password: {source: file, file: master}}\n"), "/tmp/cfg/x.yaml")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join("/tmp/cfg", "master"), cfg.Bitwarden["w"].Password.File)
	})
	t.Run("rejects an unknown account", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "credentials:\n  gl:\n    token:\n" + slot("missing"),
			wantErr: `credential "gl" token: unknown bitwarden account "missing"`,
		})
	})
	t.Run("rejects accounts sharing a vault", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "bitwarden:\n  a: {email: User@Example.com, server: https://vault.example.com/}\n  b: {email: user@example.com, server: https://Vault.example.com}\n",
			wantErr: `bitwarden accounts "a" and "b" use the same email and server`,
		})
	})
	t.Run("rejects an account without email", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "bitwarden:\n  a: {server: https://vault.example.com}\n",
			wantErr: `bitwarden account "a": requires email`,
		})
	})
	t.Run("rejects an unsupported password source", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "bitwarden:\n  a: {email: a@b.c, password: {source: ssh-agent}}\n",
			wantErr: `bitwarden account "a" password: source "ssh-agent" is not supported`,
		})
	})
	t.Run("rejects an incomplete password source", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "bitwarden:\n  a: {email: a@b.c, password: {source: env}}\n",
			wantErr: `bitwarden account "a" password: source env requires env`,
		})
	})
	t.Run("rejects a key colliding with a credential slot", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "bitwarden:\n  token: {email: a@b.c}\ncredentials:\n  bitwarden:\n    token: {source: env, env: X}\n",
			wantErr: `bitwarden account "token": provided key bitwarden.token collides with credential "bitwarden" slot token`,
		})
	})
	t.Run("rejects a dotted key colliding with a credential slot", func(t *testing.T) {
		tester(t, testCase{
			yaml:    "bitwarden:\n  work.token: {email: a@b.c}\ncredentials:\n  bitwarden.work:\n    token: {source: env, env: X}\n",
			wantErr: `bitwarden account "work.token": provided key bitwarden.work.token collides with credential "bitwarden.work" slot token`,
		})
	})
	t.Run("allows an account beside a dotted credential", func(t *testing.T) {
		tester(t, testCase{
			yaml: "bitwarden:\n  work: {email: a@b.c}\ncredentials:\n  bitwarden.work:\n    token: {source: env, env: X}\n",
		})
	})
	for _, field := range []string{"email: a@b.c", "server: https://vault.example.com", "password_env: BW_MASTER"} {
		t.Run("rejects the removed slot field "+strings.Fields(field)[0], func(t *testing.T) {
			tester(t, testCase{
				yaml:    "bitwarden:\n  w: {email: a@b.c}\ncredentials:\n  gl:\n    token:\n" + slot("w") + "      " + field + "\n",
				wantErr: "no longer takes email, server, or password_env",
			})
		})
	}
}
