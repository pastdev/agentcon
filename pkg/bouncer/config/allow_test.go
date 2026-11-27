package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowCreds defines one credential of each kind for the load checks.
const allowCreds = `
credentials:
  plain:
    allow: [agent, subrequest]
    token: {source: provided}
  agent-only:
    allow: [agent]
    token: {source: provided}
  audit:
    allow: [subrequest]
    token: {source: provided}
  sign:
    allow: [internal]
    private_key: {source: provided}
`

func TestAllowLoadChecks(t *testing.T) {
	type testCase struct {
		yaml    string
		wantErr string
		check   func(*testing.T, *Config)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		cfg, err := Parse([]byte(tc.yaml), "/tmp/cfg/config.yaml")
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		if tc.check != nil {
			tc.check(t, cfg)
		}
	}
	service := func(svc string) string {
		return allowCreds + `
profiles:
  p:
    http:
      - name: api
        hosts: [api.example.com]
` + svc
	}

	t.Run("accepts every kind of credential where it belongs", func(t *testing.T) {
		tester(t, testCase{
			yaml: service(`        credentials: [plain, audit]
        inject: {credential: plain, bearer: true}
        lookup_credential: plain
        rules:
          - action: allow
            path: /audit
            subrequest:
              filters: [lookup]
              credentials: [audit]
          - action: allow
            gitlab_project: group/proj
            filters: [{path: lookup.ts, id: lookup}]
`),
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				svc := cfg.Profiles["p"].HTTP[0]
				assert.Equal(t, []string{"plain", "audit"}, svc.Credentials)
				assert.Equal(t, "plain", svc.Inject.Credential)
				assert.Equal(t, []string{"audit"}, svc.Rules[0].Subrequest.Credentials)
				assert.Equal(t, "lookup", svc.Rules[1].Filters[0].ID)
				assert.True(t, cfg.Credentials["audit"].Elevated())
				assert.False(t, cfg.Credentials["plain"].Elevated())
				assert.False(t, cfg.Credentials["sign"].Elevated())
			},
		})
	})

	// Credential checks.
	t.Run("allow is required", func(t *testing.T) {
		tester(t, testCase{yaml: "credentials:\n  x: {token: {source: provided}}\n", wantErr: `credential "x": allow is required`})
	})
	t.Run("allow may not be empty", func(t *testing.T) {
		tester(t, testCase{yaml: "credentials:\n  x: {allow: [], token: {source: provided}}\n", wantErr: `credential "x": allow is required`})
	})
	t.Run("allow rejects an unknown kind", func(t *testing.T) {
		tester(t, testCase{yaml: "credentials:\n  x: {allow: [filter], token: {source: provided}}\n", wantErr: `credential "x": unknown allow kind "filter"`})
	})
	t.Run("allow internal stands alone", func(t *testing.T) {
		tester(t, testCase{yaml: "credentials:\n  x: {allow: [internal, agent], token: {source: provided}}\n", wantErr: `credential "x": allow internal may not be combined`})
	})
	t.Run("internal: true is removed", func(t *testing.T) {
		tester(t, testCase{yaml: "credentials:\n  x: {internal: true, allow: [internal], token: {source: provided}}\n", wantErr: `credential "x": internal is removed; use allow: [internal]`})
	})
	t.Run("export_env requires agent", func(t *testing.T) {
		tester(t, testCase{yaml: "credentials:\n  x: {allow: [subrequest], export_env: [X], token: {source: provided}}\n", wantErr: `credential "x": export_env requires allow agent`})
	})

	// Service checks.
	t.Run("a service's singular credential is removed", func(t *testing.T) {
		tester(t, testCase{yaml: service("        credential: plain\n"), wantErr: `http "api": credential is removed; use credentials and inject.credential`})
	})
	t.Run("credentials must exist", func(t *testing.T) {
		tester(t, testCase{yaml: service("        credentials: [nope]\n"), wantErr: `http "api": unknown credential "nope"`})
	})
	t.Run("credentials may not list an internal credential", func(t *testing.T) {
		tester(t, testCase{yaml: service("        credentials: [sign]\n"), wantErr: `http "api": credential "sign" is internal and is never sent`})
	})
	t.Run("inject requires inject.credential", func(t *testing.T) {
		tester(t, testCase{yaml: service("        credentials: [plain]\n        inject: {bearer: true}\n"), wantErr: `http "api": inject requires inject.credential`})
	})
	t.Run("inject.credential must be in credentials", func(t *testing.T) {
		tester(t, testCase{yaml: service("        credentials: [plain]\n        inject: {credential: agent-only, bearer: true}\n"), wantErr: `inject.credential "agent-only" is not in credentials`})
	})
	t.Run("inject.credential may not be elevated", func(t *testing.T) {
		tester(t, testCase{yaml: service("        credentials: [audit]\n        inject: {credential: audit, bearer: true}\n"), wantErr: `inject.credential "audit" is elevated`})
	})
	t.Run("inject.git may not set credential", func(t *testing.T) {
		tester(t, testCase{
			yaml:    service("        credentials: [plain]\n        inject: {credential: plain, bearer: true, git: {credential: plain, basic: {}}}\n"),
			wantErr: `inject.git may not set credential, it uses inject.credential`,
		})
	})
	t.Run("lookup_credential must be in credentials", func(t *testing.T) {
		tester(t, testCase{yaml: service("        credentials: [plain]\n        lookup_credential: agent-only\n"), wantErr: `lookup_credential "agent-only" is not in credentials`})
	})
	t.Run("lookup_credential must allow agent", func(t *testing.T) {
		tester(t, testCase{yaml: service("        credentials: [audit]\n        lookup_credential: audit\n"), wantErr: `lookup_credential "audit" must allow agent`})
	})
	t.Run("a gitlab_project path lookup needs lookup_credential", func(t *testing.T) {
		tester(t, testCase{
			yaml:    service("        credentials: [plain]\n        rules:\n          - action: allow\n            gitlab_project: group/proj\n"),
			wantErr: `rules[0]: gitlab_project path lookups need lookup_credential`,
		})
	})
	t.Run("a gitlab_project with an id needs no lookup", func(t *testing.T) {
		tester(t, testCase{yaml: service("        rules:\n          - action: allow\n            gitlab_project: {path: group/proj, id: 7}\n")})
	})
	t.Run("an ssh service's credential must allow agent", func(t *testing.T) {
		tester(t, testCase{
			yaml:    allowCreds + "profiles:\n  p:\n    ssh:\n      - name: gh\n        hosts: [github.com]\n        credential: audit\n",
			wantErr: `ssh "gh": credential "audit" must allow agent`,
		})
	})

	// Subrequest rule checks.
	rule := func(sub string) string {
		return service("        credentials: [plain, audit, agent-only]\n        rules:\n          - action: allow\n            path: /x\n" + sub +
			"          - action: allow\n            path: /y\n            filters: [{path: f.ts, id: f}]\n")
	}
	t.Run("a subrequest block needs filters or credentials", func(t *testing.T) {
		tester(t, testCase{yaml: rule("            subrequest: {}\n"), wantErr: `rules[0]: subrequest needs filters or credentials`})
	})
	t.Run("subrequest.filters may not be empty", func(t *testing.T) {
		tester(t, testCase{yaml: rule("            subrequest: {filters: []}\n"), wantErr: `rules[0]: subrequest.filters is empty`})
	})
	t.Run("subrequest.credentials may not be empty", func(t *testing.T) {
		tester(t, testCase{yaml: rule("            subrequest: {credentials: []}\n"), wantErr: `rules[0]: subrequest.credentials is empty`})
	})
	t.Run("subrequest.credentials must be in the service's credentials", func(t *testing.T) {
		tester(t, testCase{yaml: rule("            subrequest: {credentials: [sign]}\n"), wantErr: `subrequest.credentials "sign" is not in credentials`})
	})
	t.Run("subrequest.credentials must be elevated", func(t *testing.T) {
		tester(t, testCase{yaml: rule("            subrequest: {credentials: [plain]}\n"), wantErr: `subrequest.credentials "plain" must be elevated`})
	})
	t.Run("subrequest.filters must name a placement id", func(t *testing.T) {
		tester(t, testCase{yaml: rule("            subrequest: {filters: [nope]}\n"), wantErr: `subrequest.filters "nope" is not the id of any filter`})
	})
	t.Run("a filter id is unique across the policy", func(t *testing.T) {
		tester(t, testCase{
			yaml: allowCreds + `
profiles:
  a:
    filters: [{path: f.ts, id: dup}]
  b:
    http:
      - name: api
        hosts: [api.example.com]
        rules:
          - action: allow
            filters: [{path: g.ts, id: dup}]
`,
			wantErr: `filter id "dup" is already used by profile "a" filters[0]`,
		})
	})
	t.Run("a parent's placement copied by extends keeps one id", func(t *testing.T) {
		tester(t, testCase{yaml: allowCreds + `
profiles:
  base:
    filters: [{path: f.ts, id: once}]
  child:
    extends: base
`})
	})
	t.Run("a subrequest block is not valid on an ssh rule", func(t *testing.T) {
		tester(t, testCase{
			yaml:    allowCreds + "profiles:\n  p:\n    ssh:\n      - name: gh\n        hosts: [github.com]\n        credential: plain\n        rules:\n          - action: allow\n            subrequest: {credentials: [audit]}\n",
			wantErr: `ssh "gh": rules[0]: subrequest is only valid on http rules`,
		})
	})
	t.Run("CheckSubrequestCredential", func(t *testing.T) {
		cfg, err := Parse([]byte(allowCreds), "/tmp/cfg/config.yaml")
		require.NoError(t, err)
		require.NoError(t, cfg.CheckSubrequestCredential("plain"))
		require.NoError(t, cfg.CheckSubrequestCredential("audit"))
		require.ErrorContains(t, cfg.CheckSubrequestCredential("agent-only"), `credential "agent-only" does not allow subrequest`)
		require.ErrorContains(t, cfg.CheckSubrequestCredential("sign"), `credential "sign" does not allow subrequest`)
		require.ErrorContains(t, cfg.CheckSubrequestCredential("nope"), `no credential named "nope"`)
	})
}
