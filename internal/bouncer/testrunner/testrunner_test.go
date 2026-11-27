package testrunner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSpec writes spec beside copies of the testdata filter and policy,
// and returns its path.
func writeSpec(t *testing.T, spec string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"counter.ts", "claims.ts", "lookup.ts", "policy.yaml"} {
		data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // fixed testdata name
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(dir, name), data, 0o600) //nolint:gosec // test fixture under TempDir
		require.NoError(t, err)
	}
	path := filepath.Join(dir, "spec.test.yaml")
	err := os.WriteFile(path, []byte(spec), 0o600)
	require.NoError(t, err)
	return path
}

func TestRunFileFormat(t *testing.T) {
	type testCase struct {
		spec    string
		want    []Result
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		path := writeSpec(t, tc.spec)
		results, err := RunFile(path, Options{Policy: filepath.Join(filepath.Dir(path), "policy.yaml")})
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		require.Len(t, results, len(tc.want))
		for i, want := range tc.want {
			got := results[i]
			assert.Equal(t, want.Name, got.Name)
			assert.Equal(t, want.Passed, got.Passed, got.Message)
			assert.Equal(t, want.Step, got.Step)
			assert.Equal(t, want.StepName, got.StepName)
			assert.Contains(t, got.Message, want.Message)
			assert.Contains(t, got.FilterLog, want.FilterLog)
		}
	}

	t.Run("cases do not share state", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: counter.ts
cases:
  - name: first
    steps:
      - request: {url: "https://example.com/"}
        expect: allow
  - name: second
    steps:
      - request: {url: "https://example.com/"}
        expect: allow
`,
			want: []Result{{Name: "first", Passed: true}, {Name: "second", Passed: true}},
		})
	})
	t.Run("steps share state", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: counter.ts
cases:
  - name: second request is over
    steps:
      - request: {url: "https://example.com/"}
        expect: allow
      - request: {url: "https://example.com/"}
        expect: deny
        expect_reason: over 1
`,
			want: []Result{{Name: "second request is over", Passed: true}},
		})
	})
	t.Run("case filter_config replaces the file's", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: counter.ts
filter_config: {max: 5}
cases:
  - name: replaced
    filter_config: {max: 0}
    steps:
      - request: {url: "https://example.com/"}
        expect: deny
        expect_reason: over 0
`,
			want: []Result{{Name: "replaced", Passed: true}},
		})
	})
	t.Run("empty case filter_config clears the file's", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: counter.ts
filter_config: {max: 5}
cases:
  - name: defaults
    filter_config: {}
    steps:
      - request: {url: "https://example.com/"}
        expect: allow
      - request: {url: "https://example.com/"}
        expect: deny
        expect_reason: over 1
`,
			want: []Result{{Name: "defaults", Passed: true}},
		})
	})
	t.Run("failing step reports its index and log", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: counter.ts
cases:
  - steps:
      - request: {url: "https://example.com/"}
        expect: allow
      - request: {url: "https://example.com/"}
        expect: allow
`,
			want: []Result{{
				Name:      "case 1",
				Step:      2,
				StepName:  "2",
				Message:   "expected allow, got deny",
				FilterLog: "request 2",
			}},
		})
	})
	t.Run("failing step reports its name", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: counter.ts
cases:
  - name: named
    steps:
      - name: only request
        request: {url: "https://example.com/"}
        expect: deny
`,
			want: []Result{{
				Name:     "named",
				Step:     1,
				StepName: "only request",
				Message:  "expected deny, got allow",
			}},
		})
	})
	t.Run("case profile replaces the file's", func(t *testing.T) {
		tester(t, testCase{
			spec: `
profile: open
cases:
  - name: file profile
    steps:
      - request: {url: "https://example.com/"}
        expect: allow
  - name: case profile
    profile: closed
    steps:
      - request: {url: "https://example.com/"}
        expect: deny
`,
			want: []Result{{Name: "file profile", Passed: true}, {Name: "case profile", Passed: true}},
		})
	})
	t.Run("leftover paths go without the credential", func(t *testing.T) {
		tester(t, testCase{
			spec: `
profile: tunnel
cases:
  - name: rule path carries it, leftover does not
    steps:
      - request: {url: "https://api.example.com/in"}
        expect: allow
        expect_credential: true
      - request: {url: "https://api.example.com/other"}
        expect: allow
        expect_credential: false
`,
			want: []Result{{Name: "rule path carries it, leftover does not", Passed: true}},
		})
	})
	t.Run("credential mismatch fails the step", func(t *testing.T) {
		tester(t, testCase{
			spec: `
profile: tunnel
cases:
  - name: leftover
    steps:
      - request: {url: "https://api.example.com/other"}
        expect_credential: true
`,
			want: []Result{{Name: "leftover", Step: 1, StepName: "1", Message: "expected credential=true, got false"}},
		})
	})
	t.Run("policy spec without a profile is an error", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - name: nameless profile
    steps:
      - request: {url: "https://example.com/"}
        expect: allow
`,
			wantErr: "no profile",
		})
	})
	t.Run("case without steps is an error", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: counter.ts
cases:
  - name: empty
`,
			wantErr: "case has no steps",
		})
	})
	t.Run("config key fails to load", func(t *testing.T) {
		tester(t, testCase{
			spec: `
config: policy.yaml
profile: open
cases: []
`,
			wantErr: "field config not found",
		})
	})
	t.Run("old format fails to load", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: counter.ts
cases:
  - name: request on the case
    request: {url: "https://example.com/"}
    expect: allow
`,
			wantErr: "field request not found",
		})
	})
}

func TestRunFileOptions(t *testing.T) {
	type testCase struct {
		spec     string // path under the tests directory
		body     string
		noPolicy bool
		wantErr  string
	}
	const filterSpec = `
cases:
  - name: counter is the filter
    steps:
      - request: {url: "https://example.com/"}
        expect: allow
      - request: {url: "https://example.com/"}
        expect: deny
        expect_reason: over 1
`
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		root := t.TempDir()
		tests := filepath.Join(root, "tests")
		filter, err := os.ReadFile(filepath.Join("testdata", "counter.ts"))
		require.NoError(t, err)
		files := map[string][]byte{
			filepath.Join(root, "ts", "filters", "counter.ts"): filter,
			filepath.Join(tests, tc.spec):                      []byte(tc.body),
		}
		for path, data := range files {
			err := os.MkdirAll(filepath.Dir(path), 0o700)
			require.NoError(t, err)
			err = os.WriteFile(path, data, 0o600)
			require.NoError(t, err)
		}
		opts := Options{TestsDir: tests, Policy: filepath.Join("testdata", "policy.yaml")}
		if tc.noPolicy {
			opts.Policy = ""
		}
		results, err := RunFile(filepath.Join(tests, tc.spec), opts)
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		require.NotEmpty(t, results)
		for _, r := range results {
			assert.True(t, r.Passed, "%s: step %s: %s", r.Name, r.StepName, r.Message)
		}
	}

	t.Run("convention finds the filter for .test.yaml", func(t *testing.T) {
		tester(t, testCase{spec: "ts/filters/counter.test.yaml", body: filterSpec})
	})
	t.Run("convention finds the filter for .test.yml", func(t *testing.T) {
		tester(t, testCase{spec: "ts/filters/counter.test.yml", body: filterSpec})
	})
	t.Run("filter overrides the convention", func(t *testing.T) {
		tester(t, testCase{
			spec: "ts/filters/other.test.yaml",
			body: "filter: ../../../ts/filters/counter.ts\n" + filterSpec,
		})
	})
	t.Run("without a conventional filter the spec tests the policy", func(t *testing.T) {
		tester(t, testCase{
			spec: "bouncers.test.yaml",
			body: `
profile: closed
cases:
  - name: closed denies
    steps:
      - request: {url: "https://example.com/"}
        expect: deny
`,
		})
	})
	t.Run("policy spec without a policy is an error", func(t *testing.T) {
		tester(t, testCase{
			spec:     "bouncers.test.yaml",
			body:     "profile: open\ncases: []\n",
			noPolicy: true,
			wantErr:  "spec names no filter and no policy is given",
		})
	})
}

func TestRunFileClaims(t *testing.T) {
	type testCase struct {
		spec    string
		want    []Result
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		path := writeSpec(t, "filter: claims.ts\n"+tc.spec)
		results, err := RunFile(path, Options{})
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		require.Len(t, results, len(tc.want))
		for i, want := range tc.want {
			got := results[i]
			assert.Equal(t, want.Passed, got.Passed, got.Message)
			assert.Equal(t, want.Step, got.Step)
			assert.Contains(t, got.Message, want.Message)
		}
	}

	t.Run("seeded claim allows without a request", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - claims: {repository: [g/a]}
    steps:
      - request: {url: "https://example.com/?repo=g/a"}
        expect: allow
        expect_claim_requested: false
        expect_claims: {repository: [g/a]}
`,
			want: []Result{{Passed: true}},
		})
	})
	t.Run("session answer adds the claim for later steps", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - claims: {repository: [g/a]}
    steps:
      - request: {url: "https://example.com/?repo=g/b"}
        claim_answer: session
        expect: allow
        expect_claim_requested: {type: repository, value: g/b}
        expect_claims: {repository: [g/b, g/a]}
      - request: {url: "https://example.com/?repo=g/b"}
        expect: allow
        expect_claim_requested: false
`,
			want: []Result{{Passed: true}},
		})
	})
	t.Run("once allows and adds nothing", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - steps:
      - request: {url: "https://example.com/?repo=g/b"}
        claim_answer: once
        expect: allow
        expect_claim_requested: true
        expect_claims: {}
      - request: {url: "https://example.com/?repo=g/b"}
        expect: deny
        expect_claim_requested: true
`,
			want: []Result{{Passed: true}},
		})
	})
	t.Run("deny and timeout resolve false", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - steps:
      - request: {url: "https://example.com/?repo=g/b"}
        claim_answer: deny
        expect: deny
        expect_reason: out of scope
      - request: {url: "https://example.com/?repo=g/b"}
        claim_answer: timeout
        expect: deny
        expect_claim_requested: true
        expect_claims: {}
`,
			want: []Result{{Passed: true}},
		})
	})
	t.Run("an invalid claim throws and fails closed", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - steps:
      - request: {url: "https://example.com/?repo="}
        claim_answer: session
        expect: deny
        expect_reason: claim value is empty
        expect_claim_requested: false
`,
			want: []Result{{Passed: true}},
		})
	})
	t.Run("expect_claims mismatch fails the step", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - claims: {repository: [g/a]}
    steps:
      - request: {url: "https://example.com/?repo=g/a"}
        expect_claims: {}
`,
			want: []Result{{Passed: false, Step: 1, Message: "expected claims none, got repository=g/a"}},
		})
	})
	t.Run("expect_claim_requested names the wrong claim", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - steps:
      - request: {url: "https://example.com/?repo=g/b"}
        expect_claim_requested: {type: repository, value: g/c}
`,
			want: []Result{{Passed: false, Step: 1, Message: "expected claim repository=g/c requested, got repository=g/b"}},
		})
	})
	t.Run("invalid seed claims fail to load", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - claims: {repository: [g/a, "bad\tvalue"]}
    steps:
      - request: {url: "https://example.com/?repo=g/a"}
`,
			wantErr: "claims: claim repository value 2: claim value contains a control character",
		})
	})
	t.Run("unknown claim_answer fails to load", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - steps:
      - request: {url: "https://example.com/?repo=g/a"}
        claim_answer: forever
`,
			wantErr: `claim_answer "forever" must be session, once, deny, or timeout`,
		})
	})
	t.Run("invalid expect_claims fails to load", func(t *testing.T) {
		tester(t, testCase{
			spec: `
cases:
  - steps:
      - request: {url: "https://example.com/?repo=g/a"}
        expect_claims: {Repo: [x]}
`,
			wantErr: "expect_claims: claim type",
		})
	})
}

func TestRunFileSigner(t *testing.T) {
	type testCase struct {
		steps      string
		wantPassed bool
		wantMsg    string
		wantErr    string
	}
	const policy = `
default_profile: p
credentials:
  sign:
    internal: true
    private_key: {source: provided}
profiles:
  p:
    http:
      - name: signing
        hosts: [signer.bouncer.internal]
        signer:
          openpgp:
            keys: [{id: C26E02CE599B53FF, credential: sign}]
`
	const commit = "tree 9bedf67800b2923982bdf60c89c57ce6986c4c5b\n" +
		"author A <a@example.com> 1764000000 +0000\n" +
		"committer A <a@example.com> 1764000000 +0000\n\nmsg\n"
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		dir := t.TempDir()
		policyPath := filepath.Join(dir, "policy.yaml")
		require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o600))
		specPath := filepath.Join(dir, "signer.test.yaml")
		require.NoError(t, os.WriteFile(specPath, []byte("profile: p\ncases:\n  - name: c\n    steps:\n"+tc.steps), 0o600))
		results, err := RunFile(specPath, Options{Policy: policyPath})
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, tc.wantPassed, results[0].Passed, results[0].Message)
		assert.Contains(t, results[0].Message, tc.wantMsg)
	}
	step := func(url, body, expect string, extra ...string) string {
		// A JSON string is a YAML double-quoted scalar.
		b, err := json.Marshal(body)
		require.NoError(t, err)
		s := "      - request:\n          method: POST\n          url: \"" + url + "\"\n          body: " + strings.TrimSpace(string(b)) + "\n        expect: " + expect + "\n"
		for _, e := range extra {
			s += "        " + e + "\n"
		}
		return s
	}
	const signURL = "https://signer.bouncer.internal/openpgp/sign?key=c26e02ce599b53ff"

	t.Run("an allowed commit gets the test signature", func(t *testing.T) {
		tester(t, testCase{steps: step(signURL, commit, "allow", "expect_body_contains: [bouncer-test-signature]"), wantPassed: true})
	})
	t.Run("arbitrary bytes are refused", func(t *testing.T) {
		tester(t, testCase{steps: step(signURL, "hello", "deny", "expect_reason: not an unsigned git commit or tag"), wantPassed: true})
	})
	t.Run("an unknown key is refused", func(t *testing.T) {
		tester(t, testCase{steps: step("https://signer.bouncer.internal/openpgp/sign?key=1111111111111111", commit, "deny", "expect_reason: unknown signing key"), wantPassed: true})
	})
	t.Run("a wrong expectation fails", func(t *testing.T) {
		tester(t, testCase{steps: step(signURL, "hello", "allow"), wantMsg: "expected allow, got deny"})
	})
	t.Run("upstream on a signer step is an error", func(t *testing.T) {
		tester(t, testCase{steps: step(signURL, commit, "allow", "upstream: {status: 200}"), wantMsg: "upstream is not allowed on signer service signing"})
	})
	t.Run("expect_credential on a signer step is an error", func(t *testing.T) {
		tester(t, testCase{steps: step(signURL, commit, "allow", "expect_credential: true"), wantMsg: "expect_credential is not allowed"})
	})
}

func TestRunFileSubrequests(t *testing.T) {
	type testCase struct {
		spec    string
		want    []Result
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		path := writeSpec(t, tc.spec)
		results, err := RunFile(path, Options{Policy: filepath.Join(filepath.Dir(path), "policy.yaml")})
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		require.Len(t, results, len(tc.want))
		for i, want := range tc.want {
			got := results[i]
			assert.Equal(t, want.Passed, got.Passed, got.Message)
			assert.Equal(t, want.Step, got.Step)
			assert.Contains(t, got.Message, want.Message)
		}
	}

	t.Run("a filter spec answers from fixtures", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: lookup.ts
cases:
  - name: allowed by the lookup
    steps:
      - request: {url: "https://example.com/?lookup=https://api.example.com/rules/main"}
        subrequests:
          - url: https://api.example.com:443/rules/main
            expect_header: {Accept: application/json}
        expect: allow
  - name: denied by the lookup status
    steps:
      - request: {url: "https://example.com/?lookup=https://api.example.com/rules/main"}
        subrequests:
          - {url: "https://api.example.com/rules/main", status: 404}
        expect: deny
        expect_reason: lookup answered 404
  - name: a fixture error rejects
    steps:
      - request: {url: "https://example.com/?lookup=https://api.example.com/rules/main"}
        subrequests:
          - {url: "https://api.example.com/rules/main", error: connection refused}
        expect: deny
        expect_reason: "lookup failed: subrequest: connection refused"
  - name: redirects chain through fixtures
    steps:
      - request: {url: "https://example.com/?lookup=https://api.example.com/old"}
        subrequests:
          - {url: "https://api.example.com/old", status: 301, headers: {Location: /new}}
          - {url: "https://api.example.com/new"}
        expect: allow
`,
			want: []Result{{Passed: true}, {Passed: true}, {Passed: true}, {Passed: true}},
		})
	})
	t.Run("fixtures are strict", func(t *testing.T) {
		tester(t, testCase{
			spec: `
filter: lookup.ts
cases:
  - name: unexpected
    steps:
      - request: {url: "https://example.com/?lookup=https://api.example.com/rules/main"}
        expect: deny
  - name: unused
    steps:
      - request: {url: "https://example.com/"}
        subrequests:
          - url: https://api.example.com/rules/main
        expect: allow
  - name: header mismatch
    steps:
      - request: {url: "https://example.com/?lookup=https://api.example.com/rules/main"}
        subrequests:
          - url: https://api.example.com/rules/main
            expect_header: {Accept: text/plain}
`,
			want: []Result{
				{Step: 1, Message: "unexpected subrequest GET https://api.example.com/rules/main"},
				{Step: 1, Message: "subrequest fixture GET https://api.example.com/rules/main was not used"},
				{Step: 1, Message: `expected header Accept="text/plain", got "application/json"`},
			},
		})
	})
	t.Run("a bouncer spec runs subrequests through the profile", func(t *testing.T) {
		tester(t, testCase{
			spec: `
profile: lookup
cases:
  - name: the lookup carries the credential
    steps:
      - request: {url: "https://api.example.com/in?lookup=https://api.example.com/rules/main"}
        subrequests:
          - url: https://api.example.com/rules/main
            expect_credential: true
        expect: allow
        expect_credential: true
  - name: the rules deny a lookup
    steps:
      - request: {url: "https://api.example.com/in?lookup=https://api.example.com/secret/x"}
        expect: deny
        expect_reason: "lookup denied: denied by rules:api rules[2]"
  - name: a path no rule matches goes through without the credential
    steps:
      - request: {url: "https://api.example.com/in?lookup=https://api.example.com/other"}
        subrequests:
          - url: https://api.example.com/other
            expect_credential: false
        expect: allow
  - name: a tunneled lookup carries no credential
    steps:
      - request: {url: "https://api.example.com/in?lookup=https://elsewhere.example.com/x"}
        subrequests:
          - url: https://elsewhere.example.com/x
            expect_credential: false
        expect: allow
  - name: credential mismatch fails
    steps:
      - request: {url: "https://api.example.com/in?lookup=https://elsewhere.example.com/x"}
        subrequests:
          - url: https://elsewhere.example.com/x
            expect_credential: true
`,
			want: []Result{{Passed: true}, {Passed: true}, {Passed: true}, {Passed: true},
				{Step: 1, Message: "expected credential=true, got false"}},
		})
	})
	t.Run("bad fixtures fail the spec", func(t *testing.T) {
		for spec, want := range map[string]string{
			`[{url: "/relative"}]`:                             "must be an absolute http or https url",
			`[{url: "https://a/x"}, {url: "https://a:443/x"}]`: "duplicate fixture GET https://a/x",
			`[{url: "https://a/x", error: boom, status: 500}]`: "error excludes status, headers, and body",
			`[{url: "https://a/x", expect_credential: true}]`:  "expect_credential needs a bouncer spec",
		} {
			tester(t, testCase{
				spec:    "filter: lookup.ts\ncases:\n  - steps:\n      - request: {url: \"https://example.com/\"}\n        subrequests: " + spec + "\n",
				wantErr: want,
			})
		}
	})
}
