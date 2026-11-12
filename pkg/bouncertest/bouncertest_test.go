package bouncertest

import (
	"os"
	"path/filepath"
	"testing"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const policy = `
default_profile: open
profiles:
  open:
    filters:
      - ts/filters/counter.ts
    http:
      - name: example
        hosts: [example.com]
        default: allow
`

func TestRun(t *testing.T) {
	type testCase struct {
		specs      map[string]string // path under tests/ to spec body
		wantPaths  []string
		wantErrs   []bool
		wantFailed int
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		tests := filepath.Join(t.TempDir(), "tests")
		for name, body := range tc.specs {
			err := os.MkdirAll(filepath.Dir(filepath.Join(tests, name)), 0o700)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(tests, name), []byte(body), 0o600)
			require.NoError(t, err)
		}
		counter, err := filepath.Abs(filepath.Join("..", "..", "internal", "bouncer", "testrunner", "testdata", "counter.ts"))
		require.NoError(t, err)
		dir := t.TempDir()

		report, err := Run(Suite{
			Bouncer:    "example",
			PolicyYAML: []byte(policy),
			TSFiles:    map[string]string{"filters/counter.ts": counter},
			TestsDir:   tests,
		}, dir)
		require.NoError(t, err)

		assert.FileExists(t, filepath.Join(dir, bouncercfg.FileName))
		assert.FileExists(t, filepath.Join(dir, bouncercfg.TSDir, "filters", "counter.ts"))
		assert.Equal(t, "example", report.Bouncer)
		require.Len(t, report.Specs, len(tc.wantPaths))
		for i, spec := range report.Specs {
			assert.Equal(t, tc.wantPaths[i], spec.Path)
			assert.Equal(t, tc.wantErrs[i], spec.Err != nil, "spec error: %v", spec.Err)
		}
		assert.Equal(t, tc.wantFailed, report.Failed())
	}

	t.Run("runs every spec against the written policy", func(t *testing.T) {
		tester(t, testCase{
			specs: map[string]string{
				"bouncers.test.yaml": `
profile: open
cases:
  - name: second request is over the profile filter's limit
    steps:
      - request: {url: "https://example.com/"}
        expect: allow
      - request: {url: "https://example.com/"}
        expect: deny
`,
				"nested/fails.test.yaml": `
profile: open
cases:
  - name: wrong expectation
    steps:
      - request: {url: "https://example.com/"}
        expect: deny
`,
			},
			wantPaths:  []string{"tests/bouncers.test.yaml", "tests/nested/fails.test.yaml"},
			wantErrs:   []bool{false, false},
			wantFailed: 1,
		})
	})
	t.Run("records a spec that fails to load and runs the rest", func(t *testing.T) {
		tester(t, testCase{
			specs: map[string]string{
				"a.test.yaml": "cases: [\n",
				"b.test.yaml": `
profile: open
cases:
  - name: allowed
    steps:
      - request: {url: "https://example.com/"}
        expect: allow
`,
			},
			wantPaths:  []string{"tests/a.test.yaml", "tests/b.test.yaml"},
			wantErrs:   []bool{true, false},
			wantFailed: 1,
		})
	})
}
