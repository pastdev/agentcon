package bouncer

import (
	"bytes"
	"errors"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/testrunner"
	"github.com/pastdev/agentcon/pkg/bouncertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteTAP(t *testing.T) {
	type testCase struct {
		report bouncertest.Report
		want   string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		var b bytes.Buffer
		err := writeTAP(&b, tc.report)
		require.NoError(t, err)
		assert.Equal(t, tc.want, b.String())
	}

	t.Run("passing specs", func(t *testing.T) {
		tester(t, testCase{
			report: bouncertest.Report{Specs: []bouncertest.SpecReport{
				{Path: "tests/bouncers.test.yaml", Results: []testrunner.Result{
					{Name: "tag push asks", Passed: true},
					{Name: "merge asks", Passed: true},
				}},
			}},
			want: `TAP version 14
# Subtest: tests/bouncers.test.yaml
    1..2
    ok 1 - tag push asks
    ok 2 - merge asks
ok 1 - tests/bouncers.test.yaml
1..1
`,
		})
	})
	t.Run("failing step with a filter log", func(t *testing.T) {
		tester(t, testCase{
			report: bouncertest.Report{Specs: []bouncertest.SpecReport{
				{Path: "tests/bouncers.test.yaml", Results: []testrunner.Result{
					{Name: "tag push asks", Passed: true},
					{
						Name:      "leftover paths",
						Step:      2,
						StepName:  "repos endpoint",
						Message:   "expected deny, got allow",
						FilterLog: "INF first\nINF second",
					},
				}},
			}},
			want: `TAP version 14
# Subtest: tests/bouncers.test.yaml
    1..2
    ok 1 - tag push asks
    not ok 2 - leftover paths
      ---
      step: 2
      step_name: repos endpoint
      message: expected deny, got allow
      filter_log: |-
        INF first
        INF second
      ...
not ok 1 - tests/bouncers.test.yaml
1..1
`,
		})
	})
	t.Run("spec that fails to load", func(t *testing.T) {
		tester(t, testCase{
			report: bouncertest.Report{Specs: []bouncertest.SpecReport{
				{Path: "tests/a.test.yaml", Err: errors.New(`tests/a.test.yaml: field request not found`)},
				{Path: "tests/b.test.yaml", Results: []testrunner.Result{{Name: "allowed", Passed: true}}},
			}},
			want: `TAP version 14
not ok 1 - tests/a.test.yaml
  ---
  message: 'tests/a.test.yaml: field request not found'
  ...
# Subtest: tests/b.test.yaml
    1..1
    ok 1 - allowed
ok 2 - tests/b.test.yaml
1..2
`,
		})
	})
}
