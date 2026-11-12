package testrunner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunFile runs every spec under examples/, so `go test ./...` keeps
// the shipped filters and config honest.
func TestRunFile(t *testing.T) {
	type testCase struct {
		roots []string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		files, err := Find(tc.roots)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(files), 10, "spec files")
		for _, f := range files {
			t.Run(f, func(t *testing.T) {
				results, err := RunFile(f, Options{})
				require.NoError(t, err)
				for _, r := range results {
					assert.True(t, r.Passed, "%s: step %s: %s\n%s", r.Name, r.StepName, r.Message, r.FilterLog)
				}
			})
		}
	}

	t.Run("runs every spec under examples", func(t *testing.T) {
		tester(t, testCase{roots: []string{"../examples"}})
	})
}
