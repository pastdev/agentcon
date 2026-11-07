package testrunner

import "testing"

// TestRunFile runs every spec under examples/, so `go test ./...` keeps
// the shipped filters and config honest.
func TestRunFile(t *testing.T) {
	type testCase struct {
		roots []string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		files, err := Find(tc.roots)
		if err != nil {
			t.Fatal(err)
		}
		if len(files) < 10 {
			t.Fatalf("found only %d spec files", len(files))
		}
		for _, f := range files {
			results, err := RunFile(f)
			if err != nil {
				t.Errorf("%s: %v", f, err)
				continue
			}
			for _, r := range results {
				if !r.Passed {
					t.Errorf("%s: %s: %s", f, r.Name, r.Message)
				}
			}
		}
	}

	t.Run("runs every spec under examples", func(t *testing.T) {
		tester(t, testCase{roots: []string{"../examples"}})
	})
}
