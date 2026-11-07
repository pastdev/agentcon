package version

import (
	"testing"
)

func TestVersion(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		if Version() == "" {
			t.Fatal("expected version")
		}
	}

	t.Run("returns a non-empty value", func(t *testing.T) {
		tester(t)
	})
}
