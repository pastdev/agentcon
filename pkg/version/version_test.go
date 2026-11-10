package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		assert.NotEmpty(t, Version())
	}

	t.Run("returns a non-empty value", func(t *testing.T) {
		tester(t)
	})
}
