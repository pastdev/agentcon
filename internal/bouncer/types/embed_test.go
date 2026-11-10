package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBouncerDTS(t *testing.T) {
	type testCase struct{}
	tester := func(t *testing.T, _ testCase) {
		t.Helper()
		assert.Contains(t, string(BouncerDTS), "defineFilter")
	}

	t.Run("embeds defineFilter in the typescript api", func(t *testing.T) {
		tester(t, testCase{})
	})
}
