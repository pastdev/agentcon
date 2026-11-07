package types

import (
	"bytes"
	"testing"
)

func TestBouncerDTS(t *testing.T) {
	type testCase struct{}
	tester := func(t *testing.T, _ testCase) {
		t.Helper()
		if !bytes.Contains(BouncerDTS, []byte("defineFilter")) {
			t.Fatal("bouncer.d.ts missing defineFilter")
		}
	}

	t.Run("embeds defineFilter in the typescript api", func(t *testing.T) {
		tester(t, testCase{})
	})
}
