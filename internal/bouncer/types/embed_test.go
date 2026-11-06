package types

import (
	"bytes"
	"testing"
)

func TestBouncerDTS(t *testing.T) {
	if !bytes.Contains(BouncerDTS, []byte("defineFilter")) {
		t.Fatal("bouncer.d.ts missing defineFilter")
	}
}
