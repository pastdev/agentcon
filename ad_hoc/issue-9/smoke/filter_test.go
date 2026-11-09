//go:build issue9

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/jsfilter"
)

func TestBundleSmokeFilter(t *testing.T) {
	dir, err := smokeDir()
	if err != nil {
		t.Fatal(err)
	}
	code, err := jsfilter.Bundle(filepath.Join(dir, "ts", "filters", "tag.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(code, "tagged:") {
		t.Fatalf("bundle missing smoke-tag output: %s", code[:min(len(code), 500)])
	}
	if !strings.Contains(code, filterDenied) {
		t.Fatal("bundle missing filter deny")
	}
}
