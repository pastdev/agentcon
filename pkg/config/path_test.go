package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandHomePath(t *testing.T) {
	home := "/home/me"
	got := expandHomePath("~/.cursor", home)
	want := filepath.Join(home, ".cursor")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	got = expandHomePath("~", home)
	if got != filepath.Clean(home) {
		t.Fatalf("tilde %q", got)
	}
	got = expandHomePath("/abs", home)
	if got != "/abs" {
		t.Fatalf("abs %q", got)
	}
}

func TestResolveMountSource(t *testing.T) {
	home := t.TempDir()
	got := resolveMountSource(".config/cursor", home)
	want := filepath.Join(home, ".config", "cursor")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveConfigDirLastOverlayWins(t *testing.T) {
	home := t.TempDir()
	first := t.TempDir()
	second := t.TempDir()
	err := os.MkdirAll(filepath.Join(first, "image"), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	err = os.MkdirAll(filepath.Join(second, "image"), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolveConfigDir("image", home, []string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(second, "image")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
