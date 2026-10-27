package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testContextPastdev = "pastdev"
	testImagePastdev   = "pastdev:latest"
)

func TestNewRunRequestLongestPrefix(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "github.com", "pastdev")
	cwd := filepath.Join(nested, "agentcon")
	err := os.MkdirAll(cwd, 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := Config{
		Contexts: map[string]contextSpec{
			"wide": {Image: "wide:latest", Root: root},
			testContextPastdev: {
				Image: testImagePastdev,
				Root:  nested,
			},
		},
	}

	req, err := NewRunRequest(&cfg, "", cwd)
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Image != testImagePastdev {
		t.Fatalf("got image %q", req.Image)
	}
	if req.Root != nested {
		t.Fatalf("got root %q, want %q", req.Root, nested)
	}
	if req.Cwd != cwd {
		t.Fatalf("got cwd %q, want %q", req.Cwd, cwd)
	}
}

func TestNewRunRequestRejectsSiblingPrefix(t *testing.T) {
	root := t.TempDir()
	git := filepath.Join(root, "git")
	git2 := filepath.Join(root, "git2", "proj")
	err := os.MkdirAll(git, 0o700)
	if err != nil {
		t.Fatalf("mkdir git: %v", err)
	}
	err = os.MkdirAll(git2, 0o700)
	if err != nil {
		t.Fatalf("mkdir git2: %v", err)
	}

	cfg := Config{
		Contexts: map[string]contextSpec{
			"main": {Image: "main:latest", Root: git},
		},
	}

	_, err = NewRunRequest(&cfg, "", git2)
	if err == nil {
		t.Fatal("expected no match")
	}
	if !strings.Contains(err.Error(), "no context root contains") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunRequestTie(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "proj")
	err := os.MkdirAll(cwd, 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := Config{
		Contexts: map[string]contextSpec{
			"a": {Image: "a:latest", Root: root},
			"b": {Image: "b:latest", Root: root},
		},
	}

	_, err = NewRunRequest(&cfg, "", cwd)
	if err == nil {
		t.Fatal("expected tie")
	}
	if !strings.Contains(err.Error(), "multiple contexts match") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunRequestByName(t *testing.T) {
	root := t.TempDir()
	other := filepath.Join(root, "other")
	err := os.MkdirAll(other, 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := Config{
		Contexts: map[string]contextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
			"other":            {Image: "other:latest", Root: other},
		},
	}

	req, err := NewRunRequest(&cfg, testContextPastdev, other)
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Root != root {
		t.Fatalf("got root %q, want %q", req.Root, root)
	}
	if req.Cwd != other {
		t.Fatalf("got cwd %q, want %q", req.Cwd, other)
	}
}

func TestNewRunRequestUnknownName(t *testing.T) {
	cfg := Config{
		Contexts: map[string]contextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: "/tmp"},
		},
	}

	_, err := NewRunRequest(&cfg, "missing", "/tmp")
	if err == nil {
		t.Fatal("expected unknown context")
	}
	if !strings.Contains(err.Error(), `unknown context "missing"`) {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunRequestExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := Config{
		Contexts: map[string]contextSpec{
			"pastdev": {Image: "img:latest", Root: "~/git"},
		},
	}

	req, err := NewRunRequest(&cfg, "pastdev", "")
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	want, err := filepath.Abs(filepath.Join(home, "git"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if req.Root != want {
		t.Fatalf("got %q, want %q", req.Root, want)
	}
}
