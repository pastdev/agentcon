package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testContextOther   = "other"
	testContextPastdev = "pastdev"
	testImageOther     = "other:latest"
	testImagePastdev   = "pastdev:latest"
)

func TestNewRunRequestUsesDefaultContext(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "github.com", "pastdev", "agentcon")
	err := os.MkdirAll(cwd, 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := Config{
		DefaultContext: testContextPastdev,
		Contexts: map[string]contextSpec{
			testContextOther: {Image: testImageOther, Root: t.TempDir()},
			testContextPastdev: {
				Image: testImagePastdev,
				Root:  root,
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
	if req.Root != root {
		t.Fatalf("got root %q, want %q", req.Root, root)
	}
	if req.Cwd != cwd {
		t.Fatalf("got cwd %q, want %q", req.Cwd, cwd)
	}
}

func TestNewRunRequestAllowsCwdAtRoot(t *testing.T) {
	root := t.TempDir()
	cfg := Config{
		DefaultContext: testContextPastdev,
		Contexts: map[string]contextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
		},
	}

	req, err := NewRunRequest(&cfg, "", root)
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Root != root {
		t.Fatalf("got root %q, want %q", req.Root, root)
	}
	if req.Cwd != root {
		t.Fatalf("got cwd %q, want %q", req.Cwd, root)
	}
}

func TestNewRunRequestRequiresDefaultContext(t *testing.T) {
	cfg := Config{
		Contexts: map[string]contextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: t.TempDir()},
		},
	}

	_, err := NewRunRequest(&cfg, "", t.TempDir())
	if err == nil {
		t.Fatal("expected missing default")
	}
	if !strings.Contains(err.Error(), "default_context is not set") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunRequestRejectsCwdOutsideRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	cfg := Config{
		DefaultContext: testContextPastdev,
		Contexts: map[string]contextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
		},
	}

	_, err := NewRunRequest(&cfg, "", other)
	if err == nil {
		t.Fatal("expected cwd outside root")
	}
	if !strings.Contains(err.Error(), "is not under context") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunRequestNamedRejectsCwdOutsideRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	cfg := Config{
		DefaultContext: testContextOther,
		Contexts: map[string]contextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
			testContextOther:   {Image: testImageOther, Root: other},
		},
	}

	_, err := NewRunRequest(&cfg, testContextPastdev, other)
	if err == nil {
		t.Fatal("expected cwd outside named root")
	}
	if !strings.Contains(err.Error(), "is not under context") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunRequestByName(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	err := os.MkdirAll(nested, 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := Config{
		DefaultContext: testContextOther,
		Contexts: map[string]contextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
			testContextOther:   {Image: testImageOther, Root: nested},
		},
	}

	req, err := NewRunRequest(&cfg, testContextPastdev, nested)
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Root != root {
		t.Fatalf("got root %q, want %q", req.Root, root)
	}
	if req.Cwd != nested {
		t.Fatalf("got cwd %q, want %q", req.Cwd, nested)
	}
}

func TestNewRunRequestUnknownName(t *testing.T) {
	root := t.TempDir()
	cfg := Config{
		DefaultContext: testContextPastdev,
		Contexts: map[string]contextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
		},
	}

	_, err := NewRunRequest(&cfg, "missing", root)
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
	root := filepath.Join(home, "git")
	cwd := filepath.Join(root, "proj")
	err := os.MkdirAll(cwd, 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := Config{
		DefaultContext: testContextPastdev,
		Contexts: map[string]contextSpec{
			testContextPastdev: {Image: "img:latest", Root: "~/git"},
		},
	}

	req, err := NewRunRequest(&cfg, testContextPastdev, cwd)
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	want, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if req.Root != want {
		t.Fatalf("got %q, want %q", req.Root, want)
	}
}
