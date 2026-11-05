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
	testBouncerListen  = "127.0.0.1:8228"
	testHostCursor     = "cursor.com"
	testHostCursorStar = "*.cursor.sh"
	testHostAnthropic  = "api.anthropic.com"
	testHostExtra      = "extra.example.com"
	testHarnessCursor  = "cursor"
	testHarnessClaude  = "claude"
	testProfileDefault = "default"
	testProfileLocked  = "locked-down"
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
		Contexts: map[string]ContextSpec{
			testContextOther: {Image: testImageOther, Root: t.TempDir()},
			testContextPastdev: {
				Image: testImagePastdev,
				Root:  root,
			},
		},
	}

	req, err := NewRunRequest(&cfg, "", cwd, t.TempDir(), "")
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
	if req.Harness != testHarnessCursor {
		t.Fatalf("got harness %q", req.Harness)
	}
}

func TestNewRunRequestAllowsCwdAtRoot(t *testing.T) {
	root := t.TempDir()
	cfg := Config{
		DefaultContext: testContextPastdev,
		Contexts: map[string]ContextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
		},
	}

	req, err := NewRunRequest(&cfg, "", root, t.TempDir(), "")
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
		Contexts: map[string]ContextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: t.TempDir()},
		},
	}

	_, err := NewRunRequest(&cfg, "", t.TempDir(), t.TempDir(), "")
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
		Contexts: map[string]ContextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
		},
	}

	_, err := NewRunRequest(&cfg, "", other, t.TempDir(), "")
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
		Contexts: map[string]ContextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
			testContextOther:   {Image: testImageOther, Root: other},
		},
	}

	_, err := NewRunRequest(&cfg, testContextPastdev, other, t.TempDir(), "")
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
		Contexts: map[string]ContextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
			testContextOther:   {Image: testImageOther, Root: nested},
		},
	}

	req, err := NewRunRequest(&cfg, testContextPastdev, nested, t.TempDir(), "")
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

func TestNewRunRequestHarnessOverride(t *testing.T) {
	root := t.TempDir()
	cfg := Config{
		DefaultContext: testContextPastdev,
		Contexts: map[string]ContextSpec{
			testContextPastdev: {
				Image:   testImagePastdev,
				Root:    root,
				Harness: testHarnessClaude,
			},
		},
	}
	req, err := NewRunRequest(&cfg, "", root, t.TempDir(), "")
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Harness != testHarnessClaude {
		t.Fatalf("got harness %q", req.Harness)
	}
	req, err = NewRunRequest(&cfg, "", root, t.TempDir(), testHarnessCursor)
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Harness != testHarnessCursor {
		t.Fatalf("got harness %q", req.Harness)
	}
}

func TestNewRunRequestUnknownName(t *testing.T) {
	root := t.TempDir()
	cfg := Config{
		DefaultContext: testContextPastdev,
		Contexts: map[string]ContextSpec{
			testContextPastdev: {Image: testImagePastdev, Root: root},
		},
	}

	_, err := NewRunRequest(&cfg, "missing", root, t.TempDir(), "")
	if err == nil {
		t.Fatal("expected unknown context")
	}
	if !strings.Contains(err.Error(), `unknown context "missing"`) {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunRequestResolvesRoot(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "proj")
	err := os.MkdirAll(cwd, 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := Config{
		DefaultContext: testContextPastdev,
		Contexts: map[string]ContextSpec{
			testContextPastdev: {Image: "img:latest", Root: root},
		},
	}

	req, err := NewRunRequest(&cfg, testContextPastdev, cwd, t.TempDir(), "")
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
