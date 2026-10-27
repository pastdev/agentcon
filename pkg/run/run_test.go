package run

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pastdev/agentcon/pkg/container"
)

const testImage = "pastdev.com/agentcon:latest"

type captureRuntime struct {
	spec container.Spec
}

func (c *captureRuntime) Run(_ context.Context, spec container.Spec) error {
	c.spec = spec
	return nil
}

func TestRunBuildsSpec(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "github.com", "example", "agentcon")
	home := t.TempDir()
	err := os.MkdirAll(cwd, 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	rt := &captureRuntime{}
	err = Run(context.Background(), Request{
		Image:   testImage,
		Root:    root,
		Cwd:     cwd,
		Home:    home,
		User:    "1000:1000",
		Args:    []string{"--help"},
		Runtime: rt,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if rt.spec.Image != testImage {
		t.Fatalf("image %q", rt.spec.Image)
	}
	if rt.spec.WorkDir != "/workspace/github.com/example/agentcon" {
		t.Fatalf("workdir %q", rt.spec.WorkDir)
	}
	if len(rt.spec.Env) != 1 || rt.spec.Env[0] != hostRootEnv+"="+root {
		t.Fatalf("env %v", rt.spec.Env)
	}
	if len(rt.spec.Mounts) != 2 {
		t.Fatalf("mounts %v", rt.spec.Mounts)
	}
	if rt.spec.Mounts[0].Source != root || rt.spec.Mounts[0].Target != workspaceMountPoint {
		t.Fatalf("workspace mount %v", rt.spec.Mounts[0])
	}
	wantCursor := filepath.Join(home, ".cursor")
	if rt.spec.Mounts[1].Source != wantCursor || rt.spec.Mounts[1].Target != harnessCursorMount {
		t.Fatalf("cursor mount %v", rt.spec.Mounts[1])
	}
	if _, statErr := os.Stat(wantCursor); statErr != nil {
		t.Fatalf("cursor dir: %v", statErr)
	}
	if len(rt.spec.Args) != 1 || rt.spec.Args[0] != "--help" {
		t.Fatalf("args %v", rt.spec.Args)
	}
}

func TestRunNamedContextOutsideRootUsesWorkspaceRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	rt := &captureRuntime{}
	err := Run(context.Background(), Request{
		Image:   testImage,
		Root:    root,
		Cwd:     other,
		Home:    t.TempDir(),
		User:    "1000:1000",
		Runtime: rt,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rt.spec.WorkDir != workspaceMountPoint {
		t.Fatalf("workdir %q", rt.spec.WorkDir)
	}
}
