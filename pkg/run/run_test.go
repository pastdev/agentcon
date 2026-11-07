package run

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pastdev/agentcon/internal/bouncer/running"
	"github.com/pastdev/agentcon/pkg/container"
)

var errUnused = errors.New("unused")

const (
	testImage     = "pastdev.com/agentcon:latest"
	testUser      = "1000:1000"
	testExtraHost = "host.docker.internal:host-gateway"
	testSlug      = "deadbeef"
)

type captureRuntime struct {
	spec  container.Spec
	build container.Build
}

func (c *captureRuntime) Run(_ context.Context, spec container.Spec) error {
	c.spec = spec
	return nil
}

func (c *captureRuntime) Create(context.Context, container.Spec) (string, error) {
	return "", errUnused
}
func (c *captureRuntime) Start(context.Context, string) error { return errUnused }
func (c *captureRuntime) AttachStartWait(context.Context, string, container.Spec) error {
	return errUnused
}
func (c *captureRuntime) CopyTo(context.Context, string, string, io.Reader) error {
	return errUnused
}
func (c *captureRuntime) Exec(context.Context, string, container.Exec) error {
	return errUnused
}
func (c *captureRuntime) Inspect(context.Context, string) (container.Info, error) {
	return container.Info{}, errUnused
}
func (c *captureRuntime) Remove(context.Context, string, bool) error { return errUnused }
func (c *captureRuntime) CreateNetwork(context.Context, container.NetworkSpec) (string, error) {
	return "", errUnused
}
func (c *captureRuntime) InspectNetwork(context.Context, string) (container.NetworkInfo, error) {
	return container.NetworkInfo{}, errUnused
}
func (c *captureRuntime) ConnectNetwork(context.Context, string, string) error {
	return errUnused
}
func (c *captureRuntime) RemoveNetwork(context.Context, string) error { return errUnused }
func (c *captureRuntime) Build(_ context.Context, spec container.Build) error {
	c.build = spec
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
	cursorMount := filepath.Join(home, ".cursor")
	err = Run(context.Background(), Request{
		Image: testImage,
		Mounts: []container.Mount{
			{Source: cursorMount, Target: "/agent/cursor"},
		},
		Root:    root,
		Cwd:     cwd,
		Home:    home,
		User:    testUser,
		Context: "git",
		Slug:    testSlug,
		Args:    []string{"--help"},
		Runtime: rt,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if rt.spec.Image != testImage {
		t.Fatalf("image %q", rt.spec.Image)
	}
	if rt.spec.Name != "agentcon-github-com-example-agentcon-deadbeef-agent" {
		t.Fatalf("name %q", rt.spec.Name)
	}
	if rt.spec.Labels[labelSlug] != testSlug || rt.spec.Labels[labelProject] != "github.com/example/agentcon" {
		t.Fatalf("labels %v", rt.spec.Labels)
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
	if rt.spec.Mounts[1].Source != cursorMount || rt.spec.Mounts[1].Target != "/agent/cursor" {
		t.Fatalf("cursor mount %v", rt.spec.Mounts[1])
	}
	if _, statErr := os.Stat(cursorMount); statErr != nil {
		t.Fatalf("cursor dir: %v", statErr)
	}
	if len(rt.spec.Args) != 1 || rt.spec.Args[0] != "--help" {
		t.Fatalf("args %v", rt.spec.Args)
	}
}

func TestRunPassesXtraceEnv(t *testing.T) {
	t.Setenv(xtraceEnv, "1")
	root := t.TempDir()
	rt := &captureRuntime{}
	err := Run(context.Background(), Request{
		Image:   testImage,
		Root:    root,
		Cwd:     root,
		Home:    t.TempDir(),
		User:    testUser,
		Runtime: rt,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	found := false
	for _, e := range rt.spec.Env {
		if e == xtraceEnv+"=1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("env %v", rt.spec.Env)
	}
}

func TestFillSessionIdentity(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "github.com", "pastdev", "agentcon")
	req := Request{Root: root, Cwd: cwd}
	err := fillSessionIdentity(&req)
	if err != nil {
		t.Fatal(err)
	}
	if !running.ValidSlug(req.Slug) {
		t.Fatalf("slug %q", req.Slug)
	}
	if req.Project != "github.com/pastdev/agentcon" {
		t.Fatalf("project %q", req.Project)
	}

	req = Request{Root: root, Cwd: cwd, Slug: "DEADBEEF", Project: "other/path"}
	err = fillSessionIdentity(&req)
	if err != nil {
		t.Fatal(err)
	}
	if req.Slug != testSlug {
		t.Fatalf("slug %q", req.Slug)
	}
	if req.Project != "other/path" {
		t.Fatalf("project %q", req.Project)
	}

	req = Request{Slug: "nope"}
	err = fillSessionIdentity(&req)
	if err == nil {
		t.Fatal("expected invalid slug")
	}
}

func TestRunBuildsImageBeforeStart(t *testing.T) {
	root := t.TempDir()
	rt := &captureRuntime{}
	err := Run(context.Background(), Request{
		Image: testImage,
		Build: &ImageBuild{
			Context:    root,
			Dockerfile: "Dockerfile",
			Tags:       []string{testImage},
		},
		Root:    root,
		Cwd:     root,
		Home:    t.TempDir(),
		User:    testUser,
		Runtime: rt,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rt.build.Context != root || rt.build.Dockerfile != "Dockerfile" {
		t.Fatalf("build %+v", rt.build)
	}
	if len(rt.build.Tags) != 1 || rt.build.Tags[0] != testImage {
		t.Fatalf("tags %v", rt.build.Tags)
	}
	if rt.spec.Image != testImage {
		t.Fatalf("image %q", rt.spec.Image)
	}
}

func TestRunWithoutAgentMounts(t *testing.T) {
	root := t.TempDir()
	rt := &captureRuntime{}
	err := Run(context.Background(), Request{
		Image:      testImage,
		Root:       root,
		Cwd:        root,
		Home:       t.TempDir(),
		User:       testUser,
		Entrypoint: []string{"/workspace/agent"},
		Args:       []string{"-agent", "http://example"},
		ExtraHosts: []string{testExtraHost},
		Runtime:    rt,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(rt.spec.Mounts) != 1 {
		t.Fatalf("mounts %v", rt.spec.Mounts)
	}
	if len(rt.spec.Entrypoint) != 1 || rt.spec.Entrypoint[0] != "/workspace/agent" {
		t.Fatalf("entrypoint %v", rt.spec.Entrypoint)
	}
	if len(rt.spec.ExtraHosts) != 1 {
		t.Fatalf("extra hosts %v", rt.spec.ExtraHosts)
	}
}

func TestParseContainerUser(t *testing.T) {
	uid, gid := parseContainerUser("1000:1001")
	if uid != 1000 || gid != 1001 {
		t.Fatalf("got %d:%d", uid, gid)
	}
	uid, gid = parseContainerUser("42")
	if uid != 42 || gid != 42 {
		t.Fatalf("uid-only got %d:%d", uid, gid)
	}
	uid, gid = parseContainerUser("")
	if uid != 0 || gid != 0 {
		t.Fatalf("empty got %d:%d", uid, gid)
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
		User:    testUser,
		Runtime: rt,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rt.spec.WorkDir != workspaceMountPoint {
		t.Fatalf("workdir %q", rt.spec.WorkDir)
	}
}
