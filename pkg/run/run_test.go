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
	// missing makes every image absent locally.
	missing   bool
	existsErr error
	pulled    []string
	network   container.NetworkInfo
	netErr    error
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
	return c.network, c.netErr
}
func (c *captureRuntime) ConnectNetwork(context.Context, string, string) error {
	return errUnused
}
func (c *captureRuntime) RemoveNetwork(context.Context, string) error { return errUnused }
func (c *captureRuntime) ImageExists(context.Context, string) (bool, error) {
	return !c.missing, c.existsErr
}
func (c *captureRuntime) Pull(_ context.Context, ref string, _ io.Writer) error {
	c.pulled = append(c.pulled, ref)
	return nil
}
func (c *captureRuntime) Build(_ context.Context, spec container.Build) error {
	c.build = spec
	return nil
}

func TestRun(t *testing.T) {
	type testCase struct {
		req     Request
		missing bool
		setenv  map[string]string
		setup   func(*testing.T, *Request)
		check   func(*testing.T, *captureRuntime)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		for k, v := range tc.setenv {
			t.Setenv(k, v)
		}
		rt := &captureRuntime{missing: tc.missing}
		tc.req.Runtime = rt
		if tc.setup != nil {
			tc.setup(t, &tc.req)
		}
		err := Run(context.Background(), tc.req)
		if err != nil {
			t.Fatal(err)
		}
		tc.check(t, rt)
	}

	t.Run("builds a workspace spec", func(t *testing.T) {
		root := t.TempDir()
		cwd := filepath.Join(root, "github.com", "example", "agentcon")
		home := t.TempDir()
		err := os.MkdirAll(cwd, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		cursorMount := filepath.Join(home, ".cursor")
		tester(t, testCase{
			req: Request{
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
			},
			check: func(t *testing.T, rt *captureRuntime) {
				t.Helper()
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
			},
		})
	})
	t.Run("passes xtrace env into the container", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			setenv: map[string]string{xtraceEnv: "1"},
			req: Request{
				Image: testImage,
				Root:  root,
				Cwd:   root,
				Home:  t.TempDir(),
				User:  testUser,
			},
			check: func(t *testing.T, rt *captureRuntime) {
				t.Helper()
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
			},
		})
	})
	t.Run("builds the image before start", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			req: Request{
				Image: testImage,
				Build: &ImageBuild{
					Context:    root,
					Dockerfile: "Dockerfile",
					Tags:       []string{testImage},
				},
				Root: root,
				Cwd:  root,
				Home: t.TempDir(),
				User: testUser,
			},
			check: func(t *testing.T, rt *captureRuntime) {
				t.Helper()
				if rt.build.Context != root || rt.build.Dockerfile != "Dockerfile" {
					t.Fatalf("build %+v", rt.build)
				}
				if len(rt.build.Tags) != 1 || rt.build.Tags[0] != testImage {
					t.Fatalf("tags %v", rt.build.Tags)
				}
				if rt.spec.Image != testImage {
					t.Fatalf("image %q", rt.spec.Image)
				}
				if rt.build.PullParent || len(rt.pulled) != 0 {
					t.Fatalf("pulled for a build: parent=%v pulled=%v", rt.build.PullParent, rt.pulled)
				}
			},
		})
	})
	t.Run("refreshes a build's base image when pulling always", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			req: Request{
				Image:      testImage,
				Build:      &ImageBuild{Context: root, Dockerfile: "Dockerfile", Tags: []string{testImage}},
				PullPolicy: PullAlways,
				Root:       root,
				Cwd:        root,
				Home:       t.TempDir(),
				User:       testUser,
			},
			check: func(t *testing.T, rt *captureRuntime) {
				t.Helper()
				if !rt.build.PullParent || len(rt.pulled) != 0 {
					t.Fatalf("parent=%v pulled=%v", rt.build.PullParent, rt.pulled)
				}
			},
		})
	})
	t.Run("pulls a missing agent image", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			req: Request{
				Image: testImage,
				Root:  root,
				Cwd:   root,
				Home:  t.TempDir(),
				User:  testUser,
			},
			missing: true,
			check: func(t *testing.T, rt *captureRuntime) {
				t.Helper()
				if len(rt.pulled) != 1 || rt.pulled[0] != testImage {
					t.Fatalf("pulled %v", rt.pulled)
				}
				if rt.spec.Image != testImage {
					t.Fatalf("image %q", rt.spec.Image)
				}
			},
		})
	})
	t.Run("mounts volume subpaths under DooD", func(t *testing.T) {
		root := t.TempDir()
		home := t.TempDir()
		cursor := home + "/.cursor"
		tester(t, testCase{
			req: Request{
				Image:  testImage,
				Mounts: []container.Mount{{Source: cursor, Target: "/agent/cursor"}},
				Root:   root,
				Cwd:    root,
				Home:   home,
				User:   testUser,
				DooD: &DooD{Mounts: []VolumePath{
					{Volume: "dev-root", Path: root},
					{Volume: "dev-home", Path: home},
				}},
			},
			check: func(t *testing.T, rt *captureRuntime) {
				t.Helper()
				want := []container.Mount{
					{Source: root, Target: "/workspace", Volume: "dev-root"},
					{Source: cursor, Target: "/agent/cursor", Volume: "dev-home", Subpath: ".cursor"},
				}
				if len(rt.spec.Mounts) != 2 || rt.spec.Mounts[0] != want[0] || rt.spec.Mounts[1] != want[1] {
					t.Fatalf("mounts %+v", rt.spec.Mounts)
				}
			},
		})
	})
	t.Run("runs without extra agent mounts", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			req: Request{
				Image:      testImage,
				Root:       root,
				Cwd:        root,
				Home:       t.TempDir(),
				User:       testUser,
				Entrypoint: []string{"/workspace/agent"},
				Args:       []string{"-agent", "http://example"},
				ExtraHosts: []string{testExtraHost},
			},
			check: func(t *testing.T, rt *captureRuntime) {
				t.Helper()
				if len(rt.spec.Mounts) != 1 {
					t.Fatalf("mounts %v", rt.spec.Mounts)
				}
				if len(rt.spec.Entrypoint) != 1 || rt.spec.Entrypoint[0] != "/workspace/agent" {
					t.Fatalf("entrypoint %v", rt.spec.Entrypoint)
				}
				if len(rt.spec.ExtraHosts) != 1 {
					t.Fatalf("extra hosts %v", rt.spec.ExtraHosts)
				}
			},
		})
	})
	t.Run("uses the workspace root when cwd is outside root", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			req: Request{
				Image: testImage,
				Root:  root,
				Cwd:   t.TempDir(),
				Home:  t.TempDir(),
				User:  testUser,
			},
			check: func(t *testing.T, rt *captureRuntime) {
				t.Helper()
				if rt.spec.WorkDir != workspaceMountPoint {
					t.Fatalf("workdir %q", rt.spec.WorkDir)
				}
			},
		})
	})
}

func TestFillSessionIdentity(t *testing.T) {
	type testCase struct {
		req     Request
		wantErr bool
		check   func(*testing.T, Request)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		req := tc.req
		err := fillSessionIdentity(&req)
		if tc.wantErr {
			if err == nil {
				t.Fatal("expected error")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		tc.check(t, req)
	}

	t.Run("fills slug and project from cwd", func(t *testing.T) {
		root := t.TempDir()
		cwd := filepath.Join(root, "github.com", "pastdev", "agentcon")
		tester(t, testCase{
			req: Request{Root: root, Cwd: cwd},
			check: func(t *testing.T, req Request) {
				t.Helper()
				if !running.ValidSlug(req.Slug) {
					t.Fatalf("slug %q", req.Slug)
				}
				if req.Project != "github.com/pastdev/agentcon" {
					t.Fatalf("project %q", req.Project)
				}
			},
		})
	})
	t.Run("keeps a valid supplied slug and project", func(t *testing.T) {
		root := t.TempDir()
		cwd := filepath.Join(root, "github.com", "pastdev", "agentcon")
		tester(t, testCase{
			req: Request{Root: root, Cwd: cwd, Slug: "DEADBEEF", Project: "other/path"},
			check: func(t *testing.T, req Request) {
				t.Helper()
				if req.Slug != "deadbeef" {
					t.Fatalf("slug %q", req.Slug)
				}
				if req.Project != "other/path" {
					t.Fatalf("project %q", req.Project)
				}
			},
		})
	})
	t.Run("rejects an invalid slug", func(t *testing.T) {
		tester(t, testCase{
			req:     Request{Slug: "nope"},
			wantErr: true,
		})
	})
}

func TestParseContainerUser(t *testing.T) {
	type testCase struct {
		user    string
		wantUID int
		wantGID int
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		uid, gid := parseContainerUser(tc.user)
		if uid != tc.wantUID || gid != tc.wantGID {
			t.Fatalf("got %d:%d", uid, gid)
		}
	}

	t.Run("parses uid and gid", func(t *testing.T) {
		tester(t, testCase{user: "1000:1001", wantUID: 1000, wantGID: 1001})
	})
	t.Run("uses uid as gid when gid is omitted", func(t *testing.T) {
		tester(t, testCase{user: "42", wantUID: 42, wantGID: 42})
	})
	t.Run("returns zeros for an empty user", func(t *testing.T) {
		tester(t, testCase{user: "", wantUID: 0, wantGID: 0})
	})
}
