package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/run"
)

func agentCfg(root string) Config {
	return Config{
		DefaultContext: "pastdev",
		Agents: map[string]AgentSpec{
			"cursor": {Image: "pastdev:latest"},
			"claude": {Image: "other:latest"},
		},
		Contexts: map[string]ContextSpec{
			"pastdev": {Agent: "cursor", Root: root},
		},
	}
}

func bouncerCfg(root string, t *testing.T) Config {
	t.Helper()
	cfg := agentCfg(root)
	cfg.Bouncers = map[string]*bouncercfg.Config{
		"github": {
			Listen: "127.0.0.1:8228",
			Profiles: map[string]*bouncercfg.Profile{
				"default": {Unmatched: bouncercfg.UnmatchedDeny},
			},
		},
	}
	cfg.Contexts["pastdev"] = ContextSpec{
		Agent:   "cursor",
		Root:    root,
		Bouncer: "github",
	}
	return cfg
}

func TestNewRunRequest(t *testing.T) {
	type testCase struct {
		cfg     Config
		flags   RunFlags
		cwd     string
		home    string
		wantErr string
		check   func(*testing.T, run.Request)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := NewRunRequest(&tc.cfg, tc.flags, tc.cwd, tc.home)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if tc.check != nil {
			tc.check(t, got)
		}
	}

	t.Run("uses the default context", func(t *testing.T) {
		root := t.TempDir()
		cwd := filepath.Join(root, "github.com", "pastdev", "agentcon")
		err := os.MkdirAll(cwd, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		cfg := agentCfg(root)
		cfg.Contexts["other"] = ContextSpec{Agent: "claude", Root: t.TempDir()}
		tester(t, testCase{
			cfg:  cfg,
			cwd:  cwd,
			home: t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if req.Image != "pastdev:latest" {
					t.Fatalf("got image %q", req.Image)
				}
				if req.Root != root {
					t.Fatalf("got root %q, want %q", req.Root, root)
				}
				if req.Cwd != cwd {
					t.Fatalf("got cwd %q, want %q", req.Cwd, cwd)
				}
				if req.Agent != "cursor" {
					t.Fatalf("got agent %q", req.Agent)
				}
			},
		})
	})
	t.Run("allows cwd at the context root", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			cfg:  agentCfg(root),
			cwd:  root,
			home: t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if req.Root != root {
					t.Fatalf("got root %q, want %q", req.Root, root)
				}
				if req.Cwd != root {
					t.Fatalf("got cwd %q, want %q", req.Cwd, root)
				}
			},
		})
	})
	t.Run("requires default_context", func(t *testing.T) {
		tester(t, testCase{
			cfg: Config{
				Agents: map[string]AgentSpec{
					"cursor": {Image: "pastdev:latest"},
				},
				Contexts: map[string]ContextSpec{
					"pastdev": {Agent: "cursor", Root: t.TempDir()},
				},
			},
			cwd:     t.TempDir(),
			home:    t.TempDir(),
			wantErr: "default_context is not set",
		})
	})
	t.Run("rejects cwd outside the context root", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			cfg:     agentCfg(root),
			cwd:     t.TempDir(),
			home:    t.TempDir(),
			wantErr: "is not under context",
		})
	})
	t.Run("rejects cwd outside a named context root", func(t *testing.T) {
		root := t.TempDir()
		other := t.TempDir()
		cfg := agentCfg(root)
		cfg.DefaultContext = "other"
		cfg.Contexts["other"] = ContextSpec{Agent: "claude", Root: other}
		tester(t, testCase{
			cfg:     cfg,
			flags:   RunFlags{Context: "pastdev"},
			cwd:     other,
			home:    t.TempDir(),
			wantErr: "is not under context",
		})
	})
	t.Run("selects a named context", func(t *testing.T) {
		root := t.TempDir()
		nested := filepath.Join(root, "nested")
		err := os.MkdirAll(nested, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		cfg := agentCfg(root)
		cfg.DefaultContext = "other"
		cfg.Contexts["other"] = ContextSpec{Agent: "claude", Root: nested}
		tester(t, testCase{
			cfg:   cfg,
			flags: RunFlags{Context: "pastdev"},
			cwd:   nested,
			home:  t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if req.Root != root {
					t.Fatalf("got root %q, want %q", req.Root, root)
				}
				if req.Cwd != nested {
					t.Fatalf("got cwd %q, want %q", req.Cwd, nested)
				}
			},
		})
	})
	t.Run("uses the context agent", func(t *testing.T) {
		root := t.TempDir()
		cfg := agentCfg(root)
		cfg.Contexts["pastdev"] = ContextSpec{Agent: "claude", Root: root}
		tester(t, testCase{
			cfg:  cfg,
			cwd:  root,
			home: t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if req.Agent != "claude" {
					t.Fatalf("got agent %q", req.Agent)
				}
				if req.Image != "other:latest" {
					t.Fatalf("got image %q", req.Image)
				}
			},
		})
	})
	t.Run("lets --agent override the context agent", func(t *testing.T) {
		root := t.TempDir()
		cfg := agentCfg(root)
		cfg.Contexts["pastdev"] = ContextSpec{Agent: "claude", Root: root}
		tester(t, testCase{
			cfg:   cfg,
			flags: RunFlags{Agent: "cursor"},
			cwd:   root,
			home:  t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if req.Agent != "cursor" {
					t.Fatalf("got agent %q", req.Agent)
				}
				if req.Image != "pastdev:latest" {
					t.Fatalf("got image %q", req.Image)
				}
			},
		})
	})
	t.Run("rejects an unknown context", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			cfg:     agentCfg(root),
			flags:   RunFlags{Context: "missing"},
			cwd:     root,
			home:    t.TempDir(),
			wantErr: `unknown context "missing"`,
		})
	})
	t.Run("rejects an unknown agent", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			cfg:     agentCfg(root),
			flags:   RunFlags{Agent: "missing"},
			cwd:     root,
			home:    t.TempDir(),
			wantErr: `unknown agent "missing"`,
		})
	})
	t.Run("resolves root to an absolute path", func(t *testing.T) {
		root := t.TempDir()
		cwd := filepath.Join(root, "proj")
		err := os.MkdirAll(cwd, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		cfg := agentCfg(root)
		cfg.Agents["cursor"] = AgentSpec{Image: "img:latest"}
		tester(t, testCase{
			cfg:   cfg,
			flags: RunFlags{Context: "pastdev"},
			cwd:   cwd,
			home:  t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				want, err := filepath.Abs(root)
				if err != nil {
					t.Fatal(err)
				}
				if req.Root != want {
					t.Fatalf("got %q, want %q", req.Root, want)
				}
			},
		})
	})
	t.Run("expands home and relative mounts", func(t *testing.T) {
		root := t.TempDir()
		home := t.TempDir()
		cfg := agentCfg(root)
		cfg.Agents["cursor"] = AgentSpec{
			Image: "pastdev:latest",
			Mounts: []MountSpec{
				{Source: "~/.cursor", Target: "/agent/cursor"},
				{Source: ".config/cursor", Target: "/agent/cursor-config"},
			},
		}
		tester(t, testCase{
			cfg:  cfg,
			cwd:  root,
			home: home,
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if len(req.Mounts) != 2 {
					t.Fatalf("mounts %v", req.Mounts)
				}
				if req.Mounts[0].Source != filepath.Join(home, ".cursor") {
					t.Fatalf("home mount %q", req.Mounts[0].Source)
				}
				if req.Mounts[1].Source != filepath.Join(home, ".config", "cursor") {
					t.Fatalf("relative mount %q", req.Mounts[1].Source)
				}
			},
		})
	})
	t.Run("tags a build-only agent as agentcon/<name>", func(t *testing.T) {
		root := t.TempDir()
		overlay := t.TempDir()
		contextDir := filepath.Join(overlay, "image")
		err := os.MkdirAll(contextDir, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(filepath.Join(contextDir, defaultDockerfile), []byte("FROM scratch\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		cfg := agentCfg(root)
		cfg.OverlayDirs = []string{overlay}
		cfg.Agents["cursor"] = AgentSpec{
			Build: &BuildSpec{Context: "image"},
		}
		tester(t, testCase{
			cfg:  cfg,
			cwd:  root,
			home: t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				wantImage := agentImagePrefix + "cursor"
				if req.Image != wantImage {
					t.Fatalf("image %q", req.Image)
				}
				if req.Build == nil {
					t.Fatal("expected build")
				}
				if req.Build.Context != contextDir {
					t.Fatalf("context %q", req.Build.Context)
				}
				if req.Build.Dockerfile != defaultDockerfile {
					t.Fatalf("dockerfile %q", req.Build.Dockerfile)
				}
				if len(req.Build.Tags) != 1 || req.Build.Tags[0] != wantImage {
					t.Fatalf("tags %v", req.Build.Tags)
				}
			},
		})
	})
	t.Run("keeps image when build and image are both set", func(t *testing.T) {
		root := t.TempDir()
		overlay := t.TempDir()
		contextDir := filepath.Join(overlay, "image")
		err := os.MkdirAll(contextDir, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(filepath.Join(contextDir, "Containerfile"), []byte("FROM scratch\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		cfg := agentCfg(root)
		cfg.OverlayDirs = []string{overlay}
		cfg.Agents["cursor"] = AgentSpec{
			Image: "pastdev:latest",
			Build: &BuildSpec{Context: "image", Dockerfile: "Containerfile"},
		}
		tester(t, testCase{
			cfg:  cfg,
			cwd:  root,
			home: t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if req.Image != "pastdev:latest" {
					t.Fatalf("image %q", req.Image)
				}
				if req.Build == nil || req.Build.Dockerfile != "Containerfile" {
					t.Fatalf("build %+v", req.Build)
				}
			},
		})
	})
	t.Run("requires image or build", func(t *testing.T) {
		root := t.TempDir()
		cfg := agentCfg(root)
		cfg.Agents["cursor"] = AgentSpec{}
		tester(t, testCase{
			cfg:     cfg,
			cwd:     root,
			home:    t.TempDir(),
			wantErr: "requires image or build",
		})
	})
	t.Run("materializes the context bouncer", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			cfg:  bouncerCfg(root, t),
			cwd:  root,
			home: t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if req.Bouncer == nil {
					t.Fatal("expected bouncer")
				}
			},
		})
	})
	t.Run("skips the bouncer when --no-bouncer", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			cfg:   bouncerCfg(root, t),
			flags: RunFlags{NoBouncer: true},
			cwd:   root,
			home:  t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if req.Bouncer != nil {
					t.Fatal("expected no bouncer")
				}
			},
		})
	})
	t.Run("lets --bouncer override the context bouncer", func(t *testing.T) {
		root := t.TempDir()
		cfg := bouncerCfg(root, t)
		cfg.Bouncers["personal"] = cfg.Bouncers["github"]
		cfg.Contexts["pastdev"] = ContextSpec{
			Agent:   "cursor",
			Root:    root,
			Bouncer: "personal",
		}
		tester(t, testCase{
			cfg:   cfg,
			flags: RunFlags{Bouncer: "github"},
			cwd:   root,
			home:  t.TempDir(),
			check: func(t *testing.T, req run.Request) {
				t.Helper()
				if req.Bouncer == nil {
					t.Fatal("expected bouncer")
				}
			},
		})
	})
	t.Run("rejects an unknown bouncer", func(t *testing.T) {
		root := t.TempDir()
		tester(t, testCase{
			cfg:     agentCfg(root),
			flags:   RunFlags{Bouncer: "missing"},
			cwd:     root,
			home:    t.TempDir(),
			wantErr: `unknown bouncer "missing"`,
		})
	})
}

func TestRunRequestPullPolicy(t *testing.T) {
	type testCase struct {
		agentPolicy   string
		sidecarPolicy string
		flag          string
		wantAgent     run.PullPolicy
		wantSidecar   run.PullPolicy
		wantErr       string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		root := t.TempDir()
		cfg := agentCfg(root)
		agent := cfg.Agents["cursor"]
		agent.PullPolicy = tc.agentPolicy
		cfg.Agents["cursor"] = agent
		cfg.Sidecar.PullPolicy = tc.sidecarPolicy
		req, err := NewRunRequest(&cfg, RunFlags{Pull: tc.flag}, root, t.TempDir())
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if req.PullPolicy != tc.wantAgent || req.SidecarPullPolicy != tc.wantSidecar {
			t.Fatalf("agent %q sidecar %q, want %q %q", req.PullPolicy, req.SidecarPullPolicy, tc.wantAgent, tc.wantSidecar)
		}
	}

	t.Run("defaults both to missing", func(t *testing.T) {
		tester(t, testCase{wantAgent: run.PullMissing, wantSidecar: run.PullMissing})
	})
	t.Run("applies the agent pull_policy to the agent only", func(t *testing.T) {
		tester(t, testCase{agentPolicy: "always", wantAgent: run.PullAlways, wantSidecar: run.PullMissing})
	})
	t.Run("applies the sidecar pull_policy to the sidecar only", func(t *testing.T) {
		tester(t, testCase{sidecarPolicy: "always", wantAgent: run.PullMissing, wantSidecar: run.PullAlways})
	})
	t.Run("overrides with the flag for both", func(t *testing.T) {
		tester(t, testCase{agentPolicy: "always", sidecarPolicy: "always", flag: "never", wantAgent: run.PullNever, wantSidecar: run.PullNever})
	})
	t.Run("rejects an unknown pull_policy", func(t *testing.T) {
		tester(t, testCase{agentPolicy: "sometimes", wantErr: `agent "cursor" pull_policy`})
	})
	t.Run("rejects an unknown sidecar pull_policy", func(t *testing.T) {
		tester(t, testCase{sidecarPolicy: "sometimes", wantErr: "sidecar pull_policy"})
	})
	t.Run("rejects an unknown flag value", func(t *testing.T) {
		tester(t, testCase{flag: "sometimes", wantErr: "--pull"})
	})
}

func TestRunRequestSidecarImage(t *testing.T) {
	type testCase struct {
		sidecar   SidecarSpec
		noBouncer bool
		wantImage string
		wantBuild bool
		wantErr   string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		root := t.TempDir()
		overlay := t.TempDir()
		contextDir := filepath.Join(overlay, "sidecar")
		err := os.MkdirAll(contextDir, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(filepath.Join(contextDir, defaultDockerfile), []byte("FROM scratch\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		cfg := bouncerCfg(root, t)
		cfg.OverlayDirs = []string{overlay}
		cfg.Sidecar = tc.sidecar
		req, err := NewRunRequest(&cfg, RunFlags{NoBouncer: tc.noBouncer}, root, t.TempDir())
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if req.SidecarImage != tc.wantImage {
			t.Fatalf("image %q, want %q", req.SidecarImage, tc.wantImage)
		}
		if tc.wantBuild != (req.SidecarBuild != nil) {
			t.Fatalf("build %+v", req.SidecarBuild)
		}
		if req.SidecarBuild == nil {
			return
		}
		if req.SidecarBuild.Context != contextDir || req.SidecarBuild.Dockerfile != defaultDockerfile {
			t.Fatalf("build %+v", req.SidecarBuild)
		}
		if len(req.SidecarBuild.Tags) != 1 || req.SidecarBuild.Tags[0] != tc.wantImage {
			t.Fatalf("tags %v", req.SidecarBuild.Tags)
		}
	}

	t.Run("leaves the stock image by default", func(t *testing.T) {
		tester(t, testCase{})
	})
	t.Run("uses a configured image", func(t *testing.T) {
		tester(t, testCase{sidecar: SidecarSpec{Image: "approved/ubi:10"}, wantImage: "approved/ubi:10"})
	})
	t.Run("tags a build-only sidecar", func(t *testing.T) {
		tester(t, testCase{
			sidecar:   SidecarSpec{Build: &BuildSpec{Context: "sidecar"}},
			wantImage: sidecarImageTag,
			wantBuild: true,
		})
	})
	t.Run("keeps image when build and image are both set", func(t *testing.T) {
		tester(t, testCase{
			sidecar:   SidecarSpec{Image: "mine/sidecar:1", Build: &BuildSpec{Context: "sidecar"}},
			wantImage: "mine/sidecar:1",
			wantBuild: true,
		})
	})
	t.Run("requires a build context", func(t *testing.T) {
		tester(t, testCase{
			sidecar: SidecarSpec{Build: &BuildSpec{}},
			wantErr: "sidecar build.context is required",
		})
	})
	t.Run("reports a missing dockerfile", func(t *testing.T) {
		tester(t, testCase{
			sidecar: SidecarSpec{Build: &BuildSpec{Context: "sidecar", Dockerfile: "Other"}},
			wantErr: "sidecar dockerfile Other",
		})
	})
	t.Run("skips the sidecar when --no-bouncer", func(t *testing.T) {
		tester(t, testCase{
			sidecar:   SidecarSpec{Build: &BuildSpec{}},
			noBouncer: true,
		})
	})
}
