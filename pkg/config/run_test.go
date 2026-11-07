package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
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
	testAgentCursor    = "cursor"
	testAgentClaude    = "claude"
	testBouncerGithub  = "github"
	testProfileDefault = "default"
	testProfileLocked  = "locked-down"
	testMountCursor    = "/agent/cursor"
	testMissing        = "missing"
)

func agentCfg(root string) Config {
	return Config{
		DefaultContext: testContextPastdev,
		Agents: map[string]AgentSpec{
			testAgentCursor: {Image: testImagePastdev},
			testAgentClaude: {Image: testImageOther},
		},
		Contexts: map[string]ContextSpec{
			testContextPastdev: {Agent: testAgentCursor, Root: root},
		},
	}
}

func TestNewRunRequestUsesDefaultContext(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "github.com", "pastdev", "agentcon")
	err := os.MkdirAll(cwd, 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := agentCfg(root)
	cfg.Contexts[testContextOther] = ContextSpec{Agent: testAgentClaude, Root: t.TempDir()}

	req, err := NewRunRequest(&cfg, RunFlags{}, cwd, t.TempDir())
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
	if req.Agent != testAgentCursor {
		t.Fatalf("got agent %q", req.Agent)
	}
}

func TestNewRunRequestAllowsCwdAtRoot(t *testing.T) {
	root := t.TempDir()
	cfg := agentCfg(root)

	req, err := NewRunRequest(&cfg, RunFlags{}, root, t.TempDir())
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
		Agents: map[string]AgentSpec{
			testAgentCursor: {Image: testImagePastdev},
		},
		Contexts: map[string]ContextSpec{
			testContextPastdev: {Agent: testAgentCursor, Root: t.TempDir()},
		},
	}

	_, err := NewRunRequest(&cfg, RunFlags{}, t.TempDir(), t.TempDir())
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
	cfg := agentCfg(root)

	_, err := NewRunRequest(&cfg, RunFlags{}, other, t.TempDir())
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
	cfg := agentCfg(root)
	cfg.DefaultContext = testContextOther
	cfg.Contexts[testContextOther] = ContextSpec{Agent: testAgentClaude, Root: other}

	_, err := NewRunRequest(&cfg, RunFlags{Context: testContextPastdev}, other, t.TempDir())
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

	cfg := agentCfg(root)
	cfg.DefaultContext = testContextOther
	cfg.Contexts[testContextOther] = ContextSpec{Agent: testAgentClaude, Root: nested}

	req, err := NewRunRequest(&cfg, RunFlags{Context: testContextPastdev}, nested, t.TempDir())
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

func TestNewRunRequestAgentOverride(t *testing.T) {
	root := t.TempDir()
	cfg := agentCfg(root)
	cfg.Contexts[testContextPastdev] = ContextSpec{
		Agent: testAgentClaude,
		Root:  root,
	}
	req, err := NewRunRequest(&cfg, RunFlags{}, root, t.TempDir())
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Agent != testAgentClaude {
		t.Fatalf("got agent %q", req.Agent)
	}
	if req.Image != testImageOther {
		t.Fatalf("got image %q", req.Image)
	}
	req, err = NewRunRequest(&cfg, RunFlags{Agent: testAgentCursor}, root, t.TempDir())
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Agent != testAgentCursor {
		t.Fatalf("got agent %q", req.Agent)
	}
	if req.Image != testImagePastdev {
		t.Fatalf("got image %q", req.Image)
	}
}

func TestNewRunRequestUnknownName(t *testing.T) {
	root := t.TempDir()
	cfg := agentCfg(root)

	_, err := NewRunRequest(&cfg, RunFlags{Context: testMissing}, root, t.TempDir())
	if err == nil {
		t.Fatal("expected unknown context")
	}
	if !strings.Contains(err.Error(), `unknown context "missing"`) {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunRequestUnknownAgent(t *testing.T) {
	root := t.TempDir()
	cfg := agentCfg(root)

	_, err := NewRunRequest(&cfg, RunFlags{Agent: testMissing}, root, t.TempDir())
	if err == nil {
		t.Fatal("expected unknown agent")
	}
	if !strings.Contains(err.Error(), `unknown agent "missing"`) {
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

	cfg := agentCfg(root)
	cfg.Agents[testAgentCursor] = AgentSpec{Image: "img:latest"}

	req, err := NewRunRequest(&cfg, RunFlags{Context: testContextPastdev}, cwd, t.TempDir())
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

func TestNewRunRequestExpandsMounts(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	cfg := agentCfg(root)
	cfg.Agents[testAgentCursor] = AgentSpec{
		Image: testImagePastdev,
		Mounts: []MountSpec{
			{Source: "~/.cursor", Target: testMountCursor},
			{Source: ".config/cursor", Target: "/agent/cursor-config"},
		},
	}

	req, err := NewRunRequest(&cfg, RunFlags{}, root, home)
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if len(req.Mounts) != 2 {
		t.Fatalf("mounts %v", req.Mounts)
	}
	if req.Mounts[0].Source != filepath.Join(home, ".cursor") {
		t.Fatalf("home mount %q", req.Mounts[0].Source)
	}
	if req.Mounts[1].Source != filepath.Join(home, ".config", "cursor") {
		t.Fatalf("relative mount %q", req.Mounts[1].Source)
	}
}

func TestNewRunRequestBuildOnlyTagsAgent(t *testing.T) {
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
	cfg.Agents[testAgentCursor] = AgentSpec{
		Build: &BuildSpec{Context: "image"},
	}

	req, err := NewRunRequest(&cfg, RunFlags{}, root, t.TempDir())
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	wantImage := agentImagePrefix + testAgentCursor
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
}

func TestNewRunRequestBuildAndImage(t *testing.T) {
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
	cfg.Agents[testAgentCursor] = AgentSpec{
		Image: testImagePastdev,
		Build: &BuildSpec{Context: "image", Dockerfile: "Containerfile"},
	}

	req, err := NewRunRequest(&cfg, RunFlags{}, root, t.TempDir())
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Image != testImagePastdev {
		t.Fatalf("image %q", req.Image)
	}
	if req.Build == nil || req.Build.Dockerfile != "Containerfile" {
		t.Fatalf("build %+v", req.Build)
	}
}

func TestNewRunRequestRequiresImageOrBuild(t *testing.T) {
	root := t.TempDir()
	cfg := agentCfg(root)
	cfg.Agents[testAgentCursor] = AgentSpec{}

	_, err := NewRunRequest(&cfg, RunFlags{}, root, t.TempDir())
	if err == nil {
		t.Fatal("expected image or build")
	}
	if !strings.Contains(err.Error(), "requires image or build") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunRequestSkipsBouncer(t *testing.T) {
	root := t.TempDir()
	cfg := bouncerCfg(root, t)

	req, err := NewRunRequest(&cfg, RunFlags{}, root, t.TempDir())
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Bouncer == nil {
		t.Fatal("expected bouncer")
	}

	req, err = NewRunRequest(&cfg, RunFlags{NoBouncer: true}, root, t.TempDir())
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Bouncer != nil {
		t.Fatal("expected no bouncer")
	}
}

func TestNewRunRequestBouncerOverride(t *testing.T) {
	root := t.TempDir()
	cfg := bouncerCfg(root, t)
	cfg.Bouncers["personal"] = cfg.Bouncers[testBouncerGithub]
	cfg.Contexts[testContextPastdev] = ContextSpec{
		Agent:   testAgentCursor,
		Root:    root,
		Bouncer: "personal",
	}

	req, err := NewRunRequest(&cfg, RunFlags{Bouncer: testBouncerGithub}, root, t.TempDir())
	if err != nil {
		t.Fatalf("new run request: %v", err)
	}
	if req.Bouncer == nil {
		t.Fatal("expected bouncer")
	}
}

func TestNewRunRequestUnknownBouncer(t *testing.T) {
	root := t.TempDir()
	cfg := agentCfg(root)

	_, err := NewRunRequest(&cfg, RunFlags{Bouncer: testMissing}, root, t.TempDir())
	if err == nil {
		t.Fatal("expected unknown bouncer")
	}
	if !strings.Contains(err.Error(), `unknown bouncer "missing"`) {
		t.Fatalf("got %v", err)
	}
}

func bouncerCfg(root string, t *testing.T) Config {
	t.Helper()
	cfg := agentCfg(root)
	cfg.Bouncers = map[string]*bouncercfg.Config{
		testBouncerGithub: {
			Listen: testBouncerListen,
			Profiles: map[string]*bouncercfg.Profile{
				testProfileDefault: {Unmatched: bouncercfg.UnmatchedDeny},
			},
		},
	}
	cfg.Contexts[testContextPastdev] = ContextSpec{
		Agent:   testAgentCursor,
		Root:    root,
		Bouncer: testBouncerGithub,
	}
	return cfg
}
