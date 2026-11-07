package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"gopkg.in/yaml.v3"
)

func TestMaterializeBouncer(t *testing.T) {
	type testCase struct {
		cfg        Config
		name       string
		bouncer    string
		home       string
		wantNil    bool
		wantErr    string
		wantListen string
		wantTS     string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		setup, err := tc.cfg.MaterializeBouncer(tc.name, tc.bouncer, AgentSpec{})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
			return
		}
		if err != nil {
			t.Fatalf("materialize: %v", err)
		}
		if tc.wantNil {
			if setup != nil {
				t.Fatal("expected no bouncer setup")
			}
			return
		}
		if setup == nil {
			t.Fatal("expected setup")
		}
		if tc.wantListen != "" && !strings.Contains(string(setup.PolicyYAML), tc.wantListen) {
			t.Fatalf("policy %s", setup.PolicyYAML)
		}
		if tc.wantTS != "" {
			if _, ok := setup.TSFiles[tc.wantTS]; !ok {
				t.Fatalf("ts files %v, want %s", setup.TSFiles, tc.wantTS)
			}
			if strings.Contains(string(setup.PolicyYAML), tc.cfg.OverlayDirs[0]) {
				t.Fatalf("host overlay leaked: %s", setup.PolicyYAML)
			}
		}
		if tc.home == "" {
			return
		}
		_, statErr := os.Stat(filepath.Join(tc.home, ".local", "state", "agentcon"))
		if !os.IsNotExist(statErr) {
			t.Fatalf("materialize should not write host state: %v", statErr)
		}
	}

	overlay := t.TempDir()
	err := os.MkdirAll(filepath.Join(overlay, bouncercfg.TSDir, "filters"), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	filter := filepath.Join(overlay, bouncercfg.TSDir, "filters", "deny.ts")
	err = os.WriteFile(filter, []byte("export {}\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()

	t.Run("without section", func(t *testing.T) {
		tester(t, testCase{
			cfg: Config{
				Contexts: map[string]ContextSpec{
					testContextPastdev: {Agent: testAgentCursor, Root: t.TempDir()},
				},
			},
			name:    testContextPastdev,
			wantNil: true,
		})
	})

	t.Run("unknown bouncer", func(t *testing.T) {
		tester(t, testCase{
			cfg:     Config{Contexts: map[string]ContextSpec{}},
			name:    testContextPastdev,
			bouncer: testBouncerGithub,
			wantErr: `unknown bouncer "github"`,
		})
	})

	t.Run("encodes policy in memory", func(t *testing.T) {
		tester(t, testCase{
			cfg: Config{
				OverlayDirs: []string{overlay},
				Bouncers: map[string]*bouncercfg.Config{
					testBouncerGithub: {
						Listen: testBouncerListen,
						Dir:    overlay,
						Profiles: map[string]*bouncercfg.Profile{
							"default": {
								Filters: []bouncercfg.FilterRef{{Path: filter}},
							},
						},
					},
				},
				Contexts: map[string]ContextSpec{
					testContextPastdev: {
						Agent:   testAgentCursor,
						Root:    t.TempDir(),
						Bouncer: testBouncerGithub,
					},
				},
			},
			name:       testContextPastdev,
			bouncer:    testBouncerGithub,
			home:       home,
			wantListen: testBouncerListen,
			wantTS:     "filters/deny.ts",
		})
	})

	t.Run("invalid policy", func(t *testing.T) {
		tester(t, testCase{
			cfg: Config{
				Bouncers: map[string]*bouncercfg.Config{
					testBouncerGithub: {
						Credentials: map[string]*bouncercfg.Credential{
							"gl": {Token: &bouncercfg.ValueSource{Source: "command"}},
						},
					},
				},
				Contexts: map[string]ContextSpec{
					testContextPastdev: {
						Agent:   testAgentCursor,
						Root:    t.TempDir(),
						Bouncer: testBouncerGithub,
					},
				},
			},
			name:    testContextPastdev,
			bouncer: testBouncerGithub,
			wantErr: "source command requires command",
		})
	})
}

func TestWriteBouncer(t *testing.T) {
	type testCase struct {
		cfg        Config
		name       string
		wantEmpty  bool
		wantErr    string
		wantListen string
		wantTS     string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		dir := t.TempDir()
		got, err := tc.cfg.WriteBouncer(tc.name, dir)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
			return
		}
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if tc.wantEmpty {
			if got != "" {
				t.Fatalf("got %q, want empty", got)
			}
			return
		}
		want := filepath.Join(dir, bouncercfg.FileName)
		if got != want {
			t.Fatalf("path %q, want %q", got, want)
		}
		//nolint:gosec // test fixture written to TempDir
		data, err := os.ReadFile(got)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), tc.wantListen) {
			t.Fatalf("policy %s", data)
		}
		if tc.wantTS == "" {
			return
		}
		_, err = os.Stat(filepath.Join(dir, bouncercfg.TSDir, tc.wantTS))
		if err != nil {
			t.Fatal(err)
		}
	}

	overlay := t.TempDir()
	err := os.MkdirAll(filepath.Join(overlay, bouncercfg.TSDir, "filters"), 0o700)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(overlay, bouncercfg.TSDir, "filters", "deny.ts"), []byte("export {}\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("writes layout", func(t *testing.T) {
		tester(t, testCase{
			cfg: Config{
				OverlayDirs: []string{overlay},
				Bouncers: map[string]*bouncercfg.Config{
					testBouncerGithub: {
						Listen: testBouncerListen,
					},
				},
				Contexts: map[string]ContextSpec{
					testContextPastdev: {
						Agent:   testAgentCursor,
						Root:    t.TempDir(),
						Bouncer: testBouncerGithub,
					},
				},
			},
			name:       testContextPastdev,
			wantListen: testBouncerListen,
			wantTS:     "filters/deny.ts",
		})
	})

	t.Run("without section", func(t *testing.T) {
		tester(t, testCase{
			cfg: Config{
				Contexts: map[string]ContextSpec{
					testContextPastdev: {Agent: testAgentCursor, Root: t.TempDir()},
				},
			},
			name:      testContextPastdev,
			wantEmpty: true,
		})
	})
}

func TestLoadBouncerService(t *testing.T) {
	type testCase struct {
		path       string
		wantErr    string
		wantListen string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := LoadBouncerService(tc.path)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
			return
		}
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if got.Listen != tc.wantListen {
			t.Fatalf("listen %q, want %q", got.Listen, tc.wantListen)
		}
	}

	t.Run("loads file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.yaml")
		err := os.WriteFile(path, []byte("listen: "+testBouncerListen+"\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			path:       path,
			wantListen: testBouncerListen,
		})
	})

	t.Run("loads directory", func(t *testing.T) {
		dir := t.TempDir()
		err := os.WriteFile(filepath.Join(dir, bouncercfg.FileName), []byte("listen: "+testBouncerListen+"\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			path:       dir,
			wantListen: testBouncerListen,
		})
	})

	t.Run("invalid policy", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.yaml")
		err := os.WriteFile(path, []byte("credentials:\n  gl:\n    token:\n      source: command\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			path:    path,
			wantErr: "source command requires command",
		})
	})
}

func TestMaterializeBouncerAgentTunnel(t *testing.T) {
	doc := &bouncercfg.Config{
		Listen: testBouncerListen,
		Profiles: map[string]*bouncercfg.Profile{
			testProfileDefault: {
				Unmatched: bouncercfg.UnmatchedDeny,
				Tunnel:    []string{testHostExtra},
			},
			testProfileLocked: {
				Extends:   testProfileDefault,
				Unmatched: bouncercfg.UnmatchedDeny,
			},
		},
	}
	cfg := Config{
		Agents: map[string]AgentSpec{
			testAgentCursor: {Image: testImagePastdev, Tunnel: []string{testHostCursor, testHostCursorStar}},
		},
		Bouncers: map[string]*bouncercfg.Config{
			testBouncerGithub: doc,
		},
		Contexts: map[string]ContextSpec{
			testContextPastdev: {
				Agent:   testAgentCursor,
				Root:    t.TempDir(),
				Bouncer: testBouncerGithub,
			},
		},
	}
	orig := append([]string{}, doc.Profiles[testProfileDefault].Tunnel...)
	setup, err := cfg.MaterializeBouncer(testContextPastdev, testBouncerGithub, cfg.Agents[testAgentCursor])
	if err != nil {
		t.Fatal(err)
	}
	if setup == nil {
		t.Fatal("expected setup")
	}
	var policy bouncercfg.Config
	err = yaml.Unmarshal(setup.PolicyYAML, &policy)
	if err != nil {
		t.Fatal(err)
	}
	got := policy.Profiles[testProfileDefault].Tunnel
	if !containsHost(got, testHostCursor) || !containsHost(got, testHostCursorStar) || !containsHost(got, testHostExtra) {
		t.Fatalf("root tunnel %v", got)
	}
	if containsHost(policy.Profiles[testProfileLocked].Tunnel, testHostCursor) {
		t.Fatalf("child should inherit, not copy: %v", policy.Profiles[testProfileLocked].Tunnel)
	}
	if !equalHosts(doc.Profiles[testProfileDefault].Tunnel, orig) {
		t.Fatal("materialize mutated source tunnel")
	}
}

func TestMaterializeBouncerUsesSelectedAgentTunnel(t *testing.T) {
	cfg := Config{
		Agents: map[string]AgentSpec{
			testAgentCursor: {Image: testImagePastdev, Tunnel: []string{testHostCursor}},
			testAgentClaude: {Image: testImageOther, Tunnel: []string{testHostAnthropic}},
		},
		Bouncers: map[string]*bouncercfg.Config{
			testBouncerGithub: {
				Listen: testBouncerListen,
				Profiles: map[string]*bouncercfg.Profile{
					testProfileDefault: {Unmatched: bouncercfg.UnmatchedDeny},
				},
			},
		},
		Contexts: map[string]ContextSpec{
			testContextPastdev: {
				Agent:   testAgentClaude,
				Root:    t.TempDir(),
				Bouncer: testBouncerGithub,
			},
		},
	}
	setup, err := cfg.MaterializeBouncer(testContextPastdev, testBouncerGithub, cfg.Agents[testAgentClaude])
	if err != nil {
		t.Fatal(err)
	}
	var policy bouncercfg.Config
	err = yaml.Unmarshal(setup.PolicyYAML, &policy)
	if err != nil {
		t.Fatal(err)
	}
	got := policy.Profiles[testProfileDefault].Tunnel
	if containsHost(got, testHostCursor) {
		t.Fatalf("cursor hosts on claude agent: %v", got)
	}
	if !containsHost(got, testHostAnthropic) {
		t.Fatalf("missing claude tunnel %v", got)
	}
}

func equalHosts(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsHost(hosts []string, want string) bool {
	for _, h := range hosts {
		if h == want {
			return true
		}
	}
	return false
}

func TestBouncerLayoutDir(t *testing.T) {
	got := BouncerLayoutDir("/home/me", testContextPastdev)
	want := filepath.Join("/home/me", ".local", "state", "agentcon", testContextPastdev, "bouncer")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
