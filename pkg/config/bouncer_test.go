package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/run"
	"gopkg.in/yaml.v3"
)

func TestMaterializeBouncer(t *testing.T) {
	type testCase struct {
		cfg        Config
		name       string
		bouncer    string
		agent      AgentSpec
		home       string
		wantNil    bool
		wantErr    string
		wantListen string
		wantTS     string
		check      func(*testing.T, *run.BouncerSetup, Config)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		setup, err := tc.cfg.MaterializeBouncer(tc.name, tc.bouncer, tc.agent)
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
		if tc.home != "" {
			_, statErr := os.Stat(filepath.Join(tc.home, ".local", "state", "agentcon"))
			if !os.IsNotExist(statErr) {
				t.Fatalf("materialize should not write host state: %v", statErr)
			}
		}
		if tc.check != nil {
			tc.check(t, setup, tc.cfg)
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
					"pastdev": {Agent: "cursor", Root: t.TempDir()},
				},
			},
			name:    "pastdev",
			wantNil: true,
		})
	})
	t.Run("unknown bouncer", func(t *testing.T) {
		tester(t, testCase{
			cfg:     Config{Contexts: map[string]ContextSpec{}},
			name:    "pastdev",
			bouncer: "github",
			wantErr: `unknown bouncer "github"`,
		})
	})
	t.Run("encodes policy in memory", func(t *testing.T) {
		tester(t, testCase{
			cfg: Config{
				OverlayDirs: []string{overlay},
				Bouncers: map[string]*bouncercfg.Config{
					"github": {
						Listen: "127.0.0.1:8228",
						Dir:    overlay,
						Profiles: map[string]*bouncercfg.Profile{
							"default": {
								Filters: []bouncercfg.FilterRef{{Path: filter}},
							},
						},
					},
				},
				Contexts: map[string]ContextSpec{
					"pastdev": {
						Agent:   "cursor",
						Root:    t.TempDir(),
						Bouncer: "github",
					},
				},
			},
			name:       "pastdev",
			bouncer:    "github",
			home:       home,
			wantListen: "127.0.0.1:8228",
			wantTS:     "filters/deny.ts",
		})
	})
	t.Run("invalid policy", func(t *testing.T) {
		tester(t, testCase{
			cfg: Config{
				Bouncers: map[string]*bouncercfg.Config{
					"github": {
						Credentials: map[string]*bouncercfg.Credential{
							"gl": {Token: &bouncercfg.ValueSource{Source: "command"}},
						},
					},
				},
				Contexts: map[string]ContextSpec{
					"pastdev": {
						Agent:   "cursor",
						Root:    t.TempDir(),
						Bouncer: "github",
					},
				},
			},
			name:    "pastdev",
			bouncer: "github",
			wantErr: "source command requires command",
		})
	})
	t.Run("unions agent tunnel onto root profiles", func(t *testing.T) {
		doc := &bouncercfg.Config{
			Listen: "127.0.0.1:8228",
			Profiles: map[string]*bouncercfg.Profile{
				"default": {
					Unmatched: bouncercfg.UnmatchedDeny,
					Tunnel:    []string{"extra.example.com"},
				},
				"locked-down": {
					Extends:   "default",
					Unmatched: bouncercfg.UnmatchedDeny,
				},
			},
		}
		cfg := Config{
			Agents: map[string]AgentSpec{
				"cursor": {Image: "pastdev:latest", Tunnel: []string{"cursor.com", "*.cursor.sh"}},
			},
			Bouncers: map[string]*bouncercfg.Config{
				"github": doc,
			},
			Contexts: map[string]ContextSpec{
				"pastdev": {
					Agent:   "cursor",
					Root:    t.TempDir(),
					Bouncer: "github",
				},
			},
		}
		orig := append([]string{}, doc.Profiles["default"].Tunnel...)
		tester(t, testCase{
			cfg:     cfg,
			name:    "pastdev",
			bouncer: "github",
			agent:   cfg.Agents["cursor"],
			check: func(t *testing.T, setup *run.BouncerSetup, _ Config) {
				t.Helper()
				var policy bouncercfg.Config
				err := yaml.Unmarshal(setup.PolicyYAML, &policy)
				if err != nil {
					t.Fatal(err)
				}
				got := policy.Profiles["default"].Tunnel
				if !containsHost(got, "cursor.com") || !containsHost(got, "*.cursor.sh") || !containsHost(got, "extra.example.com") {
					t.Fatalf("root tunnel %v", got)
				}
				if containsHost(policy.Profiles["locked-down"].Tunnel, "cursor.com") {
					t.Fatalf("child should inherit, not copy: %v", policy.Profiles["locked-down"].Tunnel)
				}
				if !equalHosts(doc.Profiles["default"].Tunnel, orig) {
					t.Fatal("materialize mutated source tunnel")
				}
			},
		})
	})
	t.Run("uses the selected agent tunnel", func(t *testing.T) {
		cfg := Config{
			Agents: map[string]AgentSpec{
				"cursor": {Image: "pastdev:latest", Tunnel: []string{"cursor.com"}},
				"claude": {Image: "other:latest", Tunnel: []string{"api.anthropic.com"}},
			},
			Bouncers: map[string]*bouncercfg.Config{
				"github": {
					Listen: "127.0.0.1:8228",
					Profiles: map[string]*bouncercfg.Profile{
						"default": {Unmatched: bouncercfg.UnmatchedDeny},
					},
				},
			},
			Contexts: map[string]ContextSpec{
				"pastdev": {
					Agent:   "claude",
					Root:    t.TempDir(),
					Bouncer: "github",
				},
			},
		}
		tester(t, testCase{
			cfg:     cfg,
			name:    "pastdev",
			bouncer: "github",
			agent:   cfg.Agents["claude"],
			check: func(t *testing.T, setup *run.BouncerSetup, _ Config) {
				t.Helper()
				var policy bouncercfg.Config
				err := yaml.Unmarshal(setup.PolicyYAML, &policy)
				if err != nil {
					t.Fatal(err)
				}
				got := policy.Profiles["default"].Tunnel
				if containsHost(got, "cursor.com") {
					t.Fatalf("cursor hosts on claude agent: %v", got)
				}
				if !containsHost(got, "api.anthropic.com") {
					t.Fatalf("missing claude tunnel %v", got)
				}
			},
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
					"github": {
						Listen: "127.0.0.1:8228",
					},
				},
				Contexts: map[string]ContextSpec{
					"pastdev": {
						Agent:   "cursor",
						Root:    t.TempDir(),
						Bouncer: "github",
					},
				},
			},
			name:       "pastdev",
			wantListen: "127.0.0.1:8228",
			wantTS:     "filters/deny.ts",
		})
	})
	t.Run("without section", func(t *testing.T) {
		tester(t, testCase{
			cfg: Config{
				Contexts: map[string]ContextSpec{
					"pastdev": {Agent: "cursor", Root: t.TempDir()},
				},
			},
			name:      "pastdev",
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
		err := os.WriteFile(path, []byte("listen: 127.0.0.1:8228\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			path:       path,
			wantListen: "127.0.0.1:8228",
		})
	})
	t.Run("loads directory", func(t *testing.T) {
		dir := t.TempDir()
		err := os.WriteFile(filepath.Join(dir, bouncercfg.FileName), []byte("listen: 127.0.0.1:8228\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			path:       dir,
			wantListen: "127.0.0.1:8228",
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
	type testCase struct {
		home string
		name string
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := BouncerLayoutDir(tc.home, tc.name)
		if got != tc.want {
			t.Fatalf("got %q, want %q", got, tc.want)
		}
	}

	t.Run("joins state under home", func(t *testing.T) {
		tester(t, testCase{
			home: "/home/me",
			name: "pastdev",
			want: filepath.Join("/home/me", ".local", "state", "agentcon", "pastdev", "bouncer"),
		})
	})
}
