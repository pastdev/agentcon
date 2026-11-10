package config

import (
	"os"
	"path/filepath"
	"testing"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/run"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		if tc.wantNil {
			assert.Nil(t, setup)
			return
		}
		require.NotNil(t, setup)
		if tc.wantListen != "" {
			assert.Contains(t, string(setup.PolicyYAML), tc.wantListen)
		}
		if tc.wantTS != "" {
			assert.Contains(t, setup.TSFiles, tc.wantTS)
			assert.NotContains(t, string(setup.PolicyYAML), tc.cfg.OverlayDirs[0], "host overlay leaked")
		}
		if tc.home != "" {
			_, err := os.Stat(filepath.Join(tc.home, ".local", "state", "agentcon"))
			require.ErrorIs(t, err, os.ErrNotExist, "materialize should not write host state")
		}
		if tc.check != nil {
			tc.check(t, setup, tc.cfg)
		}
	}

	overlay := t.TempDir()
	err := os.MkdirAll(filepath.Join(overlay, bouncercfg.TSDir, "filters"), 0o700)
	require.NoError(t, err)
	filter := filepath.Join(overlay, bouncercfg.TSDir, "filters", "deny.ts")
	err = os.WriteFile(filter, []byte("export {}\n"), 0o600)
	require.NoError(t, err)
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
				require.NoError(t, err)
				assert.Subset(t, policy.Profiles["default"].Tunnel, []string{"cursor.com", "*.cursor.sh", "extra.example.com"})
				assert.NotContains(t, policy.Profiles["locked-down"].Tunnel, "cursor.com", "child should inherit, not copy")
				assert.Equal(t, orig, doc.Profiles["default"].Tunnel, "materialize mutated source tunnel")
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
				require.NoError(t, err)
				got := policy.Profiles["default"].Tunnel
				assert.NotContains(t, got, "cursor.com")
				assert.Contains(t, got, "api.anthropic.com")
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
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		if tc.wantEmpty {
			assert.Empty(t, got)
			return
		}
		require.Equal(t, filepath.Join(dir, bouncercfg.FileName), got)
		//nolint:gosec // test fixture written to TempDir
		data, err := os.ReadFile(got)
		require.NoError(t, err)
		assert.Contains(t, string(data), tc.wantListen)
		if tc.wantTS == "" {
			return
		}
		assert.FileExists(t, filepath.Join(dir, bouncercfg.TSDir, tc.wantTS))
	}

	overlay := t.TempDir()
	err := os.MkdirAll(filepath.Join(overlay, bouncercfg.TSDir, "filters"), 0o700)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(overlay, bouncercfg.TSDir, "filters", "deny.ts"), []byte("export {}\n"), 0o600)
	require.NoError(t, err)

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
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.wantListen, got.Listen)
	}

	t.Run("loads file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.yaml")
		err := os.WriteFile(path, []byte("listen: 127.0.0.1:8228\n"), 0o600)
		require.NoError(t, err)
		tester(t, testCase{
			path:       path,
			wantListen: "127.0.0.1:8228",
		})
	})
	t.Run("loads directory", func(t *testing.T) {
		dir := t.TempDir()
		err := os.WriteFile(filepath.Join(dir, bouncercfg.FileName), []byte("listen: 127.0.0.1:8228\n"), 0o600)
		require.NoError(t, err)
		tester(t, testCase{
			path:       dir,
			wantListen: "127.0.0.1:8228",
		})
	})
	t.Run("invalid policy", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.yaml")
		err := os.WriteFile(path, []byte("credentials:\n  gl:\n    token:\n      source: command\n"), 0o600)
		require.NoError(t, err)
		tester(t, testCase{
			path:    path,
			wantErr: "source command requires command",
		})
	})
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
		assert.Equal(t, tc.want, got)
	}

	t.Run("joins state under home", func(t *testing.T) {
		tester(t, testCase{
			home: "/home/me",
			name: "pastdev",
			want: filepath.Join("/home/me", ".local", "state", "agentcon", "pastdev", "bouncer"),
		})
	})
}
