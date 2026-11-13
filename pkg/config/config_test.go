package config

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoader(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		loader := NewLoader()
		cfg, err := loader.Config()
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Empty(t, cfg.Agents)
	}

	t.Run("returns an empty config", func(t *testing.T) {
		tester(t)
	})
}

func TestLoaderOverlayDirs(t *testing.T) {
	type testCase struct {
		args []string
		want func(xdg, flagDir string) []string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		xdg := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", xdg)
		flagDir := t.TempDir()
		args := make([]string, 0, len(tc.args))
		for _, a := range tc.args {
			if a == "FLAGDIR" {
				a = flagDir
			}
			if a == "FLAGFILE" {
				a = filepath.Join(flagDir, "agentcon.yaml")
			}
			args = append(args, a)
		}

		loader := NewLoader()
		var got []string
		root := &cobra.Command{
			Use: "agentcon",
			RunE: func(_ *cobra.Command, _ []string) error {
				cfg, err := loader.Config()
				if err != nil {
					return err
				}
				got = cfg.OverlayDirs
				return nil
			},
		}
		loader.AddFlags(root)
		root.SetArgs(args)
		err := root.Execute()
		require.NoError(t, err)
		assert.Equal(t, tc.want(xdg, flagDir), got)
	}

	t.Run("no flags uses the default dirs", func(t *testing.T) {
		tester(t, testCase{
			want: func(xdg, _ string) []string {
				return []string{
					SystemConfigDir,
					filepath.Join(xdg, "agentcon.d"),
					resolveOverlayDir(DirectoryConfigDir),
				}
			},
		})
	})
	t.Run("config dir replaces the default dirs", func(t *testing.T) {
		tester(t, testCase{
			args: []string{"-d", "FLAGDIR"},
			want: func(_, flagDir string) []string { return []string{flagDir} },
		})
	})
	t.Run("config file uses its dir", func(t *testing.T) {
		tester(t, testCase{
			args: []string{"-c", "FLAGFILE"},
			want: func(_, flagDir string) []string { return []string{flagDir} },
		})
	})
}
