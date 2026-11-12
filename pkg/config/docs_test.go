package config

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/pastdev/agentcon/pkg/bouncertest"
	cfgldr "github.com/pastdev/configloader/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDocsExamples runs the tests of every bouncer example under
// docs/bouncer, each loaded alone as an agentcon.d overlay.
func TestDocsExamples(t *testing.T) {
	type testCase struct {
		dir string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		var cfg Config
		err := cfgldr.Sources[Config]{
			Sources: []cfgldr.SourceLoader{cfgldr.DirSource{Path: tc.dir, Unmarshal: valueTemplateUnmarshal()}},
		}.Load(&cfg)
		require.NoError(t, err)
		cfg.OverlayDirs = []string{resolveOverlayDir(tc.dir)}

		var contexts []string
		for name, spec := range cfg.Contexts {
			if spec.Bouncer != "" {
				contexts = append(contexts, name)
			}
		}
		sort.Strings(contexts)
		require.NotEmpty(t, contexts, "contexts with a bouncer")
		for _, name := range contexts {
			t.Run(name, func(t *testing.T) {
				suite, err := cfg.BouncerTests(name)
				require.NoError(t, err)
				report, err := bouncertest.Run(suite, t.TempDir())
				require.NoError(t, err)
				require.NotEmpty(t, report.Specs, "specs under %s", suite.TestsDir)
				for _, spec := range report.Specs {
					t.Run(spec.Path, func(t *testing.T) {
						require.NoError(t, spec.Err)
						for _, r := range spec.Results {
							t.Run(r.Name, func(t *testing.T) {
								assert.True(t, r.Passed, "step %s: %s\n%s", r.StepName, r.Message, r.FilterLog)
							})
						}
					})
				}
			})
		}
	}

	dirs, err := filepath.Glob(filepath.Join("..", "..", "docs", "bouncer", "*"))
	require.NoError(t, err)
	require.NotEmpty(t, dirs)
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			tester(t, testCase{dir: dir})
		})
	}
}
