// Package harness holds builtin harness metadata.
// Add a harness by creating <name>/default.yml with a harnesses.<name> block.
package harness

import (
	"embed"
	"io/fs"
	"sort"
)

const Cursor = "cursor"

//go:embed */default.yml
var defaults embed.FS

// DefaultYAML returns each embedded harness document, sorted by path.
// Each document is an agentcon config fragment under harnesses.<name>.
func DefaultYAML() [][]byte {
	matches, err := fs.Glob(defaults, "*/default.yml")
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	out := make([][]byte, 0, len(matches))
	for _, name := range matches {
		data, err := defaults.ReadFile(name)
		if err != nil {
			continue
		}
		out = append(out, data)
	}
	return out
}
