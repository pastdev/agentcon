package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func expandHomePath(p, home string) string {
	if p == "" {
		return p
	}
	if p == "~" {
		return filepath.Clean(home)
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Clean(filepath.Join(home, p[2:]))
	}
	return p
}

func resolveMountSource(p, home string) string {
	p = expandHomePath(p, home)
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(home, p))
}

func resolveConfigDir(p, home string, overlayDirs []string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path is required")
	}
	expanded := expandHomePath(p, home)
	if filepath.IsAbs(expanded) {
		info, err := os.Stat(expanded)
		if err != nil {
			return "", fmt.Errorf("path %q: %w", p, err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("path %q is not a directory", expanded)
		}
		return filepath.Clean(expanded), nil
	}

	var found string
	for _, dir := range overlayDirs {
		cand := filepath.Clean(filepath.Join(dir, expanded))
		info, err := os.Stat(cand)
		if err != nil || !info.IsDir() {
			continue
		}
		found = cand
	}
	if found == "" {
		return "", fmt.Errorf("path %q not found in config directories", p)
	}
	return found, nil
}
