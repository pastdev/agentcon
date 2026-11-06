package config

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// FileName is the policy file in a folder-layer directory.
	FileName = "config.yaml"
	// TSDir is the template and node_modules tree next to FileName.
	TSDir = "ts"
)

// FS is a destination for WriteLayout.
type FS interface {
	WriteFile(name string, data []byte, perm os.FileMode) error
}

type dirFS struct {
	root string
}

type prefixFS struct {
	fs     FS
	prefix string
}

// DirFS writes layout files under root.
func DirFS(root string) FS {
	return dirFS{root: root}
}

// Prefix writes layout files under prefix on fs.
func Prefix(fs FS, prefix string) FS {
	return prefixFS{fs: fs, prefix: prefix}
}

// LoadDir loads the folder-layer layout from dir.
func LoadDir(dir string) (*Config, error) {
	return Load(filepath.Join(dir, FileName))
}

// WriteLayout writes policy YAML and a ts/ tree onto dest.
// tsFiles maps paths relative to ts/ onto host files to copy.
func WriteLayout(dest FS, policy []byte, tsFiles map[string]string) error {
	err := dest.WriteFile(FileName, policy, 0o644)
	if err != nil {
		return fmt.Errorf("write %s: %w", FileName, err)
	}
	for rel, abs := range tsFiles {
		name, ok := layoutTSName(rel)
		if !ok {
			continue
		}
		//nolint:gosec // packing host overlay files the caller selected
		data, err := os.ReadFile(abs)
		if err != nil {
			return fmt.Errorf("read %s: %w", abs, err)
		}
		err = dest.WriteFile(name, data, 0o644)
		if err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// CollectTSFiles walks overlay dirs and returns the winning file for each
// path under ts/. Later overlays overwrite earlier ones.
func CollectTSFiles(overlayDirs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, dir := range overlayDirs {
		src := filepath.Join(dir, TSDir)
		info, err := os.Stat(src)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			continue
		}
		err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(src, p)
			if err != nil {
				return fmt.Errorf("relative path: %w", err)
			}
			out[filepath.ToSlash(rel)] = p
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk ts %s: %w", src, err)
		}
	}
	return out, nil
}

// RewriteTSPaths rewrites absolute overlay ts/ prefixes in policy YAML to
// the folder-layer relative path "ts".
func RewriteTSPaths(policy []byte, overlayDirs []string) []byte {
	text := string(policy)
	for _, prefix := range tsPrefixes(overlayDirs) {
		text = strings.ReplaceAll(text, prefix, TSDir)
	}
	return []byte(text)
}

func (d dirFS) WriteFile(name string, data []byte, perm os.FileMode) error {
	dest, err := layoutPath(d.root, name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(filepath.Dir(dest), 0o700)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dest), err)
	}
	err = os.WriteFile(dest, data, perm)
	if err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}

func (p prefixFS) WriteFile(name string, data []byte, perm os.FileMode) error {
	err := p.fs.WriteFile(path.Join(p.prefix, name), data, perm)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func layoutPath(root, name string) (string, error) {
	cleaned := path.Clean("/" + filepath.ToSlash(name))
	if cleaned == "/" || strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("invalid layout path %q", name)
	}
	rel := filepath.FromSlash(cleaned[1:])
	dest := filepath.Join(root, rel)
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("layout root: %w", err)
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", fmt.Errorf("layout path: %w", err)
	}
	sep := string(filepath.Separator)
	if absDest != absRoot && !strings.HasPrefix(absDest, absRoot+sep) {
		return "", fmt.Errorf("layout path %q escapes %s", name, root)
	}
	return absDest, nil
}

func layoutTSName(rel string) (string, bool) {
	cleaned := path.Clean("/" + filepath.ToSlash(rel))
	if cleaned == "/" || strings.Contains(cleaned, "..") {
		return "", false
	}
	rel = cleaned[1:]
	if rel == "" || rel == "." {
		return "", false
	}
	return path.Join(TSDir, rel), true
}

func tsPrefixes(overlayDirs []string) []string {
	seen := map[string]bool{}
	var prefixes []string
	for _, dir := range overlayDirs {
		ts := filepath.Join(dir, TSDir)
		abs, err := filepath.Abs(ts)
		if err != nil {
			continue
		}
		for _, prefix := range []string{abs, filepath.ToSlash(abs)} {
			if prefix == "" || seen[prefix] {
				continue
			}
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i]) > len(prefixes[j])
	})
	return prefixes
}
