package run

import (
	"archive/tar"
	"bytes"
	"fmt"
	"path/filepath"
)

func tarFiles(files map[string][]byte, modes map[string]int64, uid, gid int) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	seenDir := map[string]bool{}
	for name, data := range files {
		err := writeTarDirs(tw, name, seenDir, uid, gid)
		if err != nil {
			return nil, err
		}
		mode := int64(0o644)
		if modes != nil && modes[name] != 0 {
			mode = modes[name]
		}
		err = tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: mode,
			Size: int64(len(data)),
			Uid:  uid,
			Gid:  gid,
		})
		if err != nil {
			return nil, fmt.Errorf("tar header %s: %w", name, err)
		}
		_, err = tw.Write(data)
		if err != nil {
			return nil, fmt.Errorf("tar write %s: %w", name, err)
		}
	}
	err := tw.Close()
	if err != nil {
		return nil, fmt.Errorf("tar close: %w", err)
	}
	return buf, nil
}

func writeTarDirs(tw *tar.Writer, name string, seen map[string]bool, uid, gid int) error {
	dir := filepath.ToSlash(filepath.Dir(name))
	if dir == "." || dir == "/" {
		return nil
	}
	var parts []string
	rest := dir
	for rest != "." && rest != "/" {
		parts = append([]string{rest}, parts...)
		rest = filepath.ToSlash(filepath.Dir(rest))
	}
	for _, d := range parts {
		if seen[d] {
			continue
		}
		seen[d] = true
		err := tw.WriteHeader(&tar.Header{
			Name:     d + "/",
			Mode:     0o755,
			Typeflag: tar.TypeDir,
			Uid:      uid,
			Gid:      gid,
		})
		if err != nil {
			return fmt.Errorf("tar dir %s: %w", d, err)
		}
	}
	return nil
}
