// Package urlfile provides a config template function that downloads a file
// once and serves it from a local cache until it is older than a TTL.
package urlfile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pastdev/agentcon/pkg/log"
)

const (
	// DefaultTTL is how long a cached file is used before it is refetched.
	DefaultTTL = 24 * time.Hour
	// DefaultTimeout bounds a single download.
	DefaultTimeout = 30 * time.Second
)

// Cache downloads files into Dir, one directory per URL.
type Cache struct {
	Dir    string
	Client *http.Client
}

// New returns a Cache that stores files under dir.
func New(dir string) *Cache {
	return &Cache{
		Dir:    dir,
		Client: &http.Client{Timeout: DefaultTimeout},
	}
}

// AddFuncs adds urlFile to funcs.
func (c *Cache) AddFuncs(funcs map[string]any) {
	funcs["urlFile"] = c.File
}

// File returns the path of a local copy of rawURL named name. The copy is
// downloaded when it is missing or older than ttl, which defaults to
// DefaultTTL. When a refetch fails and an older copy exists, that copy is
// used and a warning is logged.
func (c *Cache) File(rawURL string, name string, ttl ...string) (string, error) {
	maxAge, err := parseTTL(ttl)
	if err != nil {
		return "", fmt.Errorf("urlFile %s: %w", rawURL, err)
	}
	err = validate(rawURL, name)
	if err != nil {
		return "", fmt.Errorf("urlFile %s: %w", rawURL, err)
	}
	if c.Dir == "" {
		return "", fmt.Errorf("urlFile %s: no cache directory", rawURL)
	}

	sum := sha256.Sum256([]byte(rawURL))
	dir := filepath.Join(c.Dir, hex.EncodeToString(sum[:]))
	path := filepath.Join(dir, name)

	info, statErr := os.Stat(path)
	if statErr == nil && time.Since(info.ModTime()) < maxAge {
		return path, nil
	}

	err = c.download(rawURL, dir, path)
	if err != nil {
		if statErr == nil {
			log.Warn().Err(err).Str("url", rawURL).Str("path", path).
				Msg("urlFile refetch failed, using cached copy")
			return path, nil
		}
		return "", fmt.Errorf("urlFile %s: %w", rawURL, err)
	}
	return path, nil
}

func parseTTL(ttl []string) (time.Duration, error) {
	switch len(ttl) {
	case 0:
		return DefaultTTL, nil
	case 1:
		d, err := time.ParseDuration(ttl[0])
		if err != nil {
			return 0, fmt.Errorf("ttl: %w", err)
		}
		if d < 0 {
			return 0, fmt.Errorf("ttl %s: negative", ttl[0])
		}
		return d, nil
	default:
		return 0, errors.New("want url, name, and an optional ttl")
	}
}

func validate(rawURL string, name string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("url must be https")
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("name %q must be a plain file name", name)
	}
	return nil
}

// download writes rawURL to path through a temporary file in dir, so path is
// either absent or a complete download.
func (c *Cache) download(rawURL string, dir string, path string) error {
	resp, err := c.Client.Get(rawURL)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("get: %s", resp.Status)
	}

	err = os.MkdirAll(dir, 0o700)
	if err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	_, err = io.Copy(tmp, resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	err = tmp.Sync()
	if err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	err = tmp.Close()
	if err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	err = os.Rename(tmp.Name(), path)
	if err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	renamed = true
	return nil
}
