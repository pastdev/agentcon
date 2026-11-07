// Package running stores host discovery records for live agentcon sessions.
package running

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// SlugLength is the hex length of a session id.
	SlugLength  = 8
	namePrefix  = "agentcon-"
	maxNameLen  = 63
	longestRole = "bouncer"
)

// Record is ~/.local/state/agentcon/running/<slug>.yml.
type Record struct {
	Context     string    `yaml:"context"`
	Project     string    `yaml:"project,omitempty"`
	Slug        string    `yaml:"slug"`
	Cwd         string    `yaml:"cwd,omitempty"`
	ControlAddr string    `yaml:"control_addr"`
	Token       string    `yaml:"token"`
	ContainerID string    `yaml:"container_id,omitempty"`
	PID         int       `yaml:"pid"`
	Started     time.Time `yaml:"started"`
}

// Query selects a running session from host discovery records.
type Query struct {
	Context string
	Project string
	Slug    string
	Cwd     string
}

// Dir is the directory that holds running records for a user home.
func Dir(home string) string {
	return filepath.Join(home, ".local", "state", "agentcon", "running")
}

// FileName is a docker-safe token from a context or project path.
func FileName(name string) string {
	out := strings.Builder{}
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out.WriteRune(r)
			continue
		}
		out.WriteByte('-')
	}
	s := strings.Trim(out.String(), "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if s == "" {
		return "ctx"
	}
	return s
}

// Path is the discovery file for a session slug.
func Path(home, slug string) string {
	return filepath.Join(Dir(home), slug+".yml")
}

// NewSlug returns an 8-character hex session id.
func NewSlug() string {
	b := make([]byte, SlugLength/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ValidSlug reports whether s is an 8-character lowercase hex session id.
func ValidSlug(s string) bool {
	if len(s) != SlugLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ProjectPath is cwd relative to the context root, slash-separated.
// The context root itself is "".
func ProjectPath(root, cwd string) string {
	if root == "" || cwd == "" {
		return ""
	}
	rel, err := filepath.Rel(root, cwd)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	return filepath.ToSlash(rel)
}

func boundedMax() int {
	return maxNameLen - len(namePrefix) - 1 - SlugLength - 1 - len(longestRole)
}

// BoundedName is the project path as a docker-safe token, left-truncated
// so ResourceName stays within 63 characters.
func BoundedName(project string) string {
	s := FileName(project)
	if project == "" {
		s = "root"
	}
	max := boundedMax()
	if len(s) <= max {
		return s
	}
	s = strings.TrimLeft(s[len(s)-max:], "-")
	if s == "" {
		return "root"
	}
	return s
}

// ResourceName is agentcon-<bounded>-<slug>-<role>, at most 63 characters.
func ResourceName(project, slug, role string) string {
	return namePrefix + BoundedName(project) + "-" + slug + "-" + role
}

// Write creates or replaces the discovery file. Mode 0600, directory 0700.
func Write(home string, rec Record) error {
	if rec.Slug == "" {
		return fmt.Errorf("running record: slug is required")
	}
	if !ValidSlug(rec.Slug) {
		return fmt.Errorf("running record: slug %q must be %d hex characters", rec.Slug, SlugLength)
	}
	if rec.ControlAddr == "" || rec.Token == "" {
		return fmt.Errorf("running record: control_addr and token are required")
	}
	dir := Dir(home)
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return fmt.Errorf("create running dir: %w", err)
	}
	data, err := yaml.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode running record: %w", err)
	}
	err = os.WriteFile(Path(home, rec.Slug), data, 0o600)
	if err != nil {
		return fmt.Errorf("write running record: %w", err)
	}
	return nil
}

// Read loads the discovery file for a session slug.
func Read(home, slug string) (Record, error) {
	var rec Record
	data, err := os.ReadFile(Path(home, slug))
	if err != nil {
		return Record{}, fmt.Errorf("read running record: %w", err)
	}
	err = yaml.Unmarshal(data, &rec)
	if err != nil {
		return Record{}, fmt.Errorf("parse running record: %w", err)
	}
	if rec.ControlAddr == "" || rec.Token == "" {
		return Record{}, fmt.Errorf("running record %s is missing control_addr or token", Path(home, slug))
	}
	if rec.Slug == "" {
		rec.Slug = slug
	}
	return rec, nil
}

// List returns every valid running record under home.
func List(home string) ([]Record, error) {
	entries, err := os.ReadDir(Dir(home))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list running records: %w", err)
	}
	var out []Record
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		slug := strings.TrimSuffix(e.Name(), ".yml")
		rec, err := Read(home, slug)
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// Remove deletes the discovery file for a session slug. Missing files are ignored.
func Remove(home, slug string) error {
	err := os.Remove(Path(home, slug))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove running record: %w", err)
	}
	return nil
}

// Find selects a running record. See Query for the match order.
func Find(home string, q Query) (Record, error) {
	all, err := List(home)
	if err != nil {
		return Record{}, err
	}
	return Match(all, q)
}

// Match filters records. --slug wins, then --project, then cwd prefix,
// then the only remaining record after --context.
func Match(all []Record, q Query) (Record, error) {
	if q.Slug != "" {
		slug := strings.ToLower(q.Slug)
		var hit []Record
		for _, rec := range all {
			if rec.Slug == slug {
				hit = append(hit, rec)
			}
		}
		return one(hit, q)
	}
	filtered := all
	if q.Context != "" {
		filtered = nil
		for _, rec := range all {
			if rec.Context == q.Context {
				filtered = append(filtered, rec)
			}
		}
	}
	if q.Project != "" {
		project := strings.Trim(strings.ReplaceAll(q.Project, "\\", "/"), "/")
		var hit []Record
		for _, rec := range filtered {
			if rec.Project == project {
				hit = append(hit, rec)
			}
		}
		return one(hit, q)
	}
	if q.Cwd != "" {
		cwd, err := filepath.Abs(q.Cwd)
		if err != nil {
			return Record{}, fmt.Errorf("resolve cwd: %w", err)
		}
		var hit []Record
		best := 0
		for _, rec := range filtered {
			n := cwdMatch(cwd, rec)
			if n == 0 {
				continue
			}
			if n > best {
				hit = []Record{rec}
				best = n
			} else if n == best {
				hit = append(hit, rec)
			}
		}
		if len(hit) > 0 {
			return one(hit, q)
		}
	}
	return one(filtered, q)
}

func cwdMatch(cwd string, rec Record) int {
	if rec.Cwd == "" {
		return 0
	}
	base, err := filepath.Abs(rec.Cwd)
	if err != nil {
		return 0
	}
	if cwd == base {
		return len(base)
	}
	rel, err := filepath.Rel(base, cwd)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return 0
	}
	return len(base)
}

func one(hit []Record, q Query) (Record, error) {
	switch len(hit) {
	case 1:
		return hit[0], nil
	case 0:
		return Record{}, fmt.Errorf("no running agentcon session matches%s", hint(q))
	default:
		return Record{}, &AmbiguousError{Records: hit}
	}
}

func hint(q Query) string {
	var parts []string
	if q.Slug != "" {
		parts = append(parts, "slug "+q.Slug)
	}
	if q.Project != "" {
		parts = append(parts, "project "+q.Project)
	}
	if q.Context != "" {
		parts = append(parts, "context "+q.Context)
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// AmbiguousError means more than one session matched.
type AmbiguousError struct {
	Records []Record
}

func (e *AmbiguousError) Error() string {
	var b strings.Builder
	b.WriteString("several agentcon sessions match; pass --slug or --project:\n")
	for _, rec := range e.Records {
		project := rec.Project
		if project == "" {
			project = "."
		}
		fmt.Fprintf(&b, "  %s  %s  %s\n", rec.Slug, rec.Context, project)
	}
	return strings.TrimRight(b.String(), "\n")
}
