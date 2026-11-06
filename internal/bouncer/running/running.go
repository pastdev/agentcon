// Package running stores host discovery records for a live bouncer.
package running

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Record is ~/.local/state/agentcon/running/<context>.yml.
type Record struct {
	Context     string    `yaml:"context"`
	ControlAddr string    `yaml:"control_addr"`
	Token       string    `yaml:"token"`
	ContainerID string    `yaml:"container_id,omitempty"`
	PID         int       `yaml:"pid"`
	Started     time.Time `yaml:"started"`
}

// Dir is the directory that holds running records for a user home.
func Dir(home string) string {
	return filepath.Join(home, ".local", "state", "agentcon", "running")
}

// FileName is the sanitized context used as the record basename (no extension).
func FileName(context string) string {
	out := strings.Builder{}
	for _, r := range strings.ToLower(context) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out.WriteRune(r)
			continue
		}
		out.WriteByte('-')
	}
	s := strings.Trim(out.String(), "-")
	if s == "" {
		return "ctx"
	}
	return s
}

// Path is the discovery file for context.
func Path(home, context string) string {
	return filepath.Join(Dir(home), FileName(context)+".yml")
}

// Write creates or replaces the discovery file. Mode 0600, directory 0700.
func Write(home string, rec Record) error {
	if rec.Context == "" {
		return fmt.Errorf("running record: context is required")
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
	err = os.WriteFile(Path(home, rec.Context), data, 0o600)
	if err != nil {
		return fmt.Errorf("write running record: %w", err)
	}
	return nil
}

// Read loads the discovery file for context.
func Read(home, context string) (Record, error) {
	var rec Record
	data, err := os.ReadFile(Path(home, context))
	if err != nil {
		return Record{}, fmt.Errorf("read running record: %w", err)
	}
	err = yaml.Unmarshal(data, &rec)
	if err != nil {
		return Record{}, fmt.Errorf("parse running record: %w", err)
	}
	if rec.ControlAddr == "" || rec.Token == "" {
		return Record{}, fmt.Errorf("running record %s is missing control_addr or token", Path(home, context))
	}
	return rec, nil
}

// Remove deletes the discovery file. Missing files are ignored.
func Remove(home, context string) error {
	err := os.Remove(Path(home, context))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove running record: %w", err)
	}
	return nil
}
