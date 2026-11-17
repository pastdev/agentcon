// Package mgmtdial finds a bouncer that agentcon started, from its state
// directory or its running records, and returns a management client for it.
package mgmtdial

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/running"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
)

// cliTimeout allows for slow calls such as a reload that compiles filters.
const cliTimeout = 30 * time.Second

// DialContext prefers a matching running record, then Dial(stateDir, configPath).
func DialContext(home string, q running.Query, stateDir, configPath string) (*mgmt.Client, error) {
	if home != "" {
		rec, err := running.Find(home, q)
		if err == nil {
			return mgmt.New("http://"+rec.ControlAddr, rec.Token, mgmt.WithTimeout(cliTimeout)), nil
		}
		var amb *running.AmbiguousError
		if errors.As(err, &amb) || (stateDir == "" && configPath == "") {
			return nil, fmt.Errorf("find session: %w", err)
		}
	}
	return Dial(stateDir, configPath)
}

// Dial locates a running daemon from stateDir (host.json, daemon.json) and
// requires an admin token on disk.
func Dial(stateDir, _ string) (*mgmt.Client, error) {
	addr, err := locate(stateDir)
	if err != nil {
		return nil, err
	}
	tok, err := os.ReadFile(daemon.AdminTokenPath(stateDir))
	if err != nil {
		return nil, fmt.Errorf("reading admin token (has `agentcon bouncer serve` run yet?): %w", err)
	}
	return mgmt.New("http://"+addr, strings.TrimSpace(string(tok)), mgmt.WithTimeout(cliTimeout)), nil
}

func locate(stateDir string) (string, error) {
	if b, err := os.ReadFile(filepath.Join(stateDir, "host.json")); err == nil { //nolint:gosec // path from operator config or the state dir, not the agent
		var host struct {
			ControlAddr string `json:"control_addr"`
		}
		if json.Unmarshal(b, &host) == nil && host.ControlAddr != "" {
			return host.ControlAddr, nil
		}
	}
	var rt daemon.Runtime
	if b, err := os.ReadFile(daemon.RuntimePath(stateDir)); err == nil && json.Unmarshal(b, &rt) == nil {
		if rt.MgmtAddr != "" {
			return rt.MgmtAddr, nil
		}
		if rt.ProxyAddr != "" {
			return rt.ProxyAddr, nil
		}
	}
	return "", fmt.Errorf("bouncer doesn't appear to be running (no %s)", daemon.RuntimePath(stateDir))
}
