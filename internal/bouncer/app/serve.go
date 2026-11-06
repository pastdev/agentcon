// Package app is the service layer for the bouncer CLI and other UIs.
package app

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/audit"
	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/running"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// ServeOptions configure a local `bouncer serve` process.
type ServeOptions struct {
	ConfigPath  string
	StateDir    string
	Context     string
	Home        string
	Provided    map[string]string
	Quiet       bool
	ShowTunnels bool
	Log         io.Writer
	Stdin       io.Reader
	Stderr      io.Writer
	Interactive bool
	Load        func() (*config.Config, error)
}

// Serve runs the daemon until ctx is cancelled.
func Serve(ctx context.Context, opts ServeOptions) error {
	if opts.ConfigPath == "" {
		return fmt.Errorf("no bouncer policy: set contexts.<name>.bouncer or pass --file")
	}
	logw := opts.Log
	if logw == nil {
		logw = os.Stderr
	}
	logger := log.New(logw, "", log.Ltime)
	d, err := daemon.New(daemon.Options{
		Provided:   opts.Provided,
		ConfigPath: opts.ConfigPath,
		StateDir:   opts.StateDir,
		Load:       opts.Load,
		Logf:       logger.Printf,
		Decision: func(e audit.Entry) {
			if opts.Quiet || (e.Decision == "tunnel" && !opts.ShowTunnels) {
				return
			}
			logger.Print(FormatDecision(e))
		},
	})
	if err != nil {
		return err
	}
	cfg := d.Config()
	logger.Printf("config %s", cfg.Path)
	logger.Printf("CA certificate %s", d.CA.CertPath())
	if cfg.Approvals.TerminalEnabled() && opts.Interactive {
		in, out := opts.Stdin, opts.Stderr
		if in == nil {
			in = os.Stdin
		}
		if out == nil {
			out = os.Stderr
		}
		go d.RunTerminalApprover(in, out)
	} else if cfg.Approvals.CLIEnabled() {
		logger.Printf("answer approvals with `agentcon bouncer approvals` / `agentcon bouncer approve <id>`")
	}
	if opts.Context != "" && opts.Home != "" {
		token, err := os.ReadFile(daemon.AdminTokenPath(opts.StateDir))
		if err != nil {
			return fmt.Errorf("read admin token: %w", err)
		}
		err = running.Write(opts.Home, running.Record{
			Context:     opts.Context,
			ControlAddr: strings.TrimPrefix(cfg.Listen, "http://"),
			Token:       strings.TrimSpace(string(token)),
			PID:         os.Getpid(),
			Started:     time.Now().UTC().Truncate(time.Second),
		})
		if err != nil {
			return fmt.Errorf("write running record: %w", err)
		}
		defer func() { _ = running.Remove(opts.Home, opts.Context) }()
	}
	return d.Run(ctx)
}

// FormatDecision is the one-line serve log for an audit entry.
func FormatDecision(e audit.Entry) string {
	who := e.Label
	if who == "" {
		who = e.Session
	}
	s := fmt.Sprintf("%-6s [%s] %s", strings.ToUpper(e.Decision), who, e.Request)
	if e.Status != 0 && e.Decision == "allow" {
		s += fmt.Sprintf(" -> %d", e.Status)
	}
	switch {
	case e.Decision == "deny" || e.Decision == "error":
		s += fmt.Sprintf("  (%s: %s)", e.By, e.Reason)
	case e.By != "":
		s += fmt.Sprintf("  (%s)", e.By)
	}
	return s
}
