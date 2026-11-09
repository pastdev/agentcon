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
	Project     string
	Slug        string
	Cwd         string
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
			if opts.Quiet || (e.Decision == audit.DecisionTunnel && !opts.ShowTunnels) {
				return
			}
			logger.Print(FormatDecision(e))
		},
	})
	if err != nil {
		return fmt.Errorf("daemon setup: %w", err)
	}
	cfg := d.Config()
	logger.Printf("config %s", cfg.Path)
	logger.Printf("CA certificate %s", d.CA.CertPath())
	if cfg.Prompts.TerminalEnabled() && opts.Interactive {
		in, out := opts.Stdin, opts.Stderr
		if in == nil {
			in = os.Stdin
		}
		if out == nil {
			out = os.Stderr
		}
		go d.RunTerminalApprover(in, out)
	} else if cfg.Prompts.CLIEnabled() {
		logger.Printf("answer prompts with `agentcon bouncer prompts` / `agentcon bouncer answer <id>`")
	}
	if opts.Context != "" && opts.Home != "" {
		token, err := os.ReadFile(daemon.AdminTokenPath(opts.StateDir))
		if err != nil {
			return fmt.Errorf("read admin token: %w", err)
		}
		slug := strings.ToLower(opts.Slug)
		if slug == "" {
			slug = running.NewSlug()
		} else if !running.ValidSlug(slug) {
			return fmt.Errorf("slug %q must be %d hex characters", opts.Slug, running.SlugLength)
		}
		err = running.Write(opts.Home, running.Record{
			Context:     opts.Context,
			Project:     opts.Project,
			Slug:        slug,
			Cwd:         opts.Cwd,
			ControlAddr: strings.TrimPrefix(cfg.Listen, "http://"),
			Token:       strings.TrimSpace(string(token)),
			PID:         os.Getpid(),
			Started:     time.Now().UTC().Truncate(time.Second),
		})
		if err != nil {
			return fmt.Errorf("write running record: %w", err)
		}
		logger.Printf("session %s", slug)
		defer func() { _ = running.Remove(opts.Home, slug) }()
	}
	err = d.Run(ctx)
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	return nil
}

// FormatDecision is the one-line serve log for an audit entry.
func FormatDecision(e audit.Entry) string {
	who := e.Label
	if who == "" {
		who = e.Session
	}
	s := fmt.Sprintf("%-6s [%s] %s", strings.ToUpper(e.Decision), who, e.Request)
	if e.Status != 0 && e.Decision == audit.DecisionAllow {
		s += fmt.Sprintf(" -> %d", e.Status)
	}
	switch {
	case e.Decision == audit.DecisionDeny || e.Decision == audit.DecisionError:
		s += fmt.Sprintf("  (%s: %s)", e.By, e.Reason)
	case e.By != "":
		s += fmt.Sprintf("  (%s)", e.By)
	}
	return s
}
