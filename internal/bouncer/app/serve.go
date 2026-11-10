// Package app is the service layer for the bouncer CLI and other UIs.
package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/pastdev/agentcon/internal/bouncer/daemon"
	"github.com/pastdev/agentcon/internal/bouncer/running"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
	"github.com/pastdev/agentcon/pkg/term"
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
	Log         zerolog.Logger
	Audit       zerolog.Logger
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
	d, err := daemon.New(daemon.Options{
		Provided:   opts.Provided,
		ConfigPath: opts.ConfigPath,
		StateDir:   opts.StateDir,
		Load:       opts.Load,
		Log:        opts.Log,
		Audit:      opts.Audit,
	})
	if err != nil {
		return fmt.Errorf("daemon setup: %w", err)
	}
	cfg := d.Config()
	opts.Log.Info().Str("path", cfg.Path).Msg("config")
	opts.Log.Info().Str("path", d.CA.CertPath()).Msg("CA certificate")
	if cfg.Prompts.TerminalEnabled() && opts.Interactive {
		in, out := opts.Stdin, opts.Stderr
		if in == nil {
			in = os.Stdin
		}
		if out == nil {
			out = os.Stderr
		}
		pctx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			d.RunTerminalPrompter(pctx, terminalFor(in), out)
		}()
		// Wait for the prompter to restore the terminal, so the shell is
		// never left in raw mode.
		defer func() {
			stop()
			<-done
		}()
	} else if cfg.Prompts.CLIEnabled() {
		opts.Log.Info().Msg("answer prompts with `agentcon bouncer prompts` / `agentcon bouncer answer <id>`")
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
		opts.Log.Info().Str("slug", slug).Msg("session")
		defer func() { _ = running.Remove(opts.Home, slug) }()
	}
	err = d.Run(ctx)
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	return nil
}

// terminalFor returns the terminal behind in, or a plain reader that never
// changes modes when in is not a terminal.
func terminalFor(in io.Reader) daemon.Terminal {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return term.New(int(f.Fd()))
	}
	return plainTerminal{in}
}

type plainTerminal struct {
	io.Reader
}

func (plainTerminal) Raw() (func(), error) { return func() {}, nil }
