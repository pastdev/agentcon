package bouncer

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pastdev/agentcon/internal/bouncer/app"
	"github.com/pastdev/agentcon/pkg/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the bouncer daemon",
		Long: `Run the proxy and SSH listeners. agentcon run execs this inside the sidecar.
Decisions go to the audit log, set with --log audit=<level>.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("working directory: %w", err)
			}
			return app.Serve(ctx, app.ServeOptions{
				ConfigPath:  configPath,
				StateDir:    stateDir,
				Context:     contextName,
				Home:        homeDir,
				Project:     projectFlag,
				Slug:        slugFlag,
				Cwd:         cwd,
				Log:         log.Bouncer,
				Audit:       log.Audit,
				Stdin:       os.Stdin,
				Stderr:      os.Stderr,
				Interactive: term.IsTerminal(int(os.Stdin.Fd())),
				Load:        bouncerLoader(),
			})
		},
	}
	return cmd
}
