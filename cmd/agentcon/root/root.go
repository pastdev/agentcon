package root

import (
	"fmt"

	"github.com/pastdev/agentcon/cmd/agentcon/bouncer"
	"github.com/pastdev/agentcon/cmd/agentcon/config"
	"github.com/pastdev/agentcon/cmd/agentcon/run"
	"github.com/pastdev/agentcon/cmd/agentcon/version"
	pkgcfg "github.com/pastdev/agentcon/pkg/config"
	"github.com/pastdev/agentcon/pkg/log"
	cfgldrlog "github.com/pastdev/configloader/pkg/log"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	var logFormat string
	var logLevels []string
	var contextName string

	cmd := cobra.Command{
		Use:   "agentcon",
		Short: `A containerized agent workspace.`,
		//nolint: revive // required to match upstream signature
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := log.Configure(logLevels, logFormat)
			if err != nil {
				return fmt.Errorf("log: %w", err)
			}
			cfgldrlog.Logger = log.Logger
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&logFormat, "log-format", "pretty", "log format (pretty|json)")
	cmd.PersistentFlags().StringArrayVar(&logLevels, "log", nil,
		"log level as [name=]level, repeatable; names are cli (the default), bouncer, and audit (default info)")
	cmd.PersistentFlags().StringVar(&contextName, "context", "", "named context (default: default_context)")

	loader := pkgcfg.NewLoader()
	config.Add(&cmd, loader)
	cmd.AddCommand(version.New())
	cmd.AddCommand(run.New(loader, &contextName))
	cmd.AddCommand(bouncer.New(loader, &contextName))

	return &cmd
}
