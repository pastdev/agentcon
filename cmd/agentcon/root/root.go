package root

import (
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
	var logLevel string

	cmd := cobra.Command{
		Use:   "agentcon",
		Short: `A containerized agent workspace.`,
		//nolint: revive // required to match upstream signature
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			log.SetFormat(logFormat)
			log.SetLevel(logLevel)
			cfgldrlog.Logger = log.Logger
		},
	}

	cmd.PersistentFlags().StringVar(&logFormat, "log-format", "pretty", "log format (pretty|json)")
	cmd.PersistentFlags().StringVar(&logLevel, "log", "info", "log level")

	loader := pkgcfg.NewLoader()
	config.Add(&cmd, loader)
	cmd.AddCommand(version.New())
	cmd.AddCommand(run.New(loader))

	return &cmd
}
