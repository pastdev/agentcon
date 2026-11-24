package bouncer

import (
	"github.com/spf13/cobra"

	"github.com/pastdev/agentcon/pkg/bouncer/gitsign"
	"github.com/pastdev/agentcon/pkg/container"
)

func gitSignCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "git-sign",
		Short:              "gpg.openpgp.program that signs git objects through the bouncer signer",
		Long:               gitsign.Help,
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Git shows this program's stderr, so only the helper speaks.
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			code := gitsign.Main(cmd.Context(), args, gitsign.OSIO())
			if code != 0 {
				return &container.ExitError{Code: code}
			}
			return nil
		},
	}
}
