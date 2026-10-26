package version

import (
	"fmt"

	pkgversion "github.com/pastdev/agentcon/pkg/version"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display agentcon version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Printf("Version: %s\n", pkgversion.Version())
			if err != nil {
				return fmt.Errorf("print version: %w", err)
			}
			return nil
		},
	}
}
