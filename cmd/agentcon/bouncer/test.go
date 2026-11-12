package bouncer

import (
	"errors"
	"fmt"
	"os"

	"github.com/pastdev/agentcon/pkg/bouncertest"
	"github.com/spf13/cobra"
)

func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run the context bouncer's policy tests and print TAP",
		Args:  cobra.NoArgs,
		// A failed test is not a usage error.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if fileFlag != "" {
				return errors.New("test needs a context, not --file: a policy file has no tests")
			}
			cfg, err := configLoader.Config()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			suite, err := cfg.BouncerTests(contextName)
			if err != nil {
				return fmt.Errorf("bouncer tests: %w", err)
			}
			dir, err := os.MkdirTemp("", "agentcon-bouncer-test-")
			if err != nil {
				return fmt.Errorf("temp dir: %w", err)
			}
			defer func() { _ = os.RemoveAll(dir) }()

			report, err := bouncertest.Run(suite, dir)
			if err != nil {
				return fmt.Errorf("bouncer tests: %w", err)
			}
			err = writeTAP(cmd.OutOrStdout(), report)
			if err != nil {
				return err
			}
			if failed := report.Failed(); failed > 0 {
				return fmt.Errorf("%d failed", failed)
			}
			return nil
		},
	}
}
