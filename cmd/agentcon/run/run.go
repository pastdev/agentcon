package run

import (
	"fmt"
	"os"
	"strings"

	pkgcfg "github.com/pastdev/agentcon/pkg/config"
	"github.com/pastdev/agentcon/pkg/container/moby"
	pkgrun "github.com/pastdev/agentcon/pkg/run"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func New(loader *pkgcfg.Loader) *cobra.Command {
	return &cobra.Command{
		Use:   "run [context] [-- harness-args...]",
		Short: "Run an agent in a configured context",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return execute(cmd, loader, args)
		},
	}
}

func execute(cmd *cobra.Command, loader *pkgcfg.Loader, args []string) error {
	cfg, err := loader.Config()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("working directory: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home directory: %w", err)
	}

	name := ""
	harnessArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
		harnessArgs = args[1:]
	}

	req, err := pkgcfg.NewRunRequest(cfg, name, cwd)
	if err != nil {
		return fmt.Errorf("run request: %w", err)
	}

	runtime, err := moby.New()
	if err != nil {
		return fmt.Errorf("container runtime: %w", err)
	}
	defer func() {
		_ = runtime.Close()
	}()

	req.Home = home
	req.User = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	req.Harness = os.Getenv("HARNESS")
	req.Args = harnessArgs
	req.TTY = term.IsTerminal(int(os.Stdin.Fd()))
	req.Stdin = cmd.InOrStdin()
	req.Stdout = cmd.OutOrStdout()
	req.Stderr = cmd.ErrOrStderr()
	req.Runtime = runtime

	err = pkgrun.Run(cmd.Context(), req)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
