package run

import (
	"errors"
	"fmt"
	"os"

	pkgcfg "github.com/pastdev/agentcon/pkg/config"
	"github.com/pastdev/agentcon/pkg/container/moby"
	pkgrun "github.com/pastdev/agentcon/pkg/run"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func New(loader *pkgcfg.Loader, contextName *string) *cobra.Command {
	var agent, bouncerName, project, slug, pull string
	var noBouncer bool
	cmd := &cobra.Command{
		Use:          "run [-- agent-args...]",
		Short:        "Run an agent in a configured context",
		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := pkgcfg.RunFlags{
				Agent:     agent,
				Bouncer:   bouncerName,
				NoBouncer: noBouncer,
				Pull:      pull,
			}
			if contextName != nil {
				flags.Context = *contextName
			}
			return execute(cmd, loader, args, flags, project, slug)
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "agent name (default: context agent)")
	cmd.Flags().StringVar(&bouncerName, "bouncer", "", "bouncer name (default: context bouncer)")
	cmd.Flags().BoolVar(&noBouncer, "no-bouncer", false, "skip the bouncer sidecar")
	cmd.Flags().StringVar(&project, "project", "", "project path relative to the context root (default: cwd)")
	cmd.Flags().StringVar(&slug, "slug", "", "session slug (default: generated)")
	cmd.Flags().StringVar(&pull, "pull", "", "image pull policy: missing, always, or never (default: agent pull_policy, else missing)")
	return cmd
}

func execute(
	cmd *cobra.Command,
	loader *pkgcfg.Loader,
	args []string,
	flags pkgcfg.RunFlags,
	project, slug string,
) error {
	if flags.NoBouncer && flags.Bouncer != "" {
		return fmt.Errorf("--bouncer and --no-bouncer cannot be used together")
	}

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

	req, err := pkgcfg.NewRunRequest(cfg, flags, cwd, home)
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
	req.Project = project
	req.Slug = slug
	req.User = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	req.Args = args
	req.TTY = term.IsTerminal(int(os.Stdin.Fd()))
	req.Stdin = cmd.InOrStdin()
	req.Stdout = cmd.OutOrStdout()
	req.Stderr = cmd.ErrOrStderr()
	req.Runtime = runtime

	err = pkgrun.Run(cmd.Context(), req)
	if err != nil {
		if errors.Is(err, pkgrun.ErrInterrupted) {
			cmd.SilenceErrors = true
		}
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
