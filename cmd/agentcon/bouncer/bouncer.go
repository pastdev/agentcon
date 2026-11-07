// Package bouncer is the agentcon subcommand for the credential broker.
package bouncer

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pastdev/agentcon/internal/bouncer/mgmt"
	"github.com/pastdev/agentcon/internal/bouncer/running"
	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	pkgcfg "github.com/pastdev/agentcon/pkg/config"
	"github.com/spf13/cobra"
)

var (
	configPath     string
	stateDir       string
	fileFlag       string
	contextNamePtr *string
	stateFlag      string
	contextName    string
	homeDir        string
	projectFlag    string
	slugFlag       string
	configLoader   *pkgcfg.Loader
)

func New(loader *pkgcfg.Loader, contextFlag *string) *cobra.Command {
	configLoader = loader
	contextNamePtr = contextFlag
	cmd := &cobra.Command{
		Use:   "bouncer",
		Short: "Credential broker sidecar and host control plane",
		Long: `bouncer holds credentials and sits between an agent and the services it uses.
agentcon run starts the sidecar next to the agent. Use these commands from the
host to lint policy and talk to a running sidecar.

  agentcon bouncer check                validate policy and compile filters
  agentcon bouncer approvals            list pending asks
  agentcon bouncer approve ID           allow a pending request

Host commands pick a live session by --slug, then --project, then cwd.`,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if p := cmd.Root(); p != nil && p.PersistentPreRun != nil {
				p.PersistentPreRun(cmd, args)
			}
			if cmd.Name() == "ssh-connect" {
				return nil
			}
			return resolve()
		},
	}
	cmd.PersistentFlags().StringVar(&fileFlag, "file", "", "bouncer policy file or directory")
	cmd.PersistentFlags().StringVar(&projectFlag, "project", "", "project path relative to the context root")
	cmd.PersistentFlags().StringVar(&slugFlag, "slug", "", "session slug")
	cmd.PersistentFlags().StringVar(&stateFlag, "state-dir", "", "bouncer state directory")
	cmd.AddCommand(
		serveCmd(),
		sshConnectCmd(),
		approvalsCmd(),
		approveCmd(true),
		approveCmd(false),
		sessionsCmd(),
		checkCmd(),
	)
	return cmd
}

func resolve() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home directory: %w", err)
	}
	homeDir = home
	contextName = flagContext()
	stateDir = stateFlag

	if fileFlag != "" {
		configPath, err = policyPath(fileFlag)
		if err != nil {
			return err
		}
		if stateDir == "" {
			stateDir = filepath.Join(filepath.Dir(configPath), "state")
		}
		return nil
	}

	if configLoader != nil {
		cfg, err := configLoader.Config()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		name := flagContext()
		if name == "" {
			name = cfg.DefaultContext
		}
		if name != "" {
			dir := pkgcfg.BouncerLayoutDir(home, name)
			path, err := cfg.WriteBouncer(name, dir)
			if err != nil {
				return err
			}
			if path != "" {
				configPath = path
				contextName = name
				if stateDir == "" {
					stateDir = filepath.Join(dir, "state")
				}
				return nil
			}
		}
	}

	return fmt.Errorf("bouncer policy not set: set contexts.<name>.bouncer or pass --file")
}

func policyPath(flag string) (string, error) {
	info, err := os.Stat(flag)
	if err == nil && info.IsDir() {
		return filepath.Join(flag, bouncercfg.FileName), nil
	}
	return flag, nil
}

func flagContext() string {
	if contextNamePtr == nil {
		return ""
	}
	return *contextNamePtr
}

func loadBouncerService() (*bouncercfg.Config, error) {
	return pkgcfg.LoadBouncerService(configPath)
}

func bouncerLoader() func() (*bouncercfg.Config, error) {
	return pkgcfg.BouncerLoader(configPath)
}

func dial() (*mgmt.Client, error) {
	if fileFlag != "" || stateFlag != "" {
		return mgmt.Dial(stateDir, configPath)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("working directory: %w", err)
	}
	return mgmt.DialContext(homeDir, running.Query{
		Context: contextName,
		Project: projectFlag,
		Slug:    slugFlag,
		Cwd:     cwd,
	}, "", "")
}
