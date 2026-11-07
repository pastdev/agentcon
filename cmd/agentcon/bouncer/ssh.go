package bouncer

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/pastdev/agentcon/internal/bouncer/sshproxy"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/spf13/cobra"
)

func sshConnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "ssh-connect host port user",
		Short:  "ssh ProxyCommand that tunnels to the bouncer SSH listener",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := os.Getenv("BOUNCER_SESSION")
			addr := os.Getenv("BOUNCER_SSH_ADDR")
			if token == "" || addr == "" {
				return errors.New("BOUNCER_SESSION/BOUNCER_SSH_ADDR not set")
			}
			port, _ := strconv.Atoi(args[1])
			err := sshproxy.Connect(addr, sshproxy.Preamble{Token: token, Host: args[0], Port: port, User: args[2]}, os.Stdin, os.Stdout)
			if err != nil {
				fmt.Fprintln(os.Stderr, "agentcon bouncer:", err)
				return &container.ExitError{Code: 255}
			}
			return nil
		},
	}
}
