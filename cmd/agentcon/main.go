package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/pastdev/agentcon/cmd/agentcon/root"
	"github.com/pastdev/agentcon/pkg/bouncer/crederr"
	"github.com/pastdev/agentcon/pkg/container"
	pkgrun "github.com/pastdev/agentcon/pkg/run"
)

func main() {
	err := root.New().Execute()
	if err != nil {
		// Only the operator sees this, so a failed credential command's
		// stderr goes here rather than into the error text.
		stderr := crederr.Stderr(err)
		if stderr != "" {
			fmt.Fprintf(os.Stderr, "credential command stderr:\n%s\n", stderr)
		}
		var exitErr *container.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		if errors.Is(err, pkgrun.ErrInterrupted) {
			os.Exit(130)
		}
		os.Exit(1)
	}
}
