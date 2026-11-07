package main

import (
	"errors"
	"os"

	"github.com/pastdev/agentcon/cmd/agentcon/root"
	"github.com/pastdev/agentcon/pkg/container"
	pkgrun "github.com/pastdev/agentcon/pkg/run"
)

func main() {
	err := root.New().Execute()
	if err != nil {
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
