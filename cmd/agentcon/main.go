package main

import (
	"errors"
	"os"

	"github.com/pastdev/agentcon/cmd/agentcon/root"
	"github.com/pastdev/agentcon/pkg/container"
)

func main() {
	err := root.New().Execute()
	if err != nil {
		var exitErr *container.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		os.Exit(1)
	}
}
