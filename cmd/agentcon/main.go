package main

import (
	"os"

	"github.com/pastdev/agentcon/cmd/agentcon/root"
)

func main() {
	err := root.New().Execute()
	if err != nil {
		os.Exit(1)
	}
}
