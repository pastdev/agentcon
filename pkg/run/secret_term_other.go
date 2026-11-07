//go:build !linux

package run

import (
	"fmt"

	"golang.org/x/term"
)

func prepareSecretTerminal(fd int) (func(), error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("terminal state: %w", err)
	}
	_, err = term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("set raw terminal: %w", err)
	}
	return func() { _ = term.Restore(fd, state) }, nil
}
