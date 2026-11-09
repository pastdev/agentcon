//go:build !linux

package term

import (
	"fmt"

	xterm "golang.org/x/term"
)

// Raw switches the terminal to keystroke-at-a-time input without echo
// and returns a func that restores the previous mode.
func (t *Terminal) Raw() (func(), error) {
	fd := t.fd
	state, err := xterm.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("terminal state: %w", err)
	}
	_, err = xterm.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("set raw terminal: %w", err)
	}
	return func() { _ = xterm.Restore(fd, state) }, nil
}
