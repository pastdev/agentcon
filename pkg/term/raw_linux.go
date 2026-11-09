//go:build linux

package term

import (
	"fmt"

	"golang.org/x/sys/unix"
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

	current, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("get termios: %w", err)
	}

	next := *current
	next.Lflag &^= unix.ECHO | unix.ECHOCTL | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	next.Iflag |= unix.ICRNL
	next.Iflag &^= unix.IGNCR | unix.INLCR
	next.Cc[unix.VMIN] = 1
	next.Cc[unix.VTIME] = 0
	err = unix.IoctlSetTermios(fd, unix.TCSETS, &next)
	if err != nil {
		return nil, fmt.Errorf("set termios: %w", err)
	}

	return func() { _ = xterm.Restore(fd, state) }, nil
}
