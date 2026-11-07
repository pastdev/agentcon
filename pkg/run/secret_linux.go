//go:build linux

package run

import (
	"fmt"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func prepareSecretTerminal(fd int) (func(), error) {
	state, err := term.GetState(fd)
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

	return func() { _ = term.Restore(fd, state) }, nil
}
