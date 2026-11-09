//go:build unix

package term

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Read reads keystrokes directly from the terminal.
func (t *Terminal) Read(buf []byte) (int, error) {
	for {
		n, err := unix.Read(t.fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return n, fmt.Errorf("read terminal: %w", err)
		}
		return n, nil
	}
}
