//go:build windows

package term

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// Read reads keystrokes directly from the terminal.
func (t *Terminal) Read(buf []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(windows.Handle(t.fd), buf, &n, nil)
	if err != nil {
		return int(n), fmt.Errorf("read terminal: %w", err)
	}
	return int(n), nil
}
