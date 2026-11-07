//go:build windows

package run

import (
	"fmt"

	"golang.org/x/sys/windows"
)

type secretReader int

func (r secretReader) Read(buf []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(windows.Handle(r), buf, &n, nil)
	if err != nil {
		return int(n), fmt.Errorf("read terminal: %w", err)
	}
	return int(n), nil
}
