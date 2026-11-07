//go:build unix

package run

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type secretReader int

func (r secretReader) Read(buf []byte) (int, error) {
	n, err := unix.Read(int(r), buf)
	if err != nil {
		return n, fmt.Errorf("read terminal: %w", err)
	}
	return n, nil
}

func secretLineEnd(b byte) bool {
	return b == '\n'
}
