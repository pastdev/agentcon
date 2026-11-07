//go:build unix

package run

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

type secretReader int

func (r secretReader) Read(buf []byte) (int, error) {
	for {
		n, err := unix.Read(int(r), buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return n, fmt.Errorf("read terminal: %w", err)
		}
		return n, nil
	}
}
