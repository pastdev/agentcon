package run

import (
	"context"
	"errors"
	"fmt"
	"io"

	"golang.org/x/term"
)

var ErrInterrupted = errors.New("interrupted")

func readSecret(ctx context.Context, fd int) ([]byte, error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("terminal state: %w", err)
	}
	defer func() { _ = term.Restore(fd, state) }()

	_, err = term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("set raw terminal: %w", err)
	}

	return readSecretBytes(ctx, secretReader(fd))
}

func readSecretBytes(ctx context.Context, r io.Reader) ([]byte, error) {
	var ret []byte
	buf := make([]byte, 1)
	for {
		err := ctx.Err()
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		n, err := r.Read(buf)
		if n > 0 {
			switch buf[0] {
			case 0x03:
				return nil, fmt.Errorf("read password: %w", ErrInterrupted)
			case 0x04:
				if len(ret) == 0 {
					return nil, fmt.Errorf("read password: %w", io.EOF)
				}
				return ret, nil
			case '\b', 0x7f:
				if len(ret) > 0 {
					ret = ret[:len(ret)-1]
				}
			case '\r', '\n':
				if secretLineEnd(buf[0]) {
					return ret, nil
				}
			default:
				if buf[0] >= 32 {
					ret = append(ret, buf[0])
				}
			}
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(ret) > 0 {
				return ret, nil
			}
			return nil, fmt.Errorf("read password: %w", err)
		}
	}
}
