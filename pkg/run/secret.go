package run

import (
	"context"
	"errors"
	"fmt"
	"io"
)

var ErrInterrupted = errors.New("interrupted")

func readSecret(ctx context.Context, fd int) ([]byte, error) {
	return readTerminalLine(ctx, fd, nil)
}

func readTerminalLine(ctx context.Context, fd int, echo io.Writer) ([]byte, error) {
	restore, err := prepareSecretTerminal(fd)
	if err != nil {
		return nil, err
	}
	defer restore()

	return readSecretBytes(ctx, secretReader(fd), echo)
}

func readSecretBytes(ctx context.Context, r io.Reader, echo io.Writer) ([]byte, error) {
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
					echoBackspace(echo)
				}
			case '\r', '\n':
				return ret, nil
			default:
				if buf[0] >= 32 {
					ret = append(ret, buf[0])
					echoByte(echo, buf[0])
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

func echoByte(w io.Writer, b byte) {
	if w == nil {
		return
	}
	_, _ = w.Write([]byte{b})
}

func echoBackspace(w io.Writer) {
	if w == nil {
		return
	}
	_, _ = io.WriteString(w, "\b \b")
}
