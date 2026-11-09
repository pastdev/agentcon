// Package term reads lines and secrets from a terminal one keystroke at a
// time, so Enter, Backspace, and Ctrl-C behave the same on every platform.
package term

import (
	"context"
	"errors"
	"fmt"
	"io"

	xterm "golang.org/x/term"
)

// ErrInterrupted is returned when Ctrl-C is typed at a prompt.
var ErrInterrupted = errors.New("interrupted")

// Terminal is an interactive terminal on a file descriptor.
type Terminal struct {
	fd int
}

// New returns the terminal on fd. Check IsTerminal first.
func New(fd int) *Terminal {
	return &Terminal{fd: fd}
}

// IsTerminal reports whether fd is a terminal.
func IsTerminal(fd int) bool {
	return xterm.IsTerminal(fd)
}

// ReadLine switches to raw mode, reads one line, and restores the terminal.
// Typed characters are echoed to echo, or not at all when echo is nil.
func (t *Terminal) ReadLine(ctx context.Context, echo io.Writer) ([]byte, error) {
	restore, err := t.Raw()
	if err != nil {
		return nil, err
	}
	defer restore()
	return ReadLine(ctx, t, echo)
}

// Editor assembles a line from keystrokes read in raw mode.
type Editor struct {
	buf  []byte
	echo io.Writer
}

// NewEditor returns an editor that echoes to echo, or not at all when echo
// is nil.
func NewEditor(echo io.Writer) *Editor {
	return &Editor{echo: echo}
}

// Key handles one keystroke. When it finishes a line, done is true and
// line holds it. Ctrl-C returns ErrInterrupted, and Ctrl-D on an empty
// line returns io.EOF.
func (e *Editor) Key(b byte) (line []byte, done bool, err error) {
	switch b {
	case 0x03:
		return nil, false, ErrInterrupted
	case 0x04:
		if len(e.buf) == 0 {
			return nil, false, io.EOF
		}
		return e.take(), true, nil
	case '\b', 0x7f:
		if len(e.buf) > 0 {
			e.buf = e.buf[:len(e.buf)-1]
			e.write("\b \b")
		}
	case '\r', '\n':
		return e.take(), true, nil
	default:
		if b >= 32 {
			e.buf = append(e.buf, b)
			e.write(string(b))
		}
	}
	return nil, false, nil
}

func (e *Editor) take() []byte {
	line := e.buf
	e.buf = nil
	return line
}

func (e *Editor) write(s string) {
	if e.echo != nil {
		_, _ = io.WriteString(e.echo, s)
	}
}

// ReadLine reads keystrokes from r until a line is finished. Input that
// ends without a newline still finishes the line.
func ReadLine(ctx context.Context, r io.Reader, echo io.Writer) ([]byte, error) {
	e := NewEditor(echo)
	buf := make([]byte, 1)
	for {
		err := ctx.Err()
		if err != nil {
			return nil, fmt.Errorf("read line: %w", err)
		}
		n, err := r.Read(buf)
		if n > 0 {
			line, done, kerr := e.Key(buf[0])
			if kerr != nil {
				return nil, fmt.Errorf("read line: %w", kerr)
			}
			if done {
				return line, nil
			}
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(e.buf) > 0 {
				return e.take(), nil
			}
			return nil, fmt.Errorf("read line: %w", err)
		}
	}
}
