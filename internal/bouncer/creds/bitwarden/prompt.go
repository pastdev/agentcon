package bitwarden

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrNeedTerminal is returned when a vault unlock needs a password and
// there is no interactive terminal and no password_env.
var ErrNeedTerminal = errors.New("bitwarden unlock requires a terminal or password_env")

// Prompter supplies the master password and, when the server asks, a
// second factor. The password is requested again on each attempt.
type Prompter interface {
	MasterPassword(label string) (string, error)
	TwoFactorCode(label, method string) (string, error)
}

// StaticPrompter returns a password (and optional 2FA code) supplied out
// of band, for example from the management API.
type StaticPrompter struct {
	Password string
	Code     string
}

func (p StaticPrompter) MasterPassword(string) (string, error) {
	if p.Password == "" {
		return "", errors.New("empty master password")
	}
	return p.Password, nil
}

func (p StaticPrompter) TwoFactorCode(string, string) (string, error) {
	if p.Code == "" {
		return "", errors.New("empty verification code")
	}
	return p.Code, nil
}

func SetPrompt(p Prompter) {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global != nil {
		global.prompt = p
	}
}

// stdPrompter reads the master password from the controlling terminal.
// It refuses a redirected stdin so a prompt cannot swallow other input.
type stdPrompter struct {
	in  *os.File
	out io.Writer
}

func (p stdPrompter) MasterPassword(label string) (string, error) {
	in := p.in
	if in == nil {
		in = os.Stdin
	}
	out := p.out
	if out == nil {
		out = os.Stderr
	}
	if !term.IsTerminal(int(in.Fd())) {
		return "", fmt.Errorf("%w: master password for %s required", ErrNeedTerminal, label)
	}
	fmt.Fprintf(out, "Bitwarden master password for %s: ", label)
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("empty master password")
	}
	return string(b), nil
}

func (p stdPrompter) TwoFactorCode(label, method string) (string, error) {
	in := p.in
	if in == nil {
		in = os.Stdin
	}
	out := p.out
	if out == nil {
		out = os.Stderr
	}
	if !term.IsTerminal(int(in.Fd())) {
		return "", fmt.Errorf("%w: verification code (%s) for %s required", ErrNeedTerminal, method, label)
	}
	fmt.Fprintf(out, "Bitwarden verification code (%s) for %s: ", method, label)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", errors.New("empty verification code")
	}
	return line, nil
}
