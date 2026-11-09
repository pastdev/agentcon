package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"golang.org/x/term"
)

// PromptAnswerer is the part of the control API that settles prompts.
type PromptAnswerer interface {
	AnswerPrompt(id string, a prompt.Answer) error
	DeclinePrompt(id string) error
}

// AnswerAtTerminal shows one pending prompt, reads the human's reply, and
// sends it. An empty value declines a text or secret prompt.
func AnswerAtTerminal(c PromptAnswerer, in *os.File, out io.Writer, p prompt.Pending) error {
	a, err := readAnswer(in, out, p)
	if err != nil {
		return err
	}
	if p.Kind != prompt.KindConfirm && a.Value == "" {
		err = c.DeclinePrompt(p.ID)
		if err != nil {
			return fmt.Errorf("decline prompt %s: %w", p.ID, err)
		}
		_, _ = fmt.Fprintf(out, "  [%s] declined\n", p.ID)
		return nil
	}
	err = c.AnswerPrompt(p.ID, a)
	if err != nil {
		return fmt.Errorf("answer prompt %s: %w", p.ID, err)
	}
	return nil
}

func readAnswer(in *os.File, out io.Writer, p prompt.Pending) (prompt.Answer, error) {
	d := approval.Display
	switch p.Kind {
	case prompt.KindSecret:
		if !term.IsTerminal(int(in.Fd())) {
			return prompt.Answer{}, fmt.Errorf("prompt %s: a secret needs an interactive terminal", p.ID)
		}
		_, _ = fmt.Fprintf(out, "%s [%s] (empty to decline): ", d(p.Message, 300), d(p.Source, 60))
		b, err := term.ReadPassword(int(in.Fd()))
		_, _ = fmt.Fprintln(out)
		if err != nil {
			return prompt.Answer{}, fmt.Errorf("read secret: %w", err)
		}
		return prompt.Answer{Value: string(b)}, nil
	case prompt.KindText:
		_, _ = fmt.Fprintf(out, "%s [%s] (empty to decline): ", d(p.Message, 300), d(p.Source, 60))
		line, err := readLine(in)
		if err != nil {
			return prompt.Answer{}, err
		}
		return prompt.Answer{Value: line}, nil
	case prompt.KindConfirm:
		_, _ = fmt.Fprintf(out, "=== approval needed [%s] source=%s\n  %s\n  request: %s\n  [y] allow once  [s] allow for session  [n] deny  [d] deny for session > ",
			p.ID, d(p.Source, 60), d(p.Message, 300), d(p.Detail, 300))
		for {
			line, err := readLine(in)
			if err != nil {
				return prompt.Answer{}, err
			}
			switch strings.ToLower(line) {
			case "y", "yes":
				return prompt.Answer{Allow: true}, nil
			case "s":
				return prompt.Answer{Allow: true, Remember: true}, nil
			case "n", "no":
				return prompt.Answer{}, nil
			case "d":
				return prompt.Answer{Remember: true}, nil
			}
			_, _ = fmt.Fprint(out, "  answer y, s, n or d > ")
		}
	}
	return prompt.Answer{}, fmt.Errorf("prompt %s: unknown kind %q", p.ID, p.Kind)
}

// readLine reads one line a byte at a time, so nothing past the newline
// is consumed and later prompts on the same input still see it.
func readLine(in io.Reader) (string, error) {
	var b strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := in.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				return strings.TrimSpace(b.String()), nil
			}
			b.WriteByte(buf[0])
		}
		if errors.Is(err, io.EOF) {
			if b.Len() == 0 {
				return "", errors.New("read answer: input closed")
			}
			return strings.TrimSpace(b.String()), nil
		}
		if err != nil {
			return "", fmt.Errorf("read answer: %w", err)
		}
	}
}
