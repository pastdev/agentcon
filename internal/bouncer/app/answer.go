package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/pastdev/agentcon/pkg/term"
)

// PromptAnswerer is the part of the control API that settles prompts.
type PromptAnswerer interface {
	AnswerPrompt(id string, a prompt.Answer) error
	DeclinePrompt(id string) error
}

// AnswerAtTerminal shows one pending prompt, reads the human's reply, and
// sends it. An empty value or Ctrl-C declines.
func AnswerAtTerminal(ctx context.Context, c PromptAnswerer, in *os.File, out io.Writer, p prompt.Pending) error {
	a, readErr := readAnswer(ctx, in, out, p)
	declined := errors.Is(readErr, term.ErrInterrupted) || (readErr == nil && p.Kind != prompt.KindConfirm && a.Value == "")
	if declined {
		err := c.DeclinePrompt(p.ID)
		if err != nil {
			return fmt.Errorf("decline prompt %s: %w", p.ID, err)
		}
		_, _ = fmt.Fprintf(out, "  [%s] declined\n", p.ID)
		return nil
	}
	if readErr != nil {
		return readErr
	}
	err := c.AnswerPrompt(p.ID, a)
	if err != nil {
		return fmt.Errorf("answer prompt %s: %w", p.ID, err)
	}
	return nil
}

func readAnswer(ctx context.Context, in *os.File, out io.Writer, p prompt.Pending) (prompt.Answer, error) {
	fd := int(in.Fd())
	tty := term.IsTerminal(fd)
	// A terminal is read a keystroke at a time so Enter and Ctrl-C work the
	// same everywhere. Other input, such as a pipe, is read as lines.
	readLine := func(echo io.Writer) (string, error) {
		if !tty {
			b, err := term.ReadLine(ctx, in, nil)
			return string(b), err
		}
		b, err := term.New(fd).ReadLine(ctx, echo)
		_, _ = fmt.Fprintln(out)
		return string(b), err
	}

	d := approval.Display
	switch p.Kind {
	case prompt.KindSecret:
		if !tty {
			return prompt.Answer{}, fmt.Errorf("prompt %s: a secret needs an interactive terminal", p.ID)
		}
		_, _ = fmt.Fprintf(out, "%s [%s] (empty to decline): ", d(p.Message, 300), d(p.Source, 60))
		// A secret is used exactly as typed, spaces included.
		v, err := readLine(nil)
		return prompt.Answer{Value: v}, err
	case prompt.KindText:
		_, _ = fmt.Fprintf(out, "%s [%s] (empty to decline): ", d(p.Message, 300), d(p.Source, 60))
		v, err := readLine(out)
		return prompt.Answer{Value: strings.TrimSpace(v)}, err
	case prompt.KindConfirm:
		_, _ = fmt.Fprintf(out, "=== approval needed [%s] source=%s\n  %s\n  request: %s\n  %s > ",
			p.ID, d(p.Source, 60), d(p.Message, 300), d(p.Detail, 300), prompt.ConfirmChoices)
		for {
			line, err := readLine(out)
			if err != nil {
				return prompt.Answer{}, err
			}
			a, ok := prompt.ParseConfirm(line)
			if ok {
				return a, nil
			}
			_, _ = fmt.Fprint(out, "  answer y, s, n or d > ")
		}
	}
	return prompt.Answer{}, fmt.Errorf("prompt %s: unknown kind %q", p.ID, p.Kind)
}
