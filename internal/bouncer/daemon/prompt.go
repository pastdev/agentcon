package daemon

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/pastdev/agentcon/pkg/term"
)

// Terminal is the input the terminal prompter reads keystrokes from.
type Terminal interface {
	io.Reader
	// Raw switches to keystroke-at-a-time input without echo and returns a
	// func that restores the previous mode.
	Raw() (func(), error)
}

// RunTerminalPrompter asks pending prompts on an interactive terminal, one
// at a time, in arrival order, until ctx ends or input closes. Prompts
// settled elsewhere (the CLI) are dropped from the queue.
//
// While a prompt is showing, the terminal is in raw mode: keystrokes are
// echoed here (never for a secret), Enter answers, and Ctrl-C declines. The
// terminal is restored between prompts, so Ctrl-C otherwise stops the
// process as usual, and it is restored before this returns.
func (d *Daemon) RunTerminalPrompter(ctx context.Context, in Terminal, out io.Writer) {
	events, cancel := d.Prompts.Subscribe()
	defer cancel()
	keys := make(chan byte)
	go func() {
		defer close(keys)
		buf := make([]byte, 1)
		for {
			n, err := in.Read(buf)
			if n == 1 {
				select {
				case keys <- buf[0]:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Prompts raised before subscribing are shown too. Their pending
	// events may also arrive, so remember what is already queued.
	queue := d.Prompts.List()
	queued := map[string]bool{}
	for _, p := range queue {
		queued[p.ID] = true
	}
	var showing *prompt.Pending
	var editor *term.Editor
	restore := func() {}
	cooked := func() {
		restore()
		restore = func() {}
	}
	defer func() { cooked() }()

	showNext := func() {
		cooked()
		showing = nil
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			showPrompt(out, p)
			r, err := in.Raw()
			if err != nil {
				_, _ = fmt.Fprintf(out, "\n  [%s] cannot read this terminal (%v); answer with `agentcon bouncer answer %s`\n", p.ID, err, p.ID)
				continue
			}
			restore = r
			showing = &p
			echo := out
			if p.Kind == prompt.KindSecret {
				echo = nil
			}
			editor = term.NewEditor(echo)
			return
		}
	}

	showNext()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			switch ev.Type {
			case "pending":
				if queued[ev.Pending.ID] {
					continue
				}
				queued[ev.Pending.ID] = true
				queue = append(queue, ev.Pending)
				if showing == nil {
					showNext()
				}
			case "settled":
				delete(queued, ev.Pending.ID)
				for i, q := range queue {
					if q.ID == ev.Pending.ID {
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				if showing != nil && showing.ID == ev.Pending.ID {
					cooked()
					_, _ = fmt.Fprintf(out, "\n  [%s] %s\n", ev.Pending.ID, verdict(ev))
					showNext()
				}
			}
		case b, ok := <-keys:
			if !ok {
				return
			}
			if showing == nil {
				continue
			}
			line, done, err := editor.Key(b)
			switch {
			case err != nil:
				// Ctrl-C, or Ctrl-D on an empty line.
				_ = d.Prompts.Decline(showing.ID)
			case done:
				d.submit(out, *showing, string(line))
			}
		}
	}
}

// submit answers the showing prompt from a finished line. The settled
// event that follows moves on to the next prompt.
func (d *Daemon) submit(out io.Writer, p prompt.Pending, line string) {
	switch p.Kind {
	case prompt.KindConfirm:
		a, ok := prompt.ParseConfirm(line)
		if !ok {
			// Raw mode: return the carriage ourselves.
			_, _ = fmt.Fprint(out, "\r\n  answer y, s, n or d > ")
			return
		}
		_ = d.Prompts.Answer(p.ID, a)
	case prompt.KindText:
		line = strings.TrimSpace(line)
		if line == "" {
			_ = d.Prompts.Decline(p.ID)
			return
		}
		_ = d.Prompts.Answer(p.ID, prompt.Answer{Value: line})
	case prompt.KindSecret:
		// A secret is used exactly as typed, spaces included.
		if line == "" {
			_ = d.Prompts.Decline(p.ID)
			return
		}
		_ = d.Prompts.Answer(p.ID, prompt.Answer{Value: line})
	}
}

func showPrompt(out io.Writer, p prompt.Pending) {
	d := approval.Display
	if p.Kind == prompt.KindConfirm {
		session := p.SessionLabel
		if session == "" {
			session = p.SessionID
		}
		_, _ = fmt.Fprintf(out, "\n=== approval needed [%s] session=%s profile=%s source=%s\n  %s\n  request: %s\n  %s > ",
			p.ID, d(session, 60), d(p.Profile, 60), d(p.Source, 60), d(p.Message, 300), d(p.Detail, 300), prompt.ConfirmChoices)
		return
	}
	_, _ = fmt.Fprintf(out, "\n=== input needed [%s] source=%s\n  %s (empty or Ctrl-C to decline) > ",
		p.ID, d(p.Source, 60), d(p.Message, 300))
}

func verdict(ev prompt.Event) string {
	if ev.Outcome != prompt.OutcomeAnswered {
		return ev.Outcome
	}
	if ev.Pending.Kind != prompt.KindConfirm {
		return "answered"
	}
	if ev.Allowed {
		return "allowed"
	}
	return "denied"
}
