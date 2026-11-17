package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
	"github.com/pastdev/agentcon/pkg/term"
)

// DefaultReadyTimeout bounds WaitReady while nothing is pending.
const DefaultReadyTimeout = 2 * time.Minute

// pollInterval is how often WaitReady polls.
const pollInterval = 200 * time.Millisecond

// notifyInterval is how often NotifyPrompts polls.
const notifyInterval = 2 * time.Second

// PromptHint returns the line that tells a human about a pending prompt,
// such as which command answers it from another terminal.
type PromptHint func(p prompt.Pending) string

// PromptOptions configure WaitReady and NotifyPrompts.
type PromptOptions struct {
	// Stdin answers prompts when it is a terminal. Otherwise each prompt is
	// reported once with Hint.
	Stdin io.Reader
	// Stderr receives prompts and hints. Nil discards them.
	Stderr io.Writer
	// Hint formats a prompt that is not answered here. Nil prints the
	// prompt without a command.
	Hint PromptHint
	// Timeout bounds WaitReady while nothing is pending. Pending prompts
	// restart it, since each prompt expires on its own. Zero means
	// DefaultReadyTimeout.
	Timeout time.Duration
}

func (o PromptOptions) stderr() io.Writer {
	if o.Stderr == nil {
		return io.Discard
	}
	return o.Stderr
}

func (o PromptOptions) hint(p prompt.Pending) string {
	if o.Hint == nil {
		return plainHint(p)
	}
	return o.Hint(p)
}

// plainHint describes a pending prompt without naming a command.
func plainHint(p prompt.Pending) string {
	return fmt.Sprintf("bouncer: pending %s %s: %s", promptWhat(p), p.ID, approval.Display(p.Message, 150))
}

// AgentconHint describes a pending prompt and the agentcon command that
// answers it.
func AgentconHint(p prompt.Pending) string {
	command := "answer"
	if p.Kind == prompt.KindConfirm {
		command = "approve"
	}
	return fmt.Sprintf("%s (agentcon bouncer %s %s)", plainHint(p), command, p.ID)
}

func promptWhat(p prompt.Pending) string {
	if p.Kind == prompt.KindConfirm {
		return "approval"
	}
	return "prompt"
}

// WaitReady waits for the daemon to finish preparing credentials. It may
// answer prompts: when o.Stdin is a terminal, prompts raised meanwhile are
// answered there with AnswerAtTerminal. Otherwise each is reported once on
// o.Stderr. A startup error fails it, even when the daemon also reports
// ready.
func WaitReady(ctx context.Context, c *mgmt.Client, o PromptOptions) error {
	stderr := o.stderr()
	timeout := o.Timeout
	if timeout == 0 {
		timeout = DefaultReadyTimeout
	}
	tty, _ := o.Stdin.(*os.File)
	if tty != nil && !term.IsTerminal(int(tty.Fd())) {
		tty = nil
	}
	hinted := map[string]bool{}
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("wait bouncer: %w", ctx.Err())
		}
		if !time.Now().Before(deadline) {
			break
		}
		// Each request ends at the idle deadline, so a slow or stalled
		// daemon cannot hold WaitReady past it.
		pollCtx, cancel := context.WithDeadline(ctx, deadline)
		status, err := c.Status(pollCtx)
		cancel()
		if err != nil {
			pause(ctx, deadline)
			continue
		}
		if status.Error != "" {
			return fmt.Errorf("bouncer startup: %s", status.Error)
		}
		if status.Ready {
			return nil
		}
		if status.PendingPrompts > 0 {
			deadline = time.Now().Add(timeout)
			pollCtx, cancel = context.WithDeadline(ctx, deadline)
			list, err := c.Prompts(pollCtx)
			cancel()
			if err != nil {
				pause(ctx, deadline)
				continue
			}
			for _, p := range list {
				if tty == nil {
					if !hinted[p.ID] {
						hinted[p.ID] = true
						_, _ = fmt.Fprintln(stderr, o.hint(p))
					}
					continue
				}
				// The caller's context, not the idle deadline: a human may
				// take longer than the deadline to answer.
				err = AnswerAtTerminal(ctx, c, tty, stderr, p)
				if errors.Is(err, io.EOF) || ctx.Err() != nil {
					return fmt.Errorf("answer bouncer prompt: %w", err)
				}
				if err != nil {
					// Most likely settled elsewhere first. Status decides.
					_, _ = fmt.Fprintf(stderr, "bouncer: %v\n", err)
				}
			}
		}
		pause(ctx, deadline)
	}
	return fmt.Errorf("timed out waiting for the bouncer to be ready")
}

// NotifyPrompts reports each new pending prompt once on o.Stderr until ctx
// ends. It never answers them, and it ignores o.Stdin and o.Timeout. Run it
// under a context that is cancelled when the session ends.
func NotifyPrompts(ctx context.Context, c *mgmt.Client, o PromptOptions) {
	stderr := o.stderr()
	seen := map[string]bool{}
	ticker := time.NewTicker(notifyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			list, err := c.Prompts(ctx)
			if err != nil {
				continue
			}
			for _, p := range list {
				if seen[p.ID] {
					continue
				}
				seen[p.ID] = true
				_, _ = fmt.Fprintln(stderr, o.hint(p))
			}
		}
	}
}

// pause waits one poll interval, or less when the deadline comes first or
// ctx ends.
func pause(ctx context.Context, deadline time.Time) {
	wait := min(pollInterval, time.Until(deadline))
	if wait <= 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
