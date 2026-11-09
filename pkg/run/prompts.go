package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/app"
	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/internal/bouncer/mgmt"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/pastdev/agentcon/pkg/term"
)

// readyTimeout bounds the wait for the sidecar while nothing is pending.
// Pending prompts restart it, since each prompt expires on its own.
const readyTimeout = 2 * time.Minute

// checkPromptable refuses a policy whose Bitwarden vaults need a master
// password that nothing could supply: the sidecar has no terminal, and
// prompts.cli: false stops agentcon run from answering.
func checkPromptable(policy []byte) error {
	cfg, err := parsePolicyCredentials(policy)
	if err != nil {
		return err
	}
	if cfg.Prompts.CLIEnabled() {
		return nil
	}
	var names []string
	for name, c := range cfg.Credentials {
		if c == nil {
			continue
		}
		for _, slot := range c.Slots() {
			if slot.Source != nil && slot.Source.Source == "bitwarden" && slot.Source.PasswordEnv == "" {
				names = append(names, name)
				break
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("credentials %s use bitwarden without password_env, and prompts.cli: false leaves nothing to ask for the master password",
		strings.Join(names, ", "))
}

// waitReady waits for the sidecar to finish preparing credentials. Prompts
// it raises meanwhile are answered at this terminal. Without a terminal,
// each is listed once for `agentcon bouncer answer`.
func waitReady(ctx context.Context, client *mgmt.Client, stdin io.Reader, stderr io.Writer, timeout time.Duration) error {
	if stderr == nil {
		stderr = io.Discard
	}
	tty, _ := stdin.(*os.File)
	if tty != nil && !term.IsTerminal(int(tty.Fd())) {
		tty = nil
	}
	hinted := map[string]bool{}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return fmt.Errorf("wait bouncer: %w", ctx.Err())
		}
		status, err := client.Status()
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if status.Ready {
			return nil
		}
		if status.Error != "" {
			return fmt.Errorf("bouncer startup: %s", status.Error)
		}
		if status.PendingPrompts > 0 {
			deadline = time.Now().Add(timeout)
			list, err := client.Prompts()
			if err != nil {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			for _, p := range list {
				if tty == nil {
					if !hinted[p.ID] {
						hinted[p.ID] = true
						_, _ = fmt.Fprintln(stderr, promptHint(p))
					}
					continue
				}
				err = app.AnswerAtTerminal(ctx, client, tty, stderr, p)
				if errors.Is(err, io.EOF) || ctx.Err() != nil {
					return fmt.Errorf("answer bouncer prompt: %w", err)
				}
				if err != nil {
					// Most likely settled elsewhere first. Status decides.
					_, _ = fmt.Fprintf(stderr, "bouncer: %v\n", err)
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the bouncer to be ready")
}

// promptHint tells the human how to answer a prompt from another terminal.
func promptHint(p prompt.Pending) string {
	what, command := "prompt", "answer"
	if p.Kind == prompt.KindConfirm {
		what, command = "approval", "approve"
	}
	return fmt.Sprintf("bouncer: pending %s %s: %s (agentcon bouncer %s %s)",
		what, p.ID, approval.Display(p.Message, 150), command, p.ID)
}
