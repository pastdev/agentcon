package daemon

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
)

// RunTerminalApprover prompts for approvals on an interactive terminal,
// one at a time, in arrival order. Approvals answered elsewhere (the CLI)
// are dropped from the queue.
func (d *Daemon) RunTerminalApprover(in io.Reader, out io.Writer) {
	events, cancel := d.Prompts.Subscribe()
	defer cancel()
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- strings.TrimSpace(sc.Text())
		}
		close(lines)
	}()

	var queue []prompt.Pending
	var showing *prompt.Pending
	showNext := func() {
		showing = nil
		if len(queue) == 0 {
			return
		}
		p := queue[0]
		queue = queue[1:]
		showing = &p
		session := p.SessionLabel
		if session == "" {
			session = p.SessionID
		}
		d := approval.Display
		_, _ = fmt.Fprintf(out, "\n=== approval needed [%s] session=%s profile=%s source=%s\n  %s\n  request: %s\n  [y] allow once  [s] allow for session  [n] deny  [d] deny for session > ",
			p.ID, d(session, 60), d(p.Profile, 60), d(p.Source, 60), d(p.Message, 300), d(p.Detail, 300))
	}
	for {
		select {
		case ev := <-events:
			switch ev.Type {
			case "pending":
				if ev.Pending.Kind != prompt.KindConfirm {
					continue
				}
				queue = append(queue, ev.Pending)
				if showing == nil {
					showNext()
				}
			case "settled":
				for i, q := range queue {
					if q.ID == ev.Pending.ID {
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				if showing != nil && showing.ID == ev.Pending.ID {
					verdict := ev.Outcome
					if ev.Outcome == prompt.OutcomeAnswered {
						verdict = "denied"
						if ev.Allowed {
							verdict = "allowed"
						}
					}
					_, _ = fmt.Fprintf(out, "\n  [%s] %s\n", ev.Pending.ID, verdict)
					showNext()
				}
			}
		case line, ok := <-lines:
			if !ok {
				return
			}
			if showing == nil {
				continue
			}
			var allow, remember bool
			switch strings.ToLower(line) {
			case "y", "yes":
				allow = true
			case "s":
				allow, remember = true, true
			case "n", "no":
			case "d":
				remember = true
			default:
				_, _ = fmt.Fprint(out, "  answer y, s, n or d > ")
				continue
			}
			_ = d.Prompts.Answer(showing.ID, prompt.Answer{Allow: allow, Remember: remember})
		}
	}
}
