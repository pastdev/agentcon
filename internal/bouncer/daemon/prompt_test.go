package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/prompt"
)

// fakeTerminal is a pipe that records raw mode.
type fakeTerminal struct {
	*io.PipeReader
	mu  sync.Mutex
	raw int
}

func (f *fakeTerminal) Raw() (func(), error) {
	f.mu.Lock()
	f.raw++
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		f.raw--
		f.mu.Unlock()
	}, nil
}

func (f *fakeTerminal) isRaw() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw > 0
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p) //nolint:wrapcheck // thin adapter: return the buffer's result as-is
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestRunTerminalPrompter(t *testing.T) {
	type testCase struct {
		kind prompt.Kind
		// raiseFirst raises the prompt before the prompter starts.
		raiseFirst bool
		// keys are typed once the prompt shows. Empty means the prompt is
		// answered elsewhere instead.
		keys       string
		wantAnswer prompt.Answer
		wantErr    error
		wantOut    []string
		hideOut    []string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		d := newTestDaemon(t)
		r, w := io.Pipe()
		tty := &fakeTerminal{PipeReader: r}
		var out lockedBuffer
		var ticket *prompt.Ticket
		raise := func() {
			ticket = d.Prompts.Raise(prompt.Question{Kind: tc.kind, Source: "test", Message: "Question?"})
		}
		if tc.raiseFirst {
			raise()
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			d.RunTerminalPrompter(ctx, tty, &out)
		}()
		t.Cleanup(func() {
			cancel()
			_ = w.Close()
			<-done
			if tty.isRaw() {
				t.Error("terminal left in raw mode")
			}
		})

		if !tc.raiseFirst {
			// Give the prompter time to subscribe before raising.
			time.Sleep(20 * time.Millisecond)
			raise()
		}
		deadline := time.Now().Add(2 * time.Second)
		for !tty.isRaw() {
			if time.Now().After(deadline) {
				t.Fatalf("prompt never shown: %q", out.String())
			}
			time.Sleep(5 * time.Millisecond)
		}
		if tc.keys == "" {
			err := d.Prompts.Answer(ticket.ID(), tc.wantAnswer)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			_, err := io.WriteString(w, tc.keys)
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := ticket.Wait(context.Background())
		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("err=%v, want %v", err, tc.wantErr)
		}
		if got != tc.wantAnswer {
			t.Fatalf("got %+v, want %+v", got, tc.wantAnswer)
		}
		outcome := "\n  [" + ticket.ID() + "] "
		for !strings.Contains(out.String(), outcome) || tty.isRaw() {
			if time.Now().After(deadline) {
				t.Fatalf("terminal not restored after settling: %q", out.String())
			}
			time.Sleep(5 * time.Millisecond)
		}
		for _, s := range tc.wantOut {
			if !strings.Contains(out.String(), s) {
				t.Errorf("output lacks %q: %q", s, out.String())
			}
		}
		for _, s := range tc.hideOut {
			if strings.Contains(out.String(), s) {
				t.Errorf("output shows %q: %q", s, out.String())
			}
		}
	}

	t.Run("secret is not echoed", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindSecret, keys: " hunter2\r", wantAnswer: prompt.Answer{Value: " hunter2"},
			wantOut: []string{"input needed", "answered"}, hideOut: []string{"hunter2"}})
	})
	t.Run("text is echoed and trimmed", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindText, keys: "12X\x7f3456 \r", wantAnswer: prompt.Answer{Value: "123456"},
			wantOut: []string{"12X\b \b3456"}})
	})
	t.Run("confirm asks again after a bad answer", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindConfirm, keys: "x\rs\r", wantAnswer: prompt.Answer{Allow: true, Remember: true},
			wantOut: []string{"approval needed", "answer y, s, n or d", "allowed"}})
	})
	t.Run("empty secret declines", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindSecret, keys: "\r", wantErr: prompt.ErrDeclined, wantOut: []string{"declined"}})
	})
	t.Run("ctrl-c declines", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindConfirm, keys: "y\x03", wantErr: prompt.ErrDeclined, wantOut: []string{"declined"}})
	})
	t.Run("shows a prompt raised before it started", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindText, raiseFirst: true, keys: "abc\r", wantAnswer: prompt.Answer{Value: "abc"}})
	})
	t.Run("answered elsewhere", func(t *testing.T) {
		tester(t, testCase{kind: prompt.KindSecret, wantAnswer: prompt.Answer{Value: "from-cli"},
			wantOut: []string{"answered"}, hideOut: []string{"from-cli"}})
	})
}
