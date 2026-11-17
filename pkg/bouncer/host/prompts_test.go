package host

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pastdev/agentcon/pkg/bouncer/mgmt"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStatus serves a scripted sequence of statuses and one pending prompt.
type fakeStatus struct {
	mu       sync.Mutex
	statuses []mgmt.Status
	prompts  []prompt.Pending
}

func (f *fakeStatus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/_bouncer/status":
		st := f.statuses[0]
		if len(f.statuses) > 1 {
			f.statuses = f.statuses[1:]
		}
		_ = json.NewEncoder(w).Encode(st)
	case "/_bouncer/prompts":
		_ = json.NewEncoder(w).Encode(f.prompts)
	default:
		http.NotFound(w, r)
	}
}

func TestWaitReady(t *testing.T) {
	type testCase struct {
		statuses   []mgmt.Status
		prompts    []prompt.Pending
		timeout    time.Duration
		hint       PromptHint
		wantErr    string
		wantStderr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		srv := httptest.NewServer(&fakeStatus{statuses: tc.statuses, prompts: tc.prompts})
		t.Cleanup(srv.Close)
		var stderr bytes.Buffer
		err := WaitReady(context.Background(), mgmt.New(srv.URL, "t"), PromptOptions{Stderr: &stderr, Hint: tc.hint, Timeout: tc.timeout})
		if tc.wantErr == "" {
			require.NoError(t, err)
		} else {
			require.ErrorContains(t, err, tc.wantErr)
		}
		assert.Equal(t, tc.wantStderr, stderr.String())
	}
	pending := mgmt.Status{PendingPrompts: 1}
	secret := []prompt.Pending{{ID: "a1", Kind: prompt.KindSecret, Message: "Bitwarden master password"}}

	t.Run("returns when ready", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{{}, {Ready: true}}, timeout: time.Minute})
	})
	t.Run("fails with the startup error", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{{Error: "bitwarden unlock: prompt declined"}}, timeout: time.Minute,
			wantErr: "bouncer startup: bitwarden unlock: prompt declined"})
	})
	t.Run("checks the startup error before ready", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{{Ready: true, Error: "bitwarden unlock: prompt declined"}}, timeout: time.Minute,
			wantErr: "bouncer startup: bitwarden unlock: prompt declined"})
	})
	t.Run("lists a prompt once without a command by default", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{pending, pending, pending, {Ready: true}}, prompts: secret, timeout: time.Minute,
			wantStderr: "bouncer: pending prompt a1: Bitwarden master password\n"})
	})
	t.Run("lists a prompt once with the agentcon hint", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{pending, pending, pending, {Ready: true}}, prompts: secret, timeout: time.Minute, hint: AgentconHint,
			wantStderr: "bouncer: pending prompt a1: Bitwarden master password (agentcon bouncer answer a1)\n"})
	})
	t.Run("times out with nothing pending", func(t *testing.T) {
		tester(t, testCase{statuses: []mgmt.Status{{}}, timeout: 300 * time.Millisecond, wantErr: "timed out"})
	})
	t.Run("does not time out while a prompt is pending", func(t *testing.T) {
		statuses := []mgmt.Status{}
		// About 1s of pending polls against a 300ms timeout.
		for range 5 {
			statuses = append(statuses, pending)
		}
		statuses = append(statuses, mgmt.Status{Ready: true})
		tester(t, testCase{statuses: statuses, prompts: secret, timeout: 300 * time.Millisecond, hint: AgentconHint,
			wantStderr: "bouncer: pending prompt a1: Bitwarden master password (agentcon bouncer answer a1)\n"})
	})
}

func TestAgentconHint(t *testing.T) {
	type testCase struct {
		p    prompt.Pending
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, AgentconHint(tc.p))
	}

	t.Run("answers a secret prompt", func(t *testing.T) {
		tester(t, testCase{p: prompt.Pending{ID: "a1", Kind: prompt.KindSecret, Message: "master password"},
			want: "bouncer: pending prompt a1: master password (agentcon bouncer answer a1)"})
	})
	t.Run("approves a confirm prompt", func(t *testing.T) {
		tester(t, testCase{p: prompt.Pending{ID: "c1", Kind: prompt.KindConfirm, Message: "merge MR 7"},
			want: "bouncer: pending approval c1: merge MR 7 (agentcon bouncer approve c1)"})
	})
}

func TestNotifyPrompts(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		srv := httptest.NewServer(&fakeStatus{statuses: []mgmt.Status{{}}, prompts: []prompt.Pending{{ID: "a1", Kind: prompt.KindSecret, Message: "pw"}}})
		t.Cleanup(srv.Close)
		var stderr lockedBuffer
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			NotifyPrompts(ctx, mgmt.New(srv.URL, "t"), PromptOptions{Stderr: &stderr})
			close(done)
		}()
		require.Eventually(t, func() bool { return stderr.String() != "" }, 5*time.Second, 50*time.Millisecond)
		// Another poll must not repeat it.
		time.Sleep(notifyInterval + 500*time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("NotifyPrompts did not return after cancel")
		}
		assert.Equal(t, "bouncer: pending prompt a1: pw\n", stderr.String())
	}

	t.Run("reports each prompt once and stops with the context", func(t *testing.T) {
		tester(t)
	})
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

func TestWaitReadyDeadline(t *testing.T) {
	type testCase struct {
		// delay is how long the status handler waits before answering
		// ready. Zero stalls until the request ends.
		delay   time.Duration
		timeout time.Duration
		// cancelAfter cancels the caller's context. Zero never cancels.
		cancelAfter time.Duration
		wantErr     error
		wantText    string
		// within bounds how long WaitReady may take.
		within time.Duration
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wait := time.After(tc.delay)
			if tc.delay == 0 {
				wait = nil
			}
			select {
			case <-r.Context().Done():
				return
			case <-release:
				return
			case <-wait:
			}
			_ = json.NewEncoder(w).Encode(mgmt.Status{Ready: true})
		}))
		t.Cleanup(func() {
			close(release)
			srv.Close()
		})
		ctx := t.Context()
		if tc.cancelAfter > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			time.AfterFunc(tc.cancelAfter, cancel)
		}
		// No client timeout, so only WaitReady's own deadline bounds a poll.
		c := mgmt.New(srv.URL, "t", mgmt.WithTimeout(0))
		start := time.Now()
		err := WaitReady(ctx, c, PromptOptions{Timeout: tc.timeout})
		elapsed := time.Since(start)
		require.Error(t, err)
		if tc.wantErr != nil {
			require.ErrorIs(t, err, tc.wantErr)
		}
		if tc.wantText != "" {
			require.ErrorContains(t, err, tc.wantText)
		}
		assert.Less(t, elapsed, tc.within)
	}

	t.Run("times out on a ready reply that comes after the deadline", func(t *testing.T) {
		tester(t, testCase{delay: 800 * time.Millisecond, timeout: 100 * time.Millisecond,
			wantText: "timed out", within: 500 * time.Millisecond})
	})
	t.Run("times out on a stalled reply", func(t *testing.T) {
		tester(t, testCase{timeout: 100 * time.Millisecond,
			wantText: "timed out", within: 500 * time.Millisecond})
	})
	t.Run("stops when the context ends during a poll", func(t *testing.T) {
		tester(t, testCase{timeout: time.Minute, cancelAfter: 50 * time.Millisecond,
			wantErr: context.Canceled, within: 180 * time.Millisecond})
	})
}
