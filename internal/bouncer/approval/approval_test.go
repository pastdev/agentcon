package approval

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAsk(t *testing.T) {
	type testCase struct {
		timeout time.Duration
		req     chain.AskRequest
		wantOK  bool
		wantErr bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		b := prompt.NewBroker(tc.timeout)
		m := NewManager(b)
		ok, err := m.Ask(context.Background(), tc.req)
		if tc.wantErr {
			require.Error(t, err)
			assert.False(t, ok)
			assert.Empty(t, b.List(), "timed-out approval still pending")
			return
		}
		assert.Equal(t, tc.wantOK, ok)
	}

	t.Run("coalesces waiters and remembers the session answer", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		m := NewManager(b)
		events, cancel := b.Subscribe()
		defer cancel()
		sess := &chain.Session{ID: "s1"}
		var wg sync.WaitGroup
		results := make([]bool, 3)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i], _ = m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "push?"})
			}(i)
		}
		ev := <-events
		require.Equal(t, "pending", ev.Type)
		time.Sleep(20 * time.Millisecond)
		require.Len(t, b.List(), 1, "expected one coalesced prompt")
		err := b.Answer(ev.Pending.ID, prompt.Answer{Allow: true, Remember: true})
		require.NoError(t, err)
		wg.Wait()
		assert.Equal(t, []bool{true, true, true}, results)
		ok, err := m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "push?"})
		require.NoError(t, err)
		assert.True(t, ok, "remembered approval not applied")
		m.ForgetSession("s1")
		ctx, c := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer c()
		ok, _ = m.Ask(ctx, chain.AskRequest{Session: sess, Prompt: "push?"})
		assert.False(t, ok, "forgotten session still approved")
	})
	t.Run("denies when the prompt is declined", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		m := NewManager(b)
		events, cancel := b.Subscribe()
		defer cancel()
		done := make(chan error, 1)
		go func() {
			ok, err := m.Ask(context.Background(), chain.AskRequest{Prompt: "x", Request: "r"})
			if ok {
				err = errors.New("declined ask was allowed")
			}
			done <- err
		}()
		err := b.Decline((<-events).Pending.ID)
		require.NoError(t, err)
		require.ErrorIs(t, <-done, prompt.ErrDeclined)
	})
	t.Run("denies when the prompt times out", func(t *testing.T) {
		tester(t, testCase{timeout: 10 * time.Millisecond, req: chain.AskRequest{Prompt: "x"}, wantErr: true})
	})
	t.Run("keeps different requests on separate prompts", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		m := NewManager(b)
		sess := &chain.Session{ID: "s1"}
		ask := func(req string, key string, out chan bool) {
			ok, _ := m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "Let the agent in?", Request: req, Key: key})
			out <- ok
		}
		harmless, dangerous := make(chan bool, 1), make(chan bool, 1)
		go ask("ssh agent@sandbox exec: ls", "", harmless)
		go ask("ssh agent@sandbox exec: rm -rf /srv", "", dangerous)
		time.Sleep(20 * time.Millisecond)
		list := b.List()
		require.Len(t, list, 2, "expected two separate prompts")
		for _, p := range list {
			err := b.Answer(p.ID, prompt.Answer{Allow: p.Detail == "ssh agent@sandbox exec: ls", Remember: true})
			require.NoError(t, err)
		}
		require.True(t, <-harmless, "harmless")
		require.False(t, <-dangerous, "dangerous")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		ok, _ := m.Ask(ctx, chain.AskRequest{Session: sess, Prompt: "Let the agent in?", Request: "ssh agent@sandbox exec: cat /etc/shadow"})
		require.False(t, ok, "remembered approval leaked to a different request")
		ok, _ = m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "Let the agent in?", Request: "ssh agent@sandbox exec: ls"})
		require.True(t, ok, "identical request should reuse the remembered approval")

		push1, push2 := make(chan bool, 1), make(chan bool, 1)
		go ask("push 1", "push-limit", push1)
		go ask("push 2", "push-limit", push2)
		time.Sleep(20 * time.Millisecond)
		list = b.List()
		require.Len(t, list, 2, "explicit key: expected two prompts")
		err := b.Answer(list[0].ID, prompt.Answer{Allow: true, Remember: true})
		require.NoError(t, err)
		assert.True(t, <-push1, "push1")
		assert.True(t, <-push2, "push2")
	})
	t.Run("does not remember an answer for a shared session", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		m := NewManager(b)
		anon := &chain.Session{ID: "anonymous", Shared: true}
		events, cancel := b.Subscribe()
		defer cancel()
		done := make(chan bool, 1)
		go func() {
			ok, _ := m.Ask(context.Background(), chain.AskRequest{Session: anon, Prompt: "x", Request: "r"})
			done <- ok
		}()
		err := b.Answer((<-events).Pending.ID, prompt.Answer{Allow: true, Remember: true})
		require.NoError(t, err)
		<-done
		ctx, c := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer c()
		ok, _ := m.Ask(ctx, chain.AskRequest{Session: anon, Prompt: "x", Request: "r"})
		assert.False(t, ok, "approval remembered for a shared session")
	})
}
