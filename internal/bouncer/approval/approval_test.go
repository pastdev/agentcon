package approval

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
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
		m := NewManager(tc.timeout)
		ok, err := m.Ask(context.Background(), tc.req)
		if tc.wantErr {
			if ok || err == nil {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
			if len(m.List()) != 0 {
				t.Fatal("timed-out approval still pending")
			}
			return
		}
		if ok != tc.wantOK {
			t.Fatalf("ok=%v", ok)
		}
	}

	t.Run("coalesces waiters and remembers the session answer", func(t *testing.T) {
		m := NewManager(time.Minute)
		events, cancel := m.Subscribe()
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
		if ev.Type != "pending" {
			t.Fatal(ev)
		}
		time.Sleep(20 * time.Millisecond)
		if n := len(m.List()); n != 1 {
			t.Fatalf("expected one coalesced prompt, got %d", n)
		}
		err := m.Resolve(ev.Pending.ID, true, true)
		if err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		for i, r := range results {
			if !r {
				t.Errorf("waiter %d not approved", i)
			}
		}
		ok, err := m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "push?"})
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Error("remembered approval not applied")
		}
		m.ForgetSession("s1")
		ctx, c := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer c()
		ok, _ = m.Ask(ctx, chain.AskRequest{Session: sess, Prompt: "push?"})
		if ok {
			t.Error("forgotten session still approved")
		}
	})
	t.Run("denies when the prompt times out", func(t *testing.T) {
		tester(t, testCase{timeout: 10 * time.Millisecond, req: chain.AskRequest{Prompt: "x"}, wantErr: true})
	})
	t.Run("keeps different requests on separate prompts", func(t *testing.T) {
		m := NewManager(time.Minute)
		sess := &chain.Session{ID: "s1"}
		ask := func(req string, key string, out chan bool) {
			ok, _ := m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "Let the agent in?", Request: req, Key: key})
			out <- ok
		}
		harmless, dangerous := make(chan bool, 1), make(chan bool, 1)
		go ask("ssh agent@sandbox exec: ls", "", harmless)
		go ask("ssh agent@sandbox exec: rm -rf /srv", "", dangerous)
		time.Sleep(20 * time.Millisecond)
		list := m.List()
		if len(list) != 2 {
			t.Fatalf("expected two separate prompts, got %d", len(list))
		}
		for _, p := range list {
			err := m.Resolve(p.ID, p.Request == "ssh agent@sandbox exec: ls", true)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !<-harmless || <-dangerous {
			t.Fatal("answers applied to the wrong requests")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		ok, _ := m.Ask(ctx, chain.AskRequest{Session: sess, Prompt: "Let the agent in?", Request: "ssh agent@sandbox exec: cat /etc/shadow"})
		if ok {
			t.Fatal("remembered approval leaked to a different request")
		}
		ok, _ = m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "Let the agent in?", Request: "ssh agent@sandbox exec: ls"})
		if !ok {
			t.Fatal("identical request should reuse the remembered approval")
		}

		a, b := make(chan bool, 1), make(chan bool, 1)
		go ask("push 1", "push-limit", a)
		go ask("push 2", "push-limit", b)
		time.Sleep(20 * time.Millisecond)
		list = m.List()
		if len(list) != 2 {
			t.Fatalf("explicit key: expected two prompts, got %d", len(list))
		}
		err := m.Resolve(list[0].ID, true, true)
		if err != nil {
			t.Fatal(err)
		}
		if !<-a || !<-b {
			t.Fatal("session-wide approval should settle both")
		}
	})
	t.Run("does not remember an answer for a shared session", func(t *testing.T) {
		m := NewManager(time.Minute)
		anon := &chain.Session{ID: "anonymous", Shared: true}
		events, cancel := m.Subscribe()
		defer cancel()
		done := make(chan bool, 1)
		go func() {
			ok, _ := m.Ask(context.Background(), chain.AskRequest{Session: anon, Prompt: "x", Request: "r"})
			done <- ok
		}()
		err := m.Resolve((<-events).Pending.ID, true, true)
		if err != nil {
			t.Fatal(err)
		}
		<-done
		ctx, c := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer c()
		ok, _ := m.Ask(ctx, chain.AskRequest{Session: anon, Prompt: "x", Request: "r"})
		if ok {
			t.Fatal("approval remembered for a shared session")
		}
	})
}
