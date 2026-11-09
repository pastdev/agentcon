package bitwarden

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/prompt"
)

func TestBrokerPrompter(t *testing.T) {
	type testCase struct {
		ask         func(p Prompter) (string, error)
		answer      string
		wantKind    prompt.Kind
		wantSource  string
		wantMessage string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		b := prompt.NewBroker(time.Minute)
		events, cancel := b.Subscribe()
		defer cancel()
		type result struct {
			v   string
			err error
		}
		done := make(chan result, 1)
		go func() {
			v, err := tc.ask(BrokerPrompter(b))
			done <- result{v, err}
		}()
		ev := <-events
		p := ev.Pending
		if p.Kind != tc.wantKind || p.Source != tc.wantSource || p.Message != tc.wantMessage {
			t.Fatalf("asked %+v", p)
		}
		var err error
		if tc.answer == "" {
			err = b.Decline(p.ID)
		} else {
			err = b.Answer(p.ID, prompt.Answer{Value: tc.answer})
		}
		if err != nil {
			t.Fatal(err)
		}
		r := <-done
		if tc.answer == "" {
			if !errors.Is(r.err, prompt.ErrDeclined) {
				t.Fatalf("err=%v", r.err)
			}
			return
		}
		if r.err != nil || r.v != tc.answer {
			t.Fatalf("got %q err=%v", r.v, r.err)
		}
	}

	t.Run("asks for a master password as a secret", func(t *testing.T) {
		tester(t, testCase{
			ask: func(p Prompter) (string, error) {
				return p.MasterPassword(context.Background(), "you@example.com", 1, 3)
			},
			answer: testPassword, wantKind: prompt.KindSecret,
			wantSource: "bitwarden:you@example.com", wantMessage: "Bitwarden master password",
		})
	})
	t.Run("names a retry", func(t *testing.T) {
		tester(t, testCase{
			ask: func(p Prompter) (string, error) {
				return p.MasterPassword(context.Background(), "you@example.com", 2, 3)
			},
			answer: testPassword, wantKind: prompt.KindSecret,
			wantSource: "bitwarden:you@example.com", wantMessage: "Bitwarden master password (incorrect, attempt 2 of 3)",
		})
	})
	t.Run("asks for a verification code as text", func(t *testing.T) {
		tester(t, testCase{
			ask: func(p Prompter) (string, error) {
				return p.TwoFactorCode(context.Background(), "you@example.com", "authenticator app", 1, 5)
			},
			answer: "123456", wantKind: prompt.KindText,
			wantSource: "bitwarden:you@example.com", wantMessage: "Bitwarden verification code for authenticator app",
		})
	})
	t.Run("returns a decline", func(t *testing.T) {
		tester(t, testCase{
			ask: func(p Prompter) (string, error) {
				return p.MasterPassword(context.Background(), "you@example.com", 1, 3)
			},
			wantKind:   prompt.KindSecret,
			wantSource: "bitwarden:you@example.com", wantMessage: "Bitwarden master password",
		})
	})
}

// TestBrokerUnlock unlocks through the broker the way the daemon does.
func TestBrokerUnlock(t *testing.T) {
	t.Run("retries a wrong password with a new prompt", func(t *testing.T) {
		srv, _ := startVault(t, true)
		b := prompt.NewBroker(time.Minute)
		events, cancel := b.Subscribe()
		defer cancel()
		v := New(Options{StateDir: t.TempDir(), Prompt: BrokerPrompter(b)})
		done := make(chan error, 1)
		go func() {
			_, err := v.Get(context.Background(), Query{Account: Account{Email: testEmail, Server: srv.URL}, Item: "Org Secret"})
			done <- err
		}()
		answers := []string{"nope", testPassword, "123456"}
		var messages []string
		for _, a := range answers {
			p := (<-events).Pending
			messages = append(messages, p.Message)
			err := b.Answer(p.ID, prompt.Answer{Value: a})
			if err != nil {
				t.Fatal(err)
			}
			<-events // settled
		}
		err := <-done
		if err != nil {
			t.Fatal(err)
		}
		want := []string{
			"Bitwarden master password",
			"Bitwarden master password (incorrect, attempt 2 of 3)",
			"Bitwarden verification code for authenticator app",
		}
		for i := range want {
			if messages[i] != want[i] {
				t.Fatalf("prompt %d %q, want %q", i, messages[i], want[i])
			}
		}
	})

	t.Run("gives each account only its own answer", func(t *testing.T) {
		srvA, _ := startVault(t, false)
		srvB, _ := startVault(t, false)
		b := prompt.NewBroker(time.Minute)
		events, cancel := b.Subscribe()
		defer cancel()
		v := New(Options{StateDir: t.TempDir(), Prompt: BrokerPrompter(b)})
		accounts := []Account{{Email: testEmail, Server: srvA.URL}, {Email: testEmail, Server: srvB.URL}}
		var wg sync.WaitGroup
		errs := make([]error, len(accounts))
		for i, a := range accounts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = v.Get(context.Background(), Query{Account: a, Item: "GitLab", Folder: "Work"})
			}()
		}
		// Both accounts ask at once, each under its own source.
		pending := map[string]string{}
		for len(pending) < 2 {
			p := (<-events).Pending
			pending[p.Source] = p.ID
		}
		sourceA := "bitwarden:" + accounts[0].label()
		sourceB := "bitwarden:" + accounts[1].label()
		if pending[sourceA] == "" || pending[sourceB] == "" {
			t.Fatalf("sources %v", pending)
		}
		// Answering A must not unlock B.
		err := b.Answer(pending[sourceA], prompt.Answer{Value: testPassword})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		still := b.List()
		if len(still) != 1 || still[0].ID != pending[sourceB] {
			t.Fatalf("after answering A, pending %+v", still)
		}
		err = b.Answer(pending[sourceB], prompt.Answer{Value: testPassword})
		if err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("account %d: %v", i, err)
			}
		}
	})

	t.Run("fails the unlock when declined", func(t *testing.T) {
		srv, _ := startVault(t, false)
		b := prompt.NewBroker(time.Minute)
		events, cancel := b.Subscribe()
		defer cancel()
		v := New(Options{StateDir: t.TempDir(), Prompt: BrokerPrompter(b)})
		done := make(chan error, 1)
		go func() {
			done <- v.Unlock(context.Background(), []Account{{Email: testEmail, Server: srv.URL}})
		}()
		err := b.Decline((<-events).Pending.ID)
		if err != nil {
			t.Fatal(err)
		}
		err = <-done
		if !errors.Is(err, prompt.ErrDeclined) {
			t.Fatalf("err=%v", err)
		}
	})
}
