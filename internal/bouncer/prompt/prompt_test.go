package prompt

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const secret = "correct horse battery staple"

func TestAnswer(t *testing.T) {
	type testCase struct {
		kind    Kind
		answer  Answer
		wantErr error
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		b := NewBroker(time.Minute)
		tk := b.Raise(Question{Kind: tc.kind, Source: "test", Message: "?"})
		err := b.Answer(tk.ID(), tc.answer)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v, want %v", err, tc.wantErr)
			}
			if len(b.List()) != 1 {
				t.Fatal("rejected answer settled the prompt")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := tk.Wait(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.answer {
			t.Fatalf("got %+v, want %+v", got, tc.answer)
		}
		if len(b.List()) != 0 {
			t.Fatal("answered prompt still pending")
		}
	}

	t.Run("confirm allow", func(t *testing.T) {
		tester(t, testCase{kind: KindConfirm, answer: Answer{Allow: true, Remember: true}})
	})
	t.Run("confirm deny", func(t *testing.T) {
		tester(t, testCase{kind: KindConfirm, answer: Answer{}})
	})
	t.Run("confirm rejects a value", func(t *testing.T) {
		tester(t, testCase{kind: KindConfirm, answer: Answer{Value: "y"}, wantErr: ErrInvalidAnswer})
	})
	t.Run("text", func(t *testing.T) {
		tester(t, testCase{kind: KindText, answer: Answer{Value: "123456"}})
	})
	t.Run("secret", func(t *testing.T) {
		tester(t, testCase{kind: KindSecret, answer: Answer{Value: secret}})
	})
	t.Run("secret rejects an empty value", func(t *testing.T) {
		tester(t, testCase{kind: KindSecret, answer: Answer{}, wantErr: ErrInvalidAnswer})
	})
	t.Run("secret rejects allow", func(t *testing.T) {
		tester(t, testCase{kind: KindSecret, answer: Answer{Allow: true, Value: secret}, wantErr: ErrInvalidAnswer})
	})
}

func TestSettle(t *testing.T) {
	t.Run("unknown id", func(t *testing.T) {
		b := NewBroker(time.Minute)
		err := b.Answer("nope", Answer{Allow: true})
		if !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		err = b.Decline("nope")
		if !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	})

	t.Run("answering twice", func(t *testing.T) {
		b := NewBroker(time.Minute)
		tk := b.Raise(Question{Kind: KindConfirm})
		err := b.Answer(tk.ID(), Answer{Allow: true})
		if err != nil {
			t.Fatal(err)
		}
		err = b.Answer(tk.ID(), Answer{})
		if !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		got, err := tk.Wait(context.Background())
		if err != nil || !got.Allow {
			t.Fatalf("got %+v err=%v", got, err)
		}
	})

	t.Run("decline", func(t *testing.T) {
		b := NewBroker(time.Minute)
		tk := b.Raise(Question{Kind: KindSecret})
		err := b.Decline(tk.ID())
		if err != nil {
			t.Fatal(err)
		}
		_, err = tk.Wait(context.Background())
		if !errors.Is(err, ErrDeclined) {
			t.Fatal(err)
		}
	})

	t.Run("expires", func(t *testing.T) {
		b := NewBroker(20 * time.Millisecond)
		_, err := b.Ask(context.Background(), Question{Kind: KindSecret})
		if !errors.Is(err, ErrExpired) {
			t.Fatal(err)
		}
		if len(b.List()) != 0 {
			t.Fatal("expired prompt still pending")
		}
	})

	t.Run("ctx withdraws", func(t *testing.T) {
		b := NewBroker(time.Minute)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := b.Ask(ctx, Question{Kind: KindSecret})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if len(b.List()) != 0 {
			t.Fatal("withdrawn prompt still pending")
		}
	})
}

func TestEvents(t *testing.T) {
	b := NewBroker(time.Minute)
	notified := make(chan Pending, 1)
	b.SetNotify(func(p Pending) { notified <- p })
	events, cancel := b.Subscribe()
	defer cancel()

	tk := b.Raise(Question{Kind: KindSecret, Source: "bitwarden:you@example.com", Message: "Master password"})
	ev := <-events
	if ev.Type != "pending" || ev.Pending.ID != tk.ID() {
		t.Fatalf("%+v", ev)
	}
	p := <-notified
	if p.ID != tk.ID() {
		t.Fatalf("%+v", p)
	}
	listed, err := json.Marshal(b.List())
	if err != nil {
		t.Fatal(err)
	}

	err = b.Answer(tk.ID(), Answer{Value: secret})
	if err != nil {
		t.Fatal(err)
	}
	ev = <-events
	if ev.Type != "settled" || ev.Outcome != OutcomeAnswered || ev.Allowed {
		t.Fatalf("%+v", ev)
	}
	settled, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range [][]byte{listed, settled} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("secret leaked: %s", out)
		}
	}
	_, err = tk.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfirmAllowedEvent(t *testing.T) {
	b := NewBroker(time.Minute)
	events, cancel := b.Subscribe()
	defer cancel()
	tk := b.Raise(Question{Kind: KindConfirm})
	<-events
	err := b.Answer(tk.ID(), Answer{Allow: true})
	if err != nil {
		t.Fatal(err)
	}
	ev := <-events
	if !ev.Allowed || ev.Outcome != OutcomeAnswered {
		t.Fatalf("%+v", ev)
	}
}
