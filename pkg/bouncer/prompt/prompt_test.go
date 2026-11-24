package prompt

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			require.ErrorIs(t, err, tc.wantErr)
			assert.Len(t, b.List(), 1, "rejected answer settled the prompt")
			return
		}
		require.NoError(t, err)
		got, err := tk.Wait(context.Background())
		require.NoError(t, err)
		assert.Equal(t, tc.answer, got)
		assert.Empty(t, b.List(), "answered prompt still pending")
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
	t.Run("claim for session", func(t *testing.T) {
		tester(t, testCase{kind: KindClaim, answer: Answer{Allow: true, Remember: true}})
	})
	t.Run("claim once", func(t *testing.T) {
		tester(t, testCase{kind: KindClaim, answer: Answer{Allow: true}})
	})
	t.Run("claim deny", func(t *testing.T) {
		tester(t, testCase{kind: KindClaim, answer: Answer{}})
	})
	t.Run("claim rejects deny for session", func(t *testing.T) {
		tester(t, testCase{kind: KindClaim, answer: Answer{Remember: true}, wantErr: ErrInvalidAnswer})
	})
	t.Run("claim rejects a value", func(t *testing.T) {
		tester(t, testCase{kind: KindClaim, answer: Answer{Allow: true, Value: "s"}, wantErr: ErrInvalidAnswer})
	})
}

func TestParseChoice(t *testing.T) {
	type testCase struct {
		kind Kind
		in   string
		want Answer
		ok   bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, ok := ParseChoice(tc.kind, tc.in)
		assert.Equal(t, tc.ok, ok)
		assert.Equal(t, tc.want, got)
	}
	t.Run("claim once", func(t *testing.T) { tester(t, testCase{kind: KindClaim, in: "y", want: Answer{Allow: true}, ok: true}) })
	t.Run("claim session", func(t *testing.T) {
		tester(t, testCase{kind: KindClaim, in: " S ", want: Answer{Allow: true, Remember: true}, ok: true})
	})
	t.Run("claim deny", func(t *testing.T) { tester(t, testCase{kind: KindClaim, in: "no", want: Answer{}, ok: true}) })
	t.Run("claim has no deny for session", func(t *testing.T) { tester(t, testCase{kind: KindClaim, in: "d"}) })
	t.Run("confirm deny for session", func(t *testing.T) {
		tester(t, testCase{kind: KindConfirm, in: "d", want: Answer{Remember: true}, ok: true})
	})
	t.Run("text is not a choice", func(t *testing.T) { tester(t, testCase{kind: KindText, in: "y"}) })
}

func TestClaimPending(t *testing.T) {
	type testCase struct {
		q    Question
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		b := NewBroker(time.Minute)
		b.Raise(tc.q)
		list := b.List()
		require.Len(t, list, 1)
		list[0].ID, list[0].Created, list[0].Expires = "", time.Time{}, time.Time{}
		got, err := json.Marshal(list[0])
		require.NoError(t, err)
		assert.JSONEq(t, tc.want, string(got))
	}
	t.Run("claim with session claims", func(t *testing.T) {
		tester(t, testCase{
			q: Question{Kind: KindClaim, Source: "filter:f", Message: "m", Claim: &claims.Claim{Type: "repo", Value: "b"},
				SessionClaims: claims.Set{"repo": {"a"}}},
			want: `{"id":"","kind":"claim","source":"filter:f","message":"m","claim":{"type":"repo","value":"b"},
				"session_claims":{"repo":["a"]},"created":"0001-01-01T00:00:00Z","expires":"0001-01-01T00:00:00Z"}`,
		})
	})
	t.Run("claim with no session claims shows {}", func(t *testing.T) {
		tester(t, testCase{
			q: Question{Kind: KindClaim, Source: "filter:f", Message: "m", Claim: &claims.Claim{Type: "repo", Value: "b"}},
			want: `{"id":"","kind":"claim","source":"filter:f","message":"m","claim":{"type":"repo","value":"b"},
				"session_claims":{},"created":"0001-01-01T00:00:00Z","expires":"0001-01-01T00:00:00Z"}`,
		})
	})
	t.Run("confirm omits claim fields", func(t *testing.T) {
		tester(t, testCase{
			q:    Question{Kind: KindConfirm, Source: "filter:f", Message: "m", Claim: &claims.Claim{Type: "repo", Value: "b"}},
			want: `{"id":"","kind":"confirm","source":"filter:f","message":"m","created":"0001-01-01T00:00:00Z","expires":"0001-01-01T00:00:00Z"}`,
		})
	})
	t.Run("snapshot does not alias the asker's set", func(t *testing.T) {
		b := NewBroker(time.Minute)
		set := claims.Set{"repo": {"a"}}
		b.Raise(Question{Kind: KindClaim, Claim: &claims.Claim{Type: "repo", Value: "b"}, SessionClaims: set})
		set["repo"][0] = "changed"
		assert.Equal(t, "a", b.List()[0].SessionClaims["repo"][0])
	})
}

func TestClaimAllowedEvent(t *testing.T) {
	b := NewBroker(time.Minute)
	events, cancel := b.Subscribe()
	defer cancel()
	tk := b.Raise(Question{Kind: KindClaim, Claim: &claims.Claim{Type: "t", Value: "v"}})
	<-events
	err := b.Answer(tk.ID(), Answer{Allow: true})
	require.NoError(t, err)
	ev := <-events
	assert.True(t, ev.Allowed)
}

func TestSettle(t *testing.T) {
	t.Run("unknown id", func(t *testing.T) {
		b := NewBroker(time.Minute)
		err := b.Answer("nope", Answer{Allow: true})
		require.ErrorIs(t, err, ErrNotFound)
		err = b.Decline("nope")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("answering twice", func(t *testing.T) {
		b := NewBroker(time.Minute)
		tk := b.Raise(Question{Kind: KindConfirm})
		err := b.Answer(tk.ID(), Answer{Allow: true})
		require.NoError(t, err)
		err = b.Answer(tk.ID(), Answer{})
		require.ErrorIs(t, err, ErrNotFound)
		got, err := tk.Wait(context.Background())
		require.NoError(t, err)
		assert.True(t, got.Allow)
	})

	t.Run("decline", func(t *testing.T) {
		b := NewBroker(time.Minute)
		tk := b.Raise(Question{Kind: KindSecret})
		err := b.Decline(tk.ID())
		require.NoError(t, err)
		_, err = tk.Wait(context.Background())
		require.ErrorIs(t, err, ErrDeclined)
	})

	t.Run("expires", func(t *testing.T) {
		b := NewBroker(20 * time.Millisecond)
		_, err := b.Ask(context.Background(), Question{Kind: KindSecret})
		require.ErrorIs(t, err, ErrExpired)
		assert.Empty(t, b.List(), "expired prompt still pending")
	})

	t.Run("ctx withdraws", func(t *testing.T) {
		b := NewBroker(time.Minute)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := b.Ask(ctx, Question{Kind: KindSecret})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Empty(t, b.List(), "withdrawn prompt still pending")
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
	require.Equal(t, "pending", ev.Type)
	require.Equal(t, tk.ID(), ev.Pending.ID)
	p := <-notified
	require.Equal(t, tk.ID(), p.ID)
	listed, err := json.Marshal(b.List())
	require.NoError(t, err)

	err = b.Answer(tk.ID(), Answer{Value: secret})
	require.NoError(t, err)
	ev = <-events
	require.Equal(t, "settled", ev.Type)
	require.Equal(t, OutcomeAnswered, ev.Outcome)
	require.False(t, ev.Allowed)
	settled, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.NotContains(t, string(listed), secret)
	assert.NotContains(t, string(settled), secret)
	_, err = tk.Wait(context.Background())
	require.NoError(t, err)
}

func TestConfirmAllowedEvent(t *testing.T) {
	b := NewBroker(time.Minute)
	events, cancel := b.Subscribe()
	defer cancel()
	tk := b.Raise(Question{Kind: KindConfirm})
	<-events
	err := b.Answer(tk.ID(), Answer{Allow: true})
	require.NoError(t, err)
	ev := <-events
	assert.True(t, ev.Allowed)
	assert.Equal(t, OutcomeAnswered, ev.Outcome)
}
