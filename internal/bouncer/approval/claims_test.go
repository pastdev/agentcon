package approval

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

// memStore is an in-memory ClaimStore keyed by session id and instance.
type memStore struct {
	mu       sync.Mutex
	sessions map[string]claims.Set
	added    []string // "type=value filter prompt"
	addErr   error
}

func storeKey(id, instance string) string { return id + "\x00" + instance }

// newMemStore holds sessions by id, with no instance.
func newMemStore(sessions map[string]claims.Set) *memStore {
	s := &memStore{sessions: map[string]claims.Set{}}
	for id, set := range sessions {
		s.sessions[storeKey(id, "")] = set
	}
	return s
}

func (s *memStore) SessionClaims(sess *chain.Session) (claims.Set, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.sessions[storeKey(sess.ID, sess.Instance)]
	return c.Clone(), ok
}

// end removes an instance of session s1, as ending or expiry does.
func (s *memStore) end(instance string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, storeKey("s1", instance))
}

// put adds an instance of session s1.
func (s *memStore) put(instance string, set claims.Set) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[storeKey("s1", instance)] = set
}

func (s *memStore) AddClaim(sess *chain.Session, c claims.Claim, filter, promptID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.addErr != nil {
		return s.addErr
	}
	set, ok := s.sessions[storeKey(sess.ID, sess.Instance)]
	if !ok {
		return ErrSessionGone
	}
	added, err := set.Add(c.Type, c.Value)
	if err != nil {
		return fmt.Errorf("add claim: %w", err)
	}
	if added {
		s.added = append(s.added, fmt.Sprintf("%s=%s %s %s", c.Type, c.Value, filter, promptID))
	}
	return nil
}

func (s *memStore) get(id string) claims.Set {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[storeKey(id, "")].Clone()
}

func claimReq(sess *chain.Session, value string) chain.ClaimRequest {
	return chain.ClaimRequest{
		Session: sess, Filter: "scope", Prompt: "add " + value + "?",
		Claim: claims.Claim{Type: "repository", Value: value}, Request: "POST x",
	}
}

// answerNext answers the next pending prompt and returns it.
func answerNext(t *testing.T, b *prompt.Broker, events <-chan prompt.Event, a prompt.Answer) prompt.Pending {
	t.Helper()
	for ev := range events {
		if ev.Type != "pending" {
			continue
		}
		require.NoError(t, b.Answer(ev.Pending.ID, a))
		return ev.Pending
	}
	t.Fatal("events closed")
	return prompt.Pending{}
}

func TestRequestClaim(t *testing.T) {
	type testCase struct {
		// answer settles the prompt. Nil means none is expected.
		answer   *prompt.Answer
		decline  bool
		timeout  time.Duration
		session  *chain.Session
		start    map[string]claims.Set
		addErr   error
		value    string
		wantOK   bool
		wantErr  error
		wantSet  claims.Set
		wantPend func(*testing.T, prompt.Pending)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		timeout := tc.timeout
		if timeout == 0 {
			timeout = time.Minute
		}
		b := prompt.NewBroker(timeout)
		store := newMemStore(tc.start)
		store.addErr = tc.addErr
		c := NewClaims(b, store)
		events, cancel := b.Subscribe()
		defer cancel()
		type result struct {
			ok  bool
			err error
		}
		done := make(chan result, 1)
		go func() {
			ok, err := c.RequestClaim(context.Background(), claimReq(tc.session, tc.value))
			done <- result{ok, err}
		}()
		switch {
		case tc.answer != nil:
			p := answerNext(t, b, events, *tc.answer)
			if tc.wantPend != nil {
				tc.wantPend(t, p)
			}
		case tc.decline:
			ev := <-events
			require.NoError(t, b.Decline(ev.Pending.ID))
		}
		r := <-done
		assert.Equal(t, tc.wantOK, r.ok)
		if tc.wantErr != nil {
			require.ErrorIs(t, r.err, tc.wantErr)
		} else if tc.timeout == 0 && !tc.decline {
			require.NoError(t, r.err)
		}
		if tc.session != nil && !tc.session.Shared {
			assert.Equal(t, tc.wantSet, store.get(tc.session.ID))
		}
		assert.Empty(t, b.List(), "prompt left pending")
	}
	s1 := &chain.Session{ID: "s1", Label: "agent", Profile: "p"}
	seeded := func() map[string]claims.Set { return map[string]claims.Set{"s1": {"repository": {"g/a"}}} }

	t.Run("held claim resolves without a prompt", func(t *testing.T) {
		tester(t, testCase{session: s1, start: seeded(), value: "g/a", wantOK: true, wantSet: claims.Set{"repository": {"g/a"}}})
	})
	t.Run("for this session adds the claim", func(t *testing.T) {
		tester(t, testCase{
			session: s1, start: seeded(), value: "g/b", answer: &prompt.Answer{Allow: true, Remember: true},
			wantOK: true, wantSet: claims.Set{"repository": {"g/a", "g/b"}},
			wantPend: func(t *testing.T, p prompt.Pending) {
				t.Helper()
				assert.Equal(t, prompt.KindClaim, p.Kind)
				assert.Equal(t, "filter:scope", p.Source)
				assert.Equal(t, "add g/b?", p.Message)
				assert.Equal(t, "POST x", p.Detail)
				assert.Equal(t, &claims.Claim{Type: "repository", Value: "g/b"}, p.Claim)
				assert.Equal(t, claims.Set{"repository": {"g/a"}}, p.SessionClaims)
				assert.Equal(t, "agent", p.SessionLabel)
			},
		})
	})
	t.Run("once allows and adds nothing", func(t *testing.T) {
		tester(t, testCase{
			session: s1, start: seeded(), value: "g/b", answer: &prompt.Answer{Allow: true},
			wantOK: true, wantSet: claims.Set{"repository": {"g/a"}},
		})
	})
	t.Run("deny resolves false", func(t *testing.T) {
		tester(t, testCase{
			session: s1, start: seeded(), value: "g/b", answer: &prompt.Answer{},
			wantOK: false, wantSet: claims.Set{"repository": {"g/a"}},
		})
	})
	t.Run("decline resolves false", func(t *testing.T) {
		tester(t, testCase{
			session: s1, start: seeded(), value: "g/b", decline: true,
			wantOK: false, wantErr: prompt.ErrDeclined, wantSet: claims.Set{"repository": {"g/a"}},
		})
	})
	t.Run("timeout resolves false", func(t *testing.T) {
		tester(t, testCase{
			session: s1, start: seeded(), value: "g/b", timeout: 10 * time.Millisecond,
			wantOK: false, wantErr: prompt.ErrExpired, wantSet: claims.Set{"repository": {"g/a"}},
		})
	})
	t.Run("invalid value is rejected without a prompt", func(t *testing.T) {
		tester(t, testCase{session: s1, start: seeded(), value: "g/\nb", wantErr: chain.ErrClaimRejected, wantSet: claims.Set{"repository": {"g/a"}}})
	})
	t.Run("over the value limit is rejected without a prompt", func(t *testing.T) {
		full := claims.Set{"repository": {}}
		for i := range claims.MaxValues {
			full["repository"] = append(full["repository"], fmt.Sprintf("v%03d", i))
		}
		tester(t, testCase{
			session: s1, start: map[string]claims.Set{"s1": full}, value: "zzz",
			wantErr: chain.ErrClaimRejected, wantSet: full,
		})
	})
	t.Run("ended session resolves false without a prompt", func(t *testing.T) {
		tester(t, testCase{session: s1, start: map[string]claims.Set{}, value: "g/b", wantErr: ErrSessionGone, wantSet: claims.Set{}})
	})
	t.Run("a failed add still allows once", func(t *testing.T) {
		tester(t, testCase{
			session: s1, start: seeded(), value: "g/b", answer: &prompt.Answer{Allow: true, Remember: true},
			addErr: claims.ErrLimit, wantOK: true, wantErr: claims.ErrLimit, wantSet: claims.Set{"repository": {"g/a"}},
		})
	})
	t.Run("shared session prompts with no claims and never gains one", func(t *testing.T) {
		tester(t, testCase{
			session: &chain.Session{ID: "anonymous", Shared: true}, start: map[string]claims.Set{}, value: "g/b",
			answer: &prompt.Answer{Allow: true, Remember: true}, wantOK: true,
			wantPend: func(t *testing.T, p prompt.Pending) {
				t.Helper()
				assert.Equal(t, claims.Set{}, p.SessionClaims)
			},
		})
	})
}

func TestRequestClaimSequences(t *testing.T) {
	t.Run("a denial is not remembered", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		store := newMemStore(map[string]claims.Set{"s1": {}})
		c := NewClaims(b, store)
		events, cancel := b.Subscribe()
		defer cancel()
		sess := &chain.Session{ID: "s1"}
		for i := range 2 {
			done := make(chan bool, 1)
			go func() {
				ok, _ := c.RequestClaim(context.Background(), claimReq(sess, "g/b"))
				done <- ok
			}()
			answerNext(t, b, events, prompt.Answer{})
			assert.False(t, <-done, "attempt %d", i+1)
		}
	})
	t.Run("an added claim stops further prompts", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		store := newMemStore(map[string]claims.Set{"s1": {}})
		c := NewClaims(b, store)
		events, cancel := b.Subscribe()
		defer cancel()
		sess := &chain.Session{ID: "s1"}
		done := make(chan bool, 1)
		go func() {
			ok, _ := c.RequestClaim(context.Background(), claimReq(sess, "g/b"))
			done <- ok
		}()
		p := answerNext(t, b, events, prompt.Answer{Allow: true, Remember: true})
		require.True(t, <-done)
		assert.Equal(t, []string{"repository=g/b scope " + p.ID}, store.added)
		ok, err := c.RequestClaim(context.Background(), claimReq(sess, "g/b"))
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Empty(t, b.List())
	})
	t.Run("concurrent identical requests share one prompt", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		store := newMemStore(map[string]claims.Set{"s1": {}})
		c := NewClaims(b, store)
		events, cancel := b.Subscribe()
		defer cancel()
		sess := &chain.Session{ID: "s1"}
		var wg sync.WaitGroup
		results := make([]bool, 5)
		for i := range results {
			wg.Go(func() {
				results[i], _ = c.RequestClaim(context.Background(), claimReq(sess, "g/b"))
			})
		}
		ev := <-events
		require.Equal(t, "pending", ev.Type)
		time.Sleep(20 * time.Millisecond)
		require.Len(t, b.List(), 1, "expected one shared prompt")
		require.NoError(t, b.Answer(ev.Pending.ID, prompt.Answer{Allow: true, Remember: true}))
		wg.Wait()
		assert.Equal(t, []bool{true, true, true, true, true}, results)
		assert.Len(t, store.added, 1)
	})
	t.Run("different claims or sessions get separate prompts", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		store := newMemStore(map[string]claims.Set{"s1": {}, "s2": {}})
		c := NewClaims(b, store)
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		for _, r := range []chain.ClaimRequest{
			claimReq(&chain.Session{ID: "s1"}, "g/b"),
			claimReq(&chain.Session{ID: "s1"}, "g/c"),
			claimReq(&chain.Session{ID: "s2"}, "g/b"),
		} {
			wg.Go(func() { _, _ = c.RequestClaim(ctx, r) })
		}
		require.Eventually(t, func() bool { return len(b.List()) == 3 }, time.Second, 5*time.Millisecond)
		cancel()
		wg.Wait()
		assert.Empty(t, b.List(), "withdrawn prompts still pending")
	})
	t.Run("ending a session withdraws its pending prompt", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		store := newMemStore(nil)
		store.put("i1", claims.Set{})
		c := NewClaims(b, store)
		events, cancel := b.Subscribe()
		defer cancel()
		sess := &chain.Session{ID: "s1", Instance: "i1"}
		results := make(chan bool, 2)
		for range 2 {
			go func() {
				ok, _ := c.RequestClaim(context.Background(), claimReq(sess, "g/b"))
				results <- ok
			}()
		}
		<-events
		time.Sleep(20 * time.Millisecond)
		store.end("i1")
		c.EndSession("i1")
		assert.False(t, <-results)
		assert.False(t, <-results)
		assert.Empty(t, b.List(), "withdrawn prompt still pending")
		for ev := range events {
			if ev.Type == "settled" {
				assert.Equal(t, prompt.OutcomeWithdrawn, ev.Outcome)
				break
			}
		}
	})
	t.Run("ending one instance leaves another's prompts", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		store := newMemStore(nil)
		store.put("i2", claims.Set{})
		c := NewClaims(b, store)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _, _ = c.RequestClaim(ctx, claimReq(&chain.Session{ID: "s1", Instance: "i2"}, "g/b")) }()
		require.Eventually(t, func() bool { return len(b.List()) == 1 }, time.Second, 5*time.Millisecond)
		c.EndSession("i1")
		time.Sleep(20 * time.Millisecond)
		assert.Len(t, b.List(), 1)
	})
	t.Run("a reused session id is a different session", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		store := newMemStore(nil)
		store.put("old", claims.Set{})
		c := NewClaims(b, store)
		old := make(chan bool, 1)
		go func() {
			ok, _ := c.RequestClaim(context.Background(), claimReq(&chain.Session{ID: "s1", Instance: "old"}, "g/b"))
			old <- ok
		}()
		require.Eventually(t, func() bool { return len(b.List()) == 1 }, time.Second, 5*time.Millisecond)
		oldPrompt := b.List()[0]

		// The old session ends without withdrawing, as expiry does, and a
		// new session takes its id.
		store.end("old")
		store.put("new", claims.Set{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _, _ = c.RequestClaim(ctx, claimReq(&chain.Session{ID: "s1", Instance: "new"}, "g/b")) }()
		require.Eventually(t, func() bool { return len(b.List()) == 2 }, time.Second, 5*time.Millisecond)

		require.NoError(t, b.Answer(oldPrompt.ID, prompt.Answer{Allow: true, Remember: true}))
		assert.False(t, <-old, "an approval for an expired session went through")
		got, ok := store.SessionClaims(&chain.Session{ID: "s1", Instance: "new"})
		require.True(t, ok)
		assert.Equal(t, claims.Set{}, got, "the new session gained the old session's claim")
		assert.Empty(t, store.added)
	})
	t.Run("a joiner leaves when its context ends", func(t *testing.T) {
		b := prompt.NewBroker(time.Minute)
		store := newMemStore(map[string]claims.Set{"s1": {}})
		c := NewClaims(b, store)
		events, cancel := b.Subscribe()
		defer cancel()
		sess := &chain.Session{ID: "s1"}
		first := make(chan bool, 1)
		go func() {
			ok, _ := c.RequestClaim(context.Background(), claimReq(sess, "g/b"))
			first <- ok
		}()
		ev := <-events
		ctx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer stop()
		ok, err := c.RequestClaim(ctx, claimReq(sess, "g/b"))
		assert.False(t, ok)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.NoError(t, b.Answer(ev.Pending.ID, prompt.Answer{Allow: true}))
		assert.True(t, <-first)
	})
}
