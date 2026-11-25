package approval

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
)

// ErrSessionGone is returned when a claim's session ended or expired.
var ErrSessionGone = errors.New("session ended")

// ClaimStore holds the live claims of sessions. It finds a session by its
// id and instance, so a later session that reuses the id is a different
// session.
type ClaimStore interface {
	// SessionClaims returns a copy of a session's claims, and false when
	// the session has ended or expired.
	SessionClaims(s *chain.Session) (claims.Set, bool)
	// AddClaim adds a claim an operator approved through a prompt. Adding
	// a claim the session holds succeeds. It returns ErrSessionGone when the
	// session has ended or expired.
	AddClaim(s *chain.Session, c claims.Claim, filter, promptID string) error
}

// claimWait is one claim prompt shared by identical requests. While it is
// pending, its claim holds a slot against the session's limits.
type claimWait struct {
	waiting
	// session is the session id and instance.
	session  string
	instance string
	claim    claims.Claim
	// reserves is false for a shared session, which never gains claims.
	reserves bool
	// cancel withdraws the prompt.
	cancel context.CancelFunc
}

// Claims raises claim prompts on a broker and records approved claims in a
// store. It implements chain.ClaimRequester.
type Claims struct {
	b     *prompt.Broker
	store ClaimStore
	mu    sync.Mutex
	// byJoin shares one prompt among identical concurrent requests: same
	// session instance, type, and value.
	byJoin map[string]*claimWait
}

// NewClaims returns a claim requester.
func NewClaims(b *prompt.Broker, store ClaimStore) *Claims {
	return &Claims{b: b, store: store, byJoin: map[string]*claimWait{}}
}

// EndSession withdraws the pending claim prompts of a session instance.
// Their requests resolve false.
func (c *Claims) EndSession(instance string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, w := range c.byJoin {
		if w.instance == instance {
			w.cancel()
		}
	}
}

// RequestClaim resolves true when the session holds the claim or the
// operator allows it. "For this session" adds the claim, except on a
// shared session, where it counts as once. Denials are not remembered.
func (c *Claims) RequestClaim(ctx context.Context, r chain.ClaimRequest) (bool, error) {
	err := claims.Valid(r.Claim.Type, r.Claim.Value)
	if err != nil {
		return false, fmt.Errorf("%w: %w", chain.ErrClaimRejected, err)
	}
	if r.Session == nil {
		return false, errors.New("claim request has no session")
	}
	sess := r.Session
	sk := sess.ID + "\x00" + sess.Instance
	jk := sk + "\x00" + r.Claim.Type + "\x00" + r.Claim.Value

	// The store check, the join, and the reservation happen under mu, and
	// an approved claim is stored before its join entry goes away, so a
	// request never prompts for a claim that a settled prompt just added.
	c.mu.Lock()
	current := claims.Set{}
	if !sess.Shared {
		var ok bool
		current, ok = c.store.SessionClaims(sess)
		if !ok {
			c.mu.Unlock()
			return false, ErrSessionGone
		}
	}
	if current.Has(r.Claim.Type, r.Claim.Value) {
		c.mu.Unlock()
		return true, nil
	}
	if w, ok := c.byJoin[jk]; ok {
		c.mu.Unlock()
		select {
		case <-w.done:
			return w.allow, nil
		case <-ctx.Done():
			return false, fmt.Errorf("claim prompt %s: %w", w.id, ctx.Err())
		}
	}
	// Pending prompts hold their slots, so every grant an operator approves
	// fits within the limits.
	err = c.reservedLocked(sk, current).Check(r.Claim.Type, r.Claim.Value)
	if err != nil {
		c.mu.Unlock()
		return false, fmt.Errorf("%w: %w", chain.ErrClaimRejected, err)
	}
	claim := r.Claim
	t := c.b.Raise(prompt.Question{
		Kind: prompt.KindClaim, Source: "filter:" + r.Filter, Message: r.Prompt, Detail: r.Request, Origin: r.Origin,
		SessionID: sess.ID, SessionLabel: sess.Label, Profile: sess.Profile,
		Claim: &claim, SessionClaims: current,
	})
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := &claimWait{
		waiting:  waiting{id: t.ID(), done: make(chan struct{})},
		session:  sk,
		instance: sess.Instance,
		claim:    claim,
		reserves: !sess.Shared,
		cancel:   cancel,
	}
	c.byJoin[jk] = w
	c.mu.Unlock()

	ans, err := t.Wait(wctx)
	allow := err == nil && ans.Allow

	c.mu.Lock()
	var addErr error
	if allow && ans.Remember && !sess.Shared {
		addErr = c.store.AddClaim(sess, claim, r.Filter, t.ID())
	}
	gone := errors.Is(addErr, ErrSessionGone)
	delete(c.byJoin, jk)
	w.allow = allow && !gone
	close(w.done)
	c.mu.Unlock()

	switch {
	case err != nil:
		return false, fmt.Errorf("claim prompt: %w", err)
	case gone:
		// The session ended or expired while the operator decided.
		return false, fmt.Errorf("claim %s not added: %w", claim.Type, addErr)
	case addErr != nil:
		// The operator allowed this request, so it goes through once.
		return true, fmt.Errorf("claim %s allowed once, not added: %w", claim.Type, addErr)
	}
	return allow, nil
}

// reservedLocked returns current plus the claims of the session's pending
// prompts. Caller holds mu.
func (c *Claims) reservedLocked(session string, current claims.Set) claims.Set {
	out := current.Clone()
	for _, w := range c.byJoin {
		if w.reserves && w.session == session {
			// Each was checked against the limits when it was raised.
			_, _ = out.Add(w.claim.Type, w.claim.Value)
		}
	}
	return out
}
