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

// ClaimStore holds the live claims of sessions.
type ClaimStore interface {
	// SessionClaims returns a copy of a session's claims, and false when
	// the session has ended or expired.
	SessionClaims(sessionID string) (claims.Set, bool)
	// AddClaim adds a claim an operator approved through a prompt. Adding
	// a claim the session holds succeeds.
	AddClaim(sessionID string, c claims.Claim, filter, promptID string) error
}

// Claims raises claim prompts on a broker and records approved claims in a
// store. It implements chain.ClaimRequester.
type Claims struct {
	b     *prompt.Broker
	store ClaimStore
	mu    sync.Mutex
	// byJoin shares one prompt among identical concurrent requests: same
	// session, type, and value.
	byJoin map[string]*waiting
}

// NewClaims returns a claim requester.
func NewClaims(b *prompt.Broker, store ClaimStore) *Claims {
	return &Claims{b: b, store: store, byJoin: map[string]*waiting{}}
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
	jk := sess.ID + "\x00" + r.Claim.Type + "\x00" + r.Claim.Value

	// The store check and the join happen under mu, and an approved claim
	// is stored before its join entry goes away, so a request never prompts
	// for a claim that a settled prompt just added.
	c.mu.Lock()
	current := claims.Set{}
	if !sess.Shared {
		var ok bool
		current, ok = c.store.SessionClaims(sess.ID)
		if !ok {
			c.mu.Unlock()
			return false, ErrSessionGone
		}
	}
	if current.Has(r.Claim.Type, r.Claim.Value) {
		c.mu.Unlock()
		return true, nil
	}
	err = current.Check(r.Claim.Type, r.Claim.Value)
	if err != nil {
		c.mu.Unlock()
		return false, fmt.Errorf("%w: %w", chain.ErrClaimRejected, err)
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
	claim := r.Claim
	t := c.b.Raise(prompt.Question{
		Kind: prompt.KindClaim, Source: "filter:" + r.Filter, Message: r.Prompt, Detail: r.Request,
		SessionID: sess.ID, SessionLabel: sess.Label, Profile: sess.Profile,
		Claim: &claim, SessionClaims: current,
	})
	w := &waiting{id: t.ID(), done: make(chan struct{})}
	c.byJoin[jk] = w
	c.mu.Unlock()

	ans, err := t.Wait(ctx)
	allow := err == nil && ans.Allow

	c.mu.Lock()
	var addErr error
	if allow && ans.Remember && !sess.Shared {
		addErr = c.store.AddClaim(sess.ID, claim, r.Filter, t.ID())
	}
	delete(c.byJoin, jk)
	w.allow = allow
	close(w.done)
	c.mu.Unlock()

	switch {
	case err != nil:
		return false, fmt.Errorf("claim prompt: %w", err)
	case addErr != nil:
		// The operator allowed this request, so it goes through once.
		return true, fmt.Errorf("claim %s allowed once, not added: %w", claim.Type, addErr)
	}
	return allow, nil
}
