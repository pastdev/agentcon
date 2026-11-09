// Package prompt holds questions waiting on a human answer.
package prompt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Kind is the kind of answer a question expects.
type Kind string

const (
	// KindConfirm expects allow or deny.
	KindConfirm Kind = "confirm"
	// KindText expects a value that may be shown as it is typed.
	KindText Kind = "text"
	// KindSecret expects a value that must not be echoed.
	KindSecret Kind = "secret"
)

// Outcomes of a settled question.
const (
	OutcomeAnswered  = "answered"
	OutcomeDeclined  = "declined"
	OutcomeExpired   = "expired"
	OutcomeWithdrawn = "withdrawn"
)

var (
	// ErrNotFound is returned when no pending question has the id.
	ErrNotFound = errors.New("no such pending prompt")
	// ErrInvalidAnswer is returned when an answer does not fit the question's kind.
	ErrInvalidAnswer = errors.New("answer does not fit the prompt")
	// ErrDeclined is returned to the asker when the human declines.
	ErrDeclined = errors.New("prompt declined")
	// ErrExpired is returned to the asker when nobody answers in time.
	ErrExpired = errors.New("prompt timed out")
)

// Question is what an asker wants to know.
type Question struct {
	Kind Kind
	// Source names the asker, for example "filter:github-write" or
	// "bitwarden:you@example.com".
	Source  string
	Message string
	// Detail is context for the human, such as the request being approved.
	Detail       string
	SessionID    string
	SessionLabel string
	Profile      string
}

// Answer is the human's reply. Allow and Remember apply to a confirm.
// Value applies to text and secret.
type Answer struct {
	Allow    bool
	Remember bool
	Value    string
}

// Pending is a question awaiting an answer. It never holds the answer.
type Pending struct {
	ID           string    `json:"id"`
	Kind         Kind      `json:"kind"`
	Source       string    `json:"source"`
	Message      string    `json:"message"`
	Detail       string    `json:"detail,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	SessionLabel string    `json:"session_label,omitempty"`
	Profile      string    `json:"profile,omitempty"`
	Created      time.Time `json:"created"`
	Expires      time.Time `json:"expires"`
}

// Event notifies subscribers of changes. Allowed is set only for an
// answered confirm.
type Event struct {
	Type    string // "pending" or "settled"
	Pending Pending
	Outcome string
	Allowed bool
}

type result struct {
	answer Answer
	err    error
}

type entry struct {
	Pending
	// done carries the one result to the asker. It is buffered so settling
	// never blocks, and nothing else keeps the answer.
	done chan result
}

// Broker tracks pending questions and hands each answer to its asker.
type Broker struct {
	mu      sync.Mutex
	timeout time.Duration
	notify  func(Pending)
	pending map[string]*entry
	subs    map[chan Event]struct{}
}

// NewBroker returns a broker whose questions expire after timeout.
func NewBroker(timeout time.Duration) *Broker {
	return &Broker{timeout: timeout, pending: map[string]*entry{}, subs: map[chan Event]struct{}{}}
}

// SetTimeout changes the timeout for future questions.
func (b *Broker) SetTimeout(d time.Duration) {
	b.mu.Lock()
	b.timeout = d
	b.mu.Unlock()
}

// SetNotify sets a function called, in a goroutine, for each new question.
// Nil disables it.
func (b *Broker) SetNotify(f func(Pending)) {
	b.mu.Lock()
	b.notify = f
	b.mu.Unlock()
}

// Ticket is a raised question. Wait for its answer exactly once.
type Ticket struct {
	b *Broker
	e *entry
}

// ID returns the question's id.
func (t *Ticket) ID() string { return t.e.ID }

// Raise records a question and returns without waiting, so the asker can
// learn its id before blocking.
func (b *Broker) Raise(q Question) *Ticket {
	b.mu.Lock()
	now := time.Now()
	e := &entry{
		Pending: Pending{
			ID: b.newID(), Kind: q.Kind, Source: q.Source, Message: q.Message, Detail: q.Detail,
			SessionID: q.SessionID, SessionLabel: q.SessionLabel, Profile: q.Profile,
			Created: now, Expires: now.Add(b.timeout),
		},
		done: make(chan result, 1),
	}
	b.pending[e.ID] = e
	b.broadcast(Event{Type: "pending", Pending: e.Pending})
	notify := b.notify
	b.mu.Unlock()
	if notify != nil {
		go notify(e.Pending)
	}
	return &Ticket{b: b, e: e}
}

// Wait blocks until the question is answered, declined, expires, or ctx
// ends. When ctx ends first, the question is withdrawn.
func (t *Ticket) Wait(ctx context.Context) (Answer, error) {
	timer := time.NewTimer(time.Until(t.e.Expires))
	defer timer.Stop()
	select {
	case r := <-t.e.done:
		return r.answer, r.err
	case <-timer.C:
		t.b.settle(t.e.ID, result{err: ErrExpired}, OutcomeExpired)
	case <-ctx.Done():
		t.b.settle(t.e.ID, result{err: fmt.Errorf("prompt %s: %w", t.e.ID, ctx.Err())}, OutcomeWithdrawn)
	}
	// Settling above loses to a concurrent answer, so take whatever won.
	r := <-t.e.done
	return r.answer, r.err
}

// Ask raises a question and waits for its answer.
func (b *Broker) Ask(ctx context.Context, q Question) (Answer, error) {
	return b.Raise(q).Wait(ctx)
}

// Answer settles a pending question with the human's reply.
func (b *Broker) Answer(id string, a Answer) error {
	b.mu.Lock()
	e, ok := b.pending[id]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	switch e.Kind {
	case KindConfirm:
		if a.Value != "" {
			return fmt.Errorf("%w: a confirm takes allow, not a value", ErrInvalidAnswer)
		}
	case KindText, KindSecret:
		if a.Value == "" || a.Allow || a.Remember {
			return fmt.Errorf("%w: a %s prompt takes only a non-empty value", ErrInvalidAnswer, e.Kind)
		}
	}
	if !b.settle(id, result{answer: a}, OutcomeAnswered) {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

// Decline settles a pending question without an answer.
func (b *Broker) Decline(id string) error {
	if !b.settle(id, result{err: ErrDeclined}, OutcomeDeclined) {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

// settle delivers r to the asker once. It reports false when the question
// was already settled.
func (b *Broker) settle(id string, r result, outcome string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.pending[id]
	if !ok {
		return false
	}
	delete(b.pending, id)
	e.done <- r
	b.broadcast(Event{
		Type:    "settled",
		Pending: e.Pending,
		Outcome: outcome,
		Allowed: e.Kind == KindConfirm && r.err == nil && r.answer.Allow,
	})
	return true
}

// List returns pending questions, oldest first.
func (b *Broker) List() []Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Pending, 0, len(b.pending))
	for _, e := range b.pending {
		out = append(out, e.Pending)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// Subscribe returns a channel of events and a cancel func. A slow
// subscriber misses events rather than blocking the broker.
func (b *Broker) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
}

// broadcast sends e to subscribers. Caller holds mu.
func (b *Broker) broadcast(e Event) {
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// newID returns an id not already pending. Caller holds mu.
func (b *Broker) newID() string {
	for {
		buf := make([]byte, 3)
		rand.Read(buf)
		id := hex.EncodeToString(buf)
		if _, taken := b.pending[id]; !taken {
			return id
		}
	}
}
