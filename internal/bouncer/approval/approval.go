// Package approval asks a human to allow or deny requests, remembering
// per-session decisions.
package approval

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/prompt"
)

// Manager raises confirm questions on a prompt broker. It coalesces
// identical concurrent asks into one question and remembers session-wide
// answers.
type Manager struct {
	b          *prompt.Broker
	mu         sync.Mutex
	byJoin     map[string]*waiting
	remembered map[string]bool
}

// waiting is one question shared by identical asks.
type waiting struct {
	id    string
	key   string // remember key: session + ask key
	done  chan struct{}
	allow bool
}

func NewManager(b *prompt.Broker) *Manager {
	return &Manager{b: b, byJoin: map[string]*waiting{}, remembered: map[string]bool{}}
}

func rememberKey(sessionID, key string) string { return sessionID + "\x00" + key }

// Ask blocks until the request is approved, denied, times out, or ctx ends.
// Identical concurrent asks from one session share a single prompt.
func (m *Manager) Ask(ctx context.Context, a chain.AskRequest) (bool, error) {
	// Without an explicit key, a decision covers only this exact request:
	// keying on the prompt alone would let one approval of a static prompt
	// cover unrelated requests.
	key := a.Key
	if key == "" {
		key = a.Prompt + "\x00" + a.Request
	}
	sid, label, profile, shared := "", "", "", false
	if a.Session != nil {
		sid, label, profile, shared = a.Session.ID, a.Session.Label, a.Session.Profile, a.Session.Shared
	}
	rk := rememberKey(sid, key)
	// Only identical requests share a pending prompt, so the human always
	// sees the request their answer applies to.
	jk := rk + "\x00" + a.Request

	m.mu.Lock()
	if v, ok := m.remembered[rk]; ok {
		m.mu.Unlock()
		return v, nil
	}
	if w, ok := m.byJoin[jk]; ok {
		m.mu.Unlock()
		// Joiners just leave when their ctx ends; the question stays for
		// the original asker.
		select {
		case <-w.done:
			return w.allow, nil
		case <-ctx.Done():
			return false, fmt.Errorf("approval %s: %w", w.id, ctx.Err())
		}
	}
	t := m.b.Raise(prompt.Question{
		Kind: prompt.KindConfirm, Source: "filter:" + a.Filter, Message: a.Prompt, Detail: a.Request,
		SessionID: sid, SessionLabel: label, Profile: profile,
	})
	w := &waiting{id: t.ID(), key: rk, done: make(chan struct{})}
	m.byJoin[jk] = w
	m.mu.Unlock()

	ans, err := t.Wait(ctx)
	allow := err == nil && ans.Allow

	m.mu.Lock()
	delete(m.byJoin, jk)
	w.allow = allow
	close(w.done)
	var covered []string
	if err == nil && ans.Remember && !shared {
		m.remembered[rk] = allow
		// A session-wide answer also settles other pending asks it covers.
		for _, o := range m.byJoin {
			if o.key == rk {
				covered = append(covered, o.id)
			}
		}
	}
	m.mu.Unlock()
	for _, id := range covered {
		// Another answer may have settled it first, which is fine.
		_ = m.b.Answer(id, prompt.Answer{Allow: allow})
	}
	if err != nil {
		return false, fmt.Errorf("approval: %w", err)
	}
	return allow, nil
}

// ForgetSession drops remembered decisions for a session.
func (m *Manager) ForgetSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := sessionID + "\x00"
	for k := range m.remembered {
		if strings.HasPrefix(k, prefix) {
			delete(m.remembered, k)
		}
	}
}
