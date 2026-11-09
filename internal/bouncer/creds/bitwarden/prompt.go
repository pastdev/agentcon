package bitwarden

import (
	"context"
	"fmt"

	"github.com/pastdev/agentcon/internal/bouncer/prompt"
)

// Prompter supplies the master password and, when the server asks, a
// second factor. Each attempt asks again. attempt counts from 1, and a
// later attempt follows a rejected answer.
type Prompter interface {
	MasterPassword(ctx context.Context, label string, attempt, attempts int) (string, error)
	TwoFactorCode(ctx context.Context, label, method string, attempt, attempts int) (string, error)
}

// BrokerPrompter asks for Bitwarden secrets through a prompt broker, so
// whoever answers prompts (a terminal, the CLI, agentcon run) can unlock a
// vault. Each question belongs to one account and one attempt, and its
// answer goes only to that attempt.
func BrokerPrompter(b *prompt.Broker) Prompter {
	return brokerPrompter{b: b}
}

type brokerPrompter struct {
	b *prompt.Broker
}

func (p brokerPrompter) MasterPassword(ctx context.Context, label string, attempt, attempts int) (string, error) {
	msg := "Bitwarden master password"
	if attempt > 1 {
		msg += fmt.Sprintf(" (incorrect, attempt %d of %d)", attempt, attempts)
	}
	return p.ask(ctx, prompt.KindSecret, label, msg)
}

func (p brokerPrompter) TwoFactorCode(ctx context.Context, label, method string, attempt, attempts int) (string, error) {
	msg := "Bitwarden verification code"
	if method != "" {
		msg += " for " + method
	}
	if attempt > 1 {
		msg += fmt.Sprintf(" (rejected, attempt %d of %d)", attempt, attempts)
	}
	return p.ask(ctx, prompt.KindText, label, msg)
}

func (p brokerPrompter) ask(ctx context.Context, kind prompt.Kind, label, msg string) (string, error) {
	a, err := p.b.Ask(ctx, prompt.Question{Kind: kind, Source: "bitwarden:" + label, Message: msg})
	if err != nil {
		return "", fmt.Errorf("ask: %w", err)
	}
	return a.Value, nil
}
