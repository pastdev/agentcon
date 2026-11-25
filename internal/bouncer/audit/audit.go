// Package audit logs one event per policy decision, session creation, and
// claim addition. Every line carries an event field naming its kind. The
// field names are stable, because hosts send audit logs to log ingestion.
package audit

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/pastdev/agentcon/pkg/bouncer/claims"
)

// Events recorded in the event field.
const (
	EventDecision       = "decision"
	EventSessionCreated = "session_created"
	EventClaimAdded     = "claim_added"
)

// Decisions recorded on an Entry.
const (
	DecisionAllow  = "allow"
	DecisionDeny   = "deny"
	DecisionTunnel = "tunnel"
	DecisionError  = "error"
)

// Entry is one audit record. Its JSON names match the logged fields.
type Entry struct {
	// Event is always EventDecision when logged.
	Event      string `json:"event,omitempty"`
	Session    string `json:"session,omitempty"`
	Label      string `json:"label,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Transport  string `json:"transport"`
	Service    string `json:"service,omitempty"`
	Request    string `json:"request"`
	Decision   string `json:"decision"` // one of the Decision* constants
	By         string `json:"by,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Status     int    `json:"status,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	// Subrequest is set when a filter made the request with subrequest().
	Subrequest *Subrequest `json:"subrequest,omitempty"`
}

// Subrequest names the filter that made a subrequest, its nesting depth,
// and the request that caused it.
type Subrequest struct {
	Filter string `json:"filter"`
	Depth  int    `json:"depth"`
	Parent string `json:"parent"`
}

// Log writes entries to a logger.
type Log struct {
	log zerolog.Logger
}

// New logs entries to log.
func New(log zerolog.Logger) *Log {
	return &Log{log: log}
}

// Write logs e at the level of its decision, with the summary as the
// message.
func (l *Log) Write(e Entry) {
	ev := l.log.WithLevel(level(e.Decision))
	str := func(key, value string) {
		if value != "" {
			ev.Str(key, value)
		}
	}
	ev.Str("event", EventDecision)
	str("session", e.Session)
	str("label", e.Label)
	str("profile", e.Profile)
	ev.Str("transport", e.Transport)
	str("service", e.Service)
	ev.Str("request", e.Request)
	ev.Str("decision", e.Decision)
	str("by", e.By)
	str("reason", e.Reason)
	if e.Status != 0 {
		ev.Int("status", e.Status)
	}
	ev.Int64("duration_ms", e.DurationMS)
	if sr := e.Subrequest; sr != nil {
		ev.Dict("subrequest", zerolog.Dict().Str("filter", sr.Filter).Int("depth", sr.Depth).Str("parent", sr.Parent))
	}
	ev.Msg(Summary(e))
}

func level(decision string) zerolog.Level {
	switch decision {
	case DecisionTunnel:
		return zerolog.DebugLevel
	case DecisionDeny:
		return zerolog.WarnLevel
	case DecisionError:
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// Summary is the one-line message for an entry.
func Summary(e Entry) string {
	s := fmt.Sprintf("%-6s [%s] %s", strings.ToUpper(e.Decision), who(e.Label, e.Session), e.Request)
	if e.Status != 0 && e.Decision == DecisionAllow {
		s += fmt.Sprintf(" -> %d", e.Status)
	}
	switch {
	case e.Decision == DecisionDeny || e.Decision == DecisionError:
		s += fmt.Sprintf("  (%s: %s)", e.By, e.Reason)
	case e.By != "":
		s += fmt.Sprintf("  (%s)", e.By)
	}
	if e.Subrequest != nil {
		s += fmt.Sprintf("  [subrequest from %s]", e.Subrequest.Filter)
	}
	return s
}

// SessionCreated logs a new session with its initial claims, {} when it
// has none.
func (l *Log) SessionCreated(session, label, profile string, c claims.Set) {
	c = c.Clone()
	l.log.Info().
		Str("event", EventSessionCreated).
		Str("session", session).
		Str("label", label).
		Str("profile", profile).
		Interface("claims", c).
		Msgf("SESSION [%s] created profile=%s claims=%d", who(label, session), profile, c.Count())
}

// ClaimEvent is one claim joining a session.
type ClaimEvent struct {
	Session string
	Label   string
	Claim   claims.Claim
	// AddedBy is claims.AddedSeeded or claims.AddedOperator.
	AddedBy string
	// Filter and Prompt name the filter that asked and the prompt the
	// operator answered. They are empty for seeded claims.
	Filter string
	Prompt string
}

// ClaimAdded logs a claim joining a session.
func (l *Log) ClaimAdded(e ClaimEvent) {
	ev := l.log.Info().
		Str("event", EventClaimAdded).
		Str("session", e.Session).
		Str("label", e.Label).
		Str("claim_type", e.Claim.Type).
		Str("claim_value", e.Claim.Value).
		Str("added_by", e.AddedBy)
	if e.Filter != "" {
		ev.Str("filter", e.Filter)
	}
	if e.Prompt != "" {
		ev.Str("prompt", e.Prompt)
	}
	ev.Msgf("CLAIM  [%s] %s=%s (%s)", who(e.Label, e.Session), e.Claim.Type, e.Claim.Value, e.AddedBy)
}

func who(label, session string) string {
	if label == "" {
		return session
	}
	return label
}
