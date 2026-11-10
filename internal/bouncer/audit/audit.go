// Package audit logs one event per policy decision.
package audit

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
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
	who := e.Label
	if who == "" {
		who = e.Session
	}
	s := fmt.Sprintf("%-6s [%s] %s", strings.ToUpper(e.Decision), who, e.Request)
	if e.Status != 0 && e.Decision == DecisionAllow {
		s += fmt.Sprintf(" -> %d", e.Status)
	}
	switch {
	case e.Decision == DecisionDeny || e.Decision == DecisionError:
		s += fmt.Sprintf("  (%s: %s)", e.By, e.Reason)
	case e.By != "":
		s += fmt.Sprintf("  (%s)", e.By)
	}
	return s
}
