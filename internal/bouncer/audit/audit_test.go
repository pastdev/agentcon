package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"

	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrite(t *testing.T) {
	type testCase struct {
		entry     Entry
		level     zerolog.Level
		wantLevel string
		want      map[string]any
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		var buf bytes.Buffer
		New(zerolog.New(&buf).Level(tc.level)).Write(tc.entry)
		if tc.want == nil {
			assert.Empty(t, buf.String())
			return
		}
		var got map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
		assert.Equal(t, tc.wantLevel, got["level"])
		delete(got, "level")
		assert.Equal(t, tc.want, got)
	}

	t.Run("logs an allow at info with its fields", func(t *testing.T) {
		tester(t, testCase{
			entry: Entry{
				Session: "s1", Label: "agent", Profile: "p", Transport: "http", Service: "gitlab",
				Request: "GET https://gitlab.example/api", Decision: DecisionAllow, By: "filter", Status: 200, DurationMS: 12,
			},
			wantLevel: "info",
			want: map[string]any{
				"event": "decision", "session": "s1", "label": "agent", "profile": "p", "transport": "http", "service": "gitlab",
				"request": "GET https://gitlab.example/api", "decision": "allow", "by": "filter", "status": float64(200),
				"duration_ms": float64(12),
				"message":     "ALLOW  [agent] GET https://gitlab.example/api -> 200  (filter)",
			},
		})
	})
	t.Run("logs a deny at warn and omits empty fields", func(t *testing.T) {
		tester(t, testCase{
			entry:     Entry{Session: "s1", Transport: "ssh", Request: "ssh git@host connect", Decision: DecisionDeny, By: "policy", Reason: "blocked"},
			wantLevel: "warn",
			want: map[string]any{
				"event": "decision", "session": "s1", "transport": "ssh", "request": "ssh git@host connect", "decision": "deny",
				"by": "policy", "reason": "blocked", "duration_ms": float64(0),
				"message": "DENY   [s1] ssh git@host connect  (policy: blocked)",
			},
		})
	})
	t.Run("logs an error at error", func(t *testing.T) {
		tester(t, testCase{
			entry:     Entry{Transport: "http", Request: "CONNECT host:443", Decision: DecisionError, Reason: "dial", Status: 502},
			wantLevel: "error",
			want: map[string]any{
				"event": "decision", "transport": "http", "request": "CONNECT host:443", "decision": "error", "reason": "dial",
				"status": float64(502), "duration_ms": float64(0),
				"message": "ERROR  [] CONNECT host:443  (: dial)",
			},
		})
	})
	t.Run("logs a tunnel at debug", func(t *testing.T) {
		tester(t, testCase{
			entry:     Entry{Transport: "http", Request: "CONNECT host:443", Decision: DecisionTunnel},
			wantLevel: "debug",
			want: map[string]any{
				"event": "decision", "transport": "http", "request": "CONNECT host:443", "decision": "tunnel", "duration_ms": float64(0),
				"message": "TUNNEL [] CONNECT host:443",
			},
		})
	})
	t.Run("hides a tunnel at info", func(t *testing.T) {
		tester(t, testCase{
			entry: Entry{Transport: "http", Request: "CONNECT host:443", Decision: DecisionTunnel},
			level: zerolog.InfoLevel,
		})
	})
}

// TestEntryRoundTrip keeps Entry's JSON names in step with the logged
// fields, which tests elsewhere decode back into entries.
func TestEntryRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Entry{Event: EventDecision, Session: "s1", Transport: "http", Request: "GET /", Decision: DecisionAllow, Status: 204, DurationMS: 3}
	New(zerolog.New(&buf)).Write(in)
	var out Entry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	assert.Equal(t, in, out)
}

func TestSessionEvents(t *testing.T) {
	type testCase struct {
		log  func(*Log)
		want map[string]any
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		var buf bytes.Buffer
		tc.log(New(zerolog.New(&buf)))
		var got map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
		assert.Equal(t, tc.want, got)
	}

	t.Run("session created with claims", func(t *testing.T) {
		tester(t, testCase{
			log: func(l *Log) {
				l.SessionCreated("deadbeef", "agentcon", "agent", claims.Set{"repository": {"gitlab.example.com/group/project"}})
			},
			want: map[string]any{
				"level": "info", "event": "session_created", "session": "deadbeef", "label": "agentcon", "profile": "agent",
				"claims":  map[string]any{"repository": []any{"gitlab.example.com/group/project"}},
				"message": "SESSION [agentcon] created profile=agent claims=1",
			},
		})
	})
	t.Run("session created without claims logs {}", func(t *testing.T) {
		tester(t, testCase{
			log: func(l *Log) { l.SessionCreated("deadbeef", "agentcon", "agent", nil) },
			want: map[string]any{
				"level": "info", "event": "session_created", "session": "deadbeef", "label": "agentcon", "profile": "agent",
				"claims": map[string]any{}, "message": "SESSION [agentcon] created profile=agent claims=0",
			},
		})
	})
	t.Run("seeded claim", func(t *testing.T) {
		tester(t, testCase{
			log: func(l *Log) {
				l.ClaimAdded(ClaimEvent{Session: "deadbeef", Label: "agentcon", AddedBy: claims.AddedSeeded,
					Claim: claims.Claim{Type: "repository", Value: "gitlab.example.com/group/project"}})
			},
			want: map[string]any{
				"level": "info", "event": "claim_added", "session": "deadbeef", "label": "agentcon",
				"claim_type": "repository", "claim_value": "gitlab.example.com/group/project", "added_by": "seeded",
				"message": "CLAIM  [agentcon] repository=gitlab.example.com/group/project (seeded)",
			},
		})
	})
	t.Run("operator claim names its filter and prompt", func(t *testing.T) {
		tester(t, testCase{
			log: func(l *Log) {
				l.ClaimAdded(ClaimEvent{Session: "deadbeef", Label: "agentcon", AddedBy: claims.AddedOperator,
					Claim: claims.Claim{Type: "repository", Value: "gitlab.example.com/group/other"}, Filter: "gitlab-issue-scope", Prompt: "a1b2c3"})
			},
			want: map[string]any{
				"level": "info", "event": "claim_added", "session": "deadbeef", "label": "agentcon",
				"claim_type": "repository", "claim_value": "gitlab.example.com/group/other", "added_by": "operator",
				"filter": "gitlab-issue-scope", "prompt": "a1b2c3",
				"message": "CLAIM  [agentcon] repository=gitlab.example.com/group/other (operator)",
			},
		})
	})
}
