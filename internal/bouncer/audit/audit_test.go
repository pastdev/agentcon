package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
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
				"session": "s1", "label": "agent", "profile": "p", "transport": "http", "service": "gitlab",
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
				"session": "s1", "transport": "ssh", "request": "ssh git@host connect", "decision": "deny",
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
				"transport": "http", "request": "CONNECT host:443", "decision": "error", "reason": "dial",
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
				"transport": "http", "request": "CONNECT host:443", "decision": "tunnel", "duration_ms": float64(0),
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
	in := Entry{Session: "s1", Transport: "http", Request: "GET /", Decision: DecisionAllow, Status: 204, DurationMS: 3}
	New(zerolog.New(&buf)).Write(in)
	var out Entry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	assert.Equal(t, in, out)
}
