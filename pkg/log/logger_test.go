package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildLevels(t *testing.T) {
	type testCase struct {
		levels      []string
		wantCLI     zerolog.Level
		wantBouncer zerolog.Level
		wantAudit   zerolog.Level
		wantErr     string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		l, err := build(&bytes.Buffer{}, false, tc.levels, "json")
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.wantCLI, l.cli.GetLevel(), "cli")
		assert.Equal(t, tc.wantBouncer, l.bouncer.GetLevel(), "bouncer")
		assert.Equal(t, tc.wantAudit, l.audit.GetLevel(), "audit")
	}

	t.Run("defaults to info", func(t *testing.T) {
		tester(t, testCase{wantCLI: zerolog.InfoLevel, wantBouncer: zerolog.InfoLevel, wantAudit: zerolog.InfoLevel})
	})
	t.Run("a bare level sets cli and bouncer inherits it", func(t *testing.T) {
		tester(t, testCase{levels: []string{"debug"}, wantCLI: zerolog.DebugLevel, wantBouncer: zerolog.DebugLevel, wantAudit: zerolog.InfoLevel})
	})
	t.Run("cli= matches a bare level", func(t *testing.T) {
		tester(t, testCase{levels: []string{"cli=warn"}, wantCLI: zerolog.WarnLevel, wantBouncer: zerolog.WarnLevel, wantAudit: zerolog.InfoLevel})
	})
	t.Run("bouncer overrides the inherited level", func(t *testing.T) {
		tester(t, testCase{levels: []string{"error", "bouncer=trace"}, wantCLI: zerolog.ErrorLevel, wantBouncer: zerolog.TraceLevel, wantAudit: zerolog.InfoLevel})
	})
	t.Run("audit is set on its own", func(t *testing.T) {
		tester(t, testCase{levels: []string{"audit=disabled"}, wantCLI: zerolog.InfoLevel, wantBouncer: zerolog.InfoLevel, wantAudit: zerolog.Disabled})
	})
	t.Run("ignores case", func(t *testing.T) {
		tester(t, testCase{levels: []string{"WARN"}, wantCLI: zerolog.WarnLevel, wantBouncer: zerolog.WarnLevel, wantAudit: zerolog.InfoLevel})
	})
	t.Run("the last value for a name wins", func(t *testing.T) {
		tester(t, testCase{levels: []string{"debug", "info"}, wantCLI: zerolog.InfoLevel, wantBouncer: zerolog.InfoLevel, wantAudit: zerolog.InfoLevel})
	})
	t.Run("rejects an unknown name", func(t *testing.T) {
		tester(t, testCase{levels: []string{"proxy=debug"}, wantErr: `name "proxy": want cli, bouncer, or audit`})
	})
	t.Run("rejects an unknown level", func(t *testing.T) {
		tester(t, testCase{levels: []string{"audit=loud"}, wantErr: `audit level "loud": unknown`})
	})
	t.Run("rejects an empty level", func(t *testing.T) {
		tester(t, testCase{levels: []string{"bouncer="}, wantErr: `bouncer level "": unknown`})
	})
}

func TestBuildFormat(t *testing.T) {
	type testCase struct {
		format  string
		color   bool
		want    []string
		notWant []string
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		var buf bytes.Buffer
		l, err := build(&buf, tc.color, nil, tc.format)
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		l.cli.Info().Msg("from cli")
		l.bouncer.Info().Msg("from bouncer")
		l.audit.Info().Msg("from audit")
		for _, s := range tc.want {
			assert.Contains(t, buf.String(), s)
		}
		for _, s := range tc.notWant {
			assert.NotContains(t, buf.String(), s)
		}
	}

	t.Run("pretty without color can be grepped", func(t *testing.T) {
		tester(t, testCase{
			format:  "pretty",
			want:    []string{"from cli log=cli", "from bouncer log=bouncer", "from audit log=audit"},
			notWant: []string{"\x1b["},
		})
	})
	t.Run("pretty on a terminal is colored", func(t *testing.T) {
		tester(t, testCase{format: "PRETTY", color: true, want: []string{"\x1b["}})
	})
	t.Run("rejects an unknown format", func(t *testing.T) {
		tester(t, testCase{format: "xml", wantErr: `format "xml": want pretty or json`})
	})
}

func TestBuildJSONLogField(t *testing.T) {
	var buf bytes.Buffer
	l, err := build(&buf, false, nil, "json")
	require.NoError(t, err)
	l.cli.Info().Msg("from cli")
	l.bouncer.Info().Msg("from bouncer")
	l.audit.Info().Msg("from audit")

	type line struct {
		Log     string `json:"log"`
		Message string `json:"message"`
	}
	var got []line
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var entry line
		require.NoError(t, json.Unmarshal([]byte(raw), &entry))
		got = append(got, entry)
	}
	assert.Equal(t, []line{
		{Log: "cli", Message: "from cli"},
		{Log: "bouncer", Message: "from bouncer"},
		{Log: "audit", Message: "from audit"},
	}, got)
}
