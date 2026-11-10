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

func TestLineWriter(t *testing.T) {
	type testCase struct {
		level   string
		writer  func() *LineWriter
		input   []byte
		flush   bool
		want    []string
		wantMsg int
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		var buf bytes.Buffer
		orig := Logger
		t.Cleanup(func() { Logger = orig })
		Logger = zerolog.New(&buf)

		w := tc.writer()
		_, err := w.Write(tc.input)
		require.NoError(t, err)
		if tc.flush {
			require.NotContains(t, buf.String(), "DONE", "partial line logged early")
			w.Flush()
		}
		if tc.wantMsg > 0 {
			got := buf.String()
			assert.Equal(t, tc.wantMsg, strings.Count(got, `"message"`), got)
			assert.Contains(t, got, `"level":"`+tc.level+`"`)
			return
		}
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, len(tc.want))
		for i, line := range lines {
			var msg struct {
				Level   string `json:"level"`
				Message string `json:"message"`
			}
			err = json.Unmarshal([]byte(line), &msg)
			require.NoError(t, err, line)
			assert.Equal(t, tc.level, msg.Level)
			assert.Equal(t, tc.want[i], msg.Message)
		}
	}

	t.Run("logs complete info lines after flush", func(t *testing.T) {
		tester(t, testCase{
			level:  "info",
			writer: InfoWriter,
			input:  []byte("building img\n#1 load\n#1 DONE"),
			flush:  true,
			want:   []string{"building img", "#1 load", "#1 DONE"},
		})
	})
	t.Run("skips empty debug lines", func(t *testing.T) {
		tester(t, testCase{
			level:   "debug",
			writer:  DebugWriter,
			input:   []byte("one\n\n\r\ntwo\n"),
			wantMsg: 2,
		})
	})
}
