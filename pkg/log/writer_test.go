package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
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
		if err != nil {
			t.Fatal(err)
		}
		if tc.flush {
			if strings.Contains(buf.String(), "DONE") {
				t.Fatalf("partial line logged early: %s", buf.String())
			}
			w.Flush()
		}
		if tc.wantMsg > 0 {
			got := buf.String()
			if strings.Count(got, `"message"`) != tc.wantMsg {
				t.Fatalf("got %s", got)
			}
			if !strings.Contains(got, `"level":"`+tc.level+`"`) {
				t.Fatalf("level %s", got)
			}
			return
		}
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != len(tc.want) {
			t.Fatalf("got %d lines: %s", len(lines), buf.String())
		}
		for i, line := range lines {
			var msg struct {
				Level   string `json:"level"`
				Message string `json:"message"`
			}
			err = json.Unmarshal([]byte(line), &msg)
			if err != nil {
				t.Fatalf("line %d: %v %s", i, err, line)
			}
			if msg.Level != tc.level || msg.Message != tc.want[i] {
				t.Fatalf("line %d: %+v", i, msg)
			}
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
