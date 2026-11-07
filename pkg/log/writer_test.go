package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestLineWriterLogsCompleteLines(t *testing.T) {
	var buf bytes.Buffer
	orig := Logger
	t.Cleanup(func() { Logger = orig })
	Logger = zerolog.New(&buf)

	w := InfoWriter()
	_, err := w.Write([]byte("building img\n#1 load\n#1 DONE"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "DONE") {
		t.Fatalf("partial line logged early: %s", buf.String())
	}
	w.Flush()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines: %s", len(lines), buf.String())
	}
	want := []string{"building img", "#1 load", "#1 DONE"}
	for i, line := range lines {
		var msg struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		}
		err = json.Unmarshal([]byte(line), &msg)
		if err != nil {
			t.Fatalf("line %d: %v %s", i, err, line)
		}
		if msg.Level != "info" || msg.Message != want[i] {
			t.Fatalf("line %d: %+v", i, msg)
		}
	}
}

func TestLineWriterSkipsEmptyLines(t *testing.T) {
	var buf bytes.Buffer
	orig := Logger
	t.Cleanup(func() { Logger = orig })
	Logger = zerolog.New(&buf)

	w := DebugWriter()
	_, err := w.Write([]byte("one\n\n\r\ntwo\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if strings.Count(got, `"message"`) != 2 {
		t.Fatalf("got %s", got)
	}
	if !strings.Contains(got, `"level":"debug"`) {
		t.Fatalf("level %s", got)
	}
}
