package log

import (
	"bytes"
	"strings"

	"github.com/rs/zerolog"
)

// LineWriter writes newline-delimited text as log messages at a fixed level.
type LineWriter struct {
	level zerolog.Level
	buf   []byte
}

func Writer(level zerolog.Level) *LineWriter {
	return &LineWriter{level: level}
}

func InfoWriter() *LineWriter {
	return Writer(zerolog.InfoLevel)
}

func DebugWriter() *LineWriter {
	return Writer(zerolog.DebugLevel)
}

func (w *LineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	w.drain(false)
	return len(p), nil
}

func (w *LineWriter) Flush() {
	w.drain(true)
}

func (w *LineWriter) drain(flush bool) {
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.logLine(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	if flush && len(w.buf) > 0 {
		w.logLine(w.buf)
		w.buf = w.buf[:0]
	}
}

func (w *LineWriter) logLine(raw []byte) {
	line := strings.TrimRight(string(raw), "\r")
	if line == "" {
		return
	}
	Logger.WithLevel(w.level).Msg(line)
}
