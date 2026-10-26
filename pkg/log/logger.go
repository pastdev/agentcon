package log

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

var Logger = zerolog.New(os.Stderr).With().Timestamp().Logger().Level(zerolog.InfoLevel)

func Ctx(ctx context.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx)
}

func Debug() *zerolog.Event {
	return Logger.Debug()
}

func Err(err error) *zerolog.Event {
	return Logger.Err(err)
}

func Error() *zerolog.Event {
	return Logger.Error()
}

func Fatal() *zerolog.Event {
	return Logger.Fatal()
}

func Hook(h zerolog.Hook) zerolog.Logger {
	return Logger.Hook(h)
}

func Info() *zerolog.Event {
	return Logger.Info()
}

func Level(level zerolog.Level) zerolog.Logger {
	return Logger.Level(level)
}

func Log() *zerolog.Event {
	return Logger.Log()
}

func Output(w io.Writer) zerolog.Logger {
	return Logger.Output(w)
}

func Panic() *zerolog.Event {
	return Logger.Panic()
}

func Print(v ...interface{}) {
	Logger.Debug().CallerSkipFrame(1).Msg(fmt.Sprint(v...))
}

func Printf(format string, v ...interface{}) {
	Logger.Debug().CallerSkipFrame(1).Msgf(format, v...)
}

func Sample(s zerolog.Sampler) zerolog.Logger {
	return Logger.Sample(s)
}

func SetFormat(format string) {
	switch strings.ToUpper(format) {
	case "JSON":
		Logger = Logger.Output(os.Stderr)
	case "PRETTY":
		Logger = Logger.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}

func SetLevel(level string) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		Logger = Level(zerolog.DebugLevel)
	case "DISABLED":
		Logger = Level(zerolog.Disabled)
	case "ERROR":
		Logger = Level(zerolog.ErrorLevel)
	case "FATAL":
		Logger = Level(zerolog.FatalLevel)
	case "INFO":
		Logger = Level(zerolog.InfoLevel)
	case "NONE":
		Logger = Level(zerolog.NoLevel)
	case "PANIC":
		Logger = Level(zerolog.PanicLevel)
	case "TRACE":
		Logger = Level(zerolog.TraceLevel)
	case "WARN":
		Logger = Level(zerolog.WarnLevel)
	}
}

func Trace() *zerolog.Event {
	return Logger.Trace()
}

func Warn() *zerolog.Event {
	return Logger.Warn()
}

func With() zerolog.Context {
	return Logger.With()
}

func WithLevel(level zerolog.Level) *zerolog.Event {
	return Logger.WithLevel(level)
}
