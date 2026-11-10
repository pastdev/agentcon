package log

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pastdev/agentcon/pkg/term"
	"github.com/rs/zerolog"
)

const (
	// LogCLI names the agentcon process's own logger.
	LogCLI = "cli"
	// LogBouncer names the bouncer daemon's logger.
	LogBouncer = "bouncer"
	// LogAudit names the logger for bouncer decisions.
	LogAudit = "audit"
)

var (
	stderrBase = zerolog.New(os.Stderr).With().Timestamp().Logger()
	// Logger is the cli logger.
	Logger = stderrBase.With().Str("log", LogCLI).Logger().Level(zerolog.InfoLevel)
	// Bouncer logs the bouncer daemon.
	Bouncer = stderrBase.With().Str("log", LogBouncer).Logger().Level(zerolog.InfoLevel)
	// Audit logs one record per bouncer decision.
	Audit = stderrBase.With().Str("log", LogAudit).Logger().Level(zerolog.InfoLevel)
)

var levels = map[string]zerolog.Level{
	"trace":    zerolog.TraceLevel,
	"debug":    zerolog.DebugLevel,
	"info":     zerolog.InfoLevel,
	"warn":     zerolog.WarnLevel,
	"error":    zerolog.ErrorLevel,
	"fatal":    zerolog.FatalLevel,
	"panic":    zerolog.PanicLevel,
	"disabled": zerolog.Disabled,
}

// Settings are the bouncer and audit levels and the format Configure
// applied, in the form --log and --log-format take. They are empty before
// Configure runs.
type Settings struct {
	Bouncer string
	Audit   string
	Format  string
}

var settings Settings

// Current returns the settings Configure applied, so a process can start
// a bouncer that logs the same way.
func Current() Settings {
	return settings
}

type loggers struct {
	cli      zerolog.Logger
	bouncer  zerolog.Logger
	audit    zerolog.Logger
	settings Settings
}

// Configure builds every logger on stderr in format, pretty or json. Each
// level is [name=]level, where a bare level sets the cli logger. The
// bouncer logger inherits the cli level, and the audit logger defaults to
// info.
func Configure(levelArgs []string, format string) error {
	l, err := build(os.Stderr, term.IsTerminal(int(os.Stderr.Fd())), levelArgs, format)
	if err != nil {
		return err
	}
	// Levels are set per logger. Lower zerolog's process-wide floor, which
	// defaults to debug, so --log trace is not filtered out by it.
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	Logger, Bouncer, Audit, settings = l.cli, l.bouncer, l.audit, l.settings
	return nil
}

func build(w io.Writer, color bool, levelArgs []string, format string) (loggers, error) {
	var out io.Writer
	format = strings.ToLower(format)
	switch format {
	case "json":
		out = w
	case "pretty":
		out = zerolog.ConsoleWriter{Out: w, NoColor: !color}
	default:
		return loggers{}, fmt.Errorf("format %q: want pretty or json", format)
	}
	set := map[string]zerolog.Level{}
	for _, arg := range levelArgs {
		name, value, named := strings.Cut(arg, "=")
		if !named {
			name, value = LogCLI, arg
		}
		if name != LogCLI && name != LogBouncer && name != LogAudit {
			return loggers{}, fmt.Errorf("name %q: want %s, %s, or %s", name, LogCLI, LogBouncer, LogAudit)
		}
		level, ok := levels[strings.ToLower(value)]
		if !ok {
			return loggers{}, fmt.Errorf("%s level %q: unknown", name, value)
		}
		set[name] = level
	}
	cli := levelOr(set, LogCLI, zerolog.InfoLevel)
	bouncer := levelOr(set, LogBouncer, cli)
	audit := levelOr(set, LogAudit, zerolog.InfoLevel)
	base := zerolog.New(out).With().Timestamp().Logger()
	return loggers{
		cli:      base.With().Str("log", LogCLI).Logger().Level(cli),
		bouncer:  base.With().Str("log", LogBouncer).Logger().Level(bouncer),
		audit:    base.With().Str("log", LogAudit).Logger().Level(audit),
		settings: Settings{Bouncer: bouncer.String(), Audit: audit.String(), Format: format},
	}, nil
}

func levelOr(set map[string]zerolog.Level, name string, fallback zerolog.Level) zerolog.Level {
	level, ok := set[name]
	if !ok {
		return fallback
	}
	return level
}

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
