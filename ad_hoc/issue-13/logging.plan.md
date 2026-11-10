# Plan: Unified logging for agentcon and the bouncer (issue 13)

Issue: https://github.com/pastdev/agentcon/issues/13

## Goal

Every agentcon process logs through zerolog, configured by `--log` and `--log-format`.
The bouncer logs the same way whether it runs as `agentcon bouncer serve` on the host or in the sidecar started by `agentcon run`.
Decisions are a debugging aid, not a durable audit trail.

## Non-goals

Do not persist logs or audit records.
A user who wants a record redirects stderr, or runs `docker logs` on the sidecar while the session is live.
Do not add `--log-file`.
Do not redact query strings in logged requests.
Do not add per-component logger names.
Do not surface bouncer messages on the terminal during `agentcon run`.

## Problems this removes

- The daemon logs through a stdlib `log.Logger` passed down as a `Logf` callback, so messages have no levels and ignore `--log` and `--log-format`.
- Severity lives in message text, such as `"warning: ..."`.
- The Bitwarden fallback writes to `os.Stderr` with `fmt.Fprintf`.
- `agentcon run` starts the sidecar with `--quiet` and no log flags, so the sidecar never logs decisions and ignores the user's level.
- Audit records go to `<state-dir>/audit.jsonl` inside the sidecar and vanish with it, and write failures are dropped.
- Filter `console.debug/info/warn/error` all log the same way.
- Pretty output is colored even when stderr is not a terminal, so `grep` on redirected output misses fields.

## Decisions

### Loggers

- There are three loggers, all writing to stderr in one format.
  - `cli` covers the agentcon process itself: config loading, image builds and pulls, container setup.
  - `bouncer` covers the daemon: listeners, proxy, SSH, credentials, filters, reloads, and state persistence.
  - `audit` carries one record per decision.
- Every line carries a `log` field naming its logger: `cli`, `bouncer`, or `audit`.
- `bouncer` inherits the `cli` level unless set.
  `audit` defaults to `info` regardless of the `cli` level.

### Flags

- `--log` is repeatable and takes `[name=]level`.
  A value without a name sets `cli`.
  Names are `cli`, `bouncer`, and `audit`, and any other name is an error.
- `--log-format` stays a single value for all three loggers.
- `pretty` output disables color when stderr is not a terminal.
- `bouncer serve --quiet` is removed.
  `--log audit=disabled` replaces it.
- `bouncer serve --show-tunnels` is removed.
  `--log audit=debug` replaces it.

### pkg/log

- `pkg/log` owns `Logger` (`cli`), `Bouncer`, and `Audit`.
- `Configure(levels []string, format string) error` replaces `SetFormat` and `SetLevel`.
  It parses the levels, rejects unknown names and levels, applies the defaults, and builds all three loggers on one writer.
- `pkg/log` exposes the configured `bouncer` and `audit` levels and the format so `run` can forward them.
- Root `PersistentPreRunE` calls `Configure` and returns its error.
- `Configure` lowers zerolog's process-wide level floor, which defaults to debug, so `--log trace` works.

### Injection

- `cmd/agentcon/bouncer/serve.go` passes `log.Bouncer` and `log.Audit` into `app.ServeOptions`.
- `daemon`, `proxy`, `sshproxy`, `bitwarden`, `jsfilter`, and `audit` take a `zerolog.Logger` in their options in place of `Logf`.
  A zero `zerolog.Logger` discards everything, so the nil checks and no-op defaults go away.
- Components add their own fields with `.With()`, such as `component=proxy` or `filter=<name>`.
- No package under `internal/bouncer` reads a `pkg/log` global.
- Tests pass `zerolog.New(&buf)` and assert on what was logged.

### Audit records

- Each decision is one event on the `audit` logger.
  The message is the current one-line summary from `FormatDecision`.
  The fields are the existing `audit.Entry` fields: `session`, `label`, `profile`, `transport`, `service`, `request`, `decision`, `by`, `reason`, `status`, and `duration_ms`.
  The event timestamp replaces `ts`.
  `audit.Entry` stays as the value components hand to the audit log.
- Levels by decision:

  | Decision | Level |
  |---|---|
  | tunnel | debug |
  | allow | info |
  | deny | warn |
  | error | error |

- `audit.jsonl` and the `json.Marshal` path in `audit` are removed.
  The `Decision` mirror callback in `daemon.Options` goes away with them.

### Bouncer message levels

| Level | Messages |
|---|---|
| info | listening addresses, config path, CA certificate path, session slug, config reloaded, the prompt answering hint, Bitwarden unlocking and unlocked |
| warn | reload failed, listen address change needs restart, incorrect master password, Bitwarden login retry, client TLS handshake failed, SSH handshake failed, SSH host cert error, credential lookup failed, preparing credentials failed, config watching disabled |
| error | failures writing the CA bundle, sessions, kv store, Bitwarden device state, or runtime file |

Errors carry the error as a field with `.Err(err)` rather than formatted into the message.

### Filter logging

| Filter call | Level |
|---|---|
| `console.debug` | debug |
| `console.log`, `console.info` | info |
| `console.warn` | warn |
| `console.error` | error |
| `log(message, fields?)` | info, with `fields` as structured fields |
| runtime `ask()` denied or failed | warn |

### run

- `run` no longer passes `--quiet` to the sidecar.
- `run` passes `--log bouncer=<level>`, `--log audit=<level>`, and `--log-format <format>` to `bouncer serve` in the sidecar.

### Docs

- README documents `--log [name=]level`, the three loggers, and redirecting stderr for a record.
- `docs/bouncer.md` replaces the `audit.jsonl` example with `docker logs <sidecar> | grep 'log=audit'`, and drops the `--quiet` mentions.
- `docs/bouncer-filters.md` documents the `console` levels and `log()` fields.

## Commits

1. `pkg/log`: three loggers, `Configure`, repeatable `--log`, and color only on a terminal.
2. Inject loggers into the bouncer and replace `Logf`, with the message levels.
3. Audit records on the `audit` logger, and remove `audit.jsonl`, `--quiet`, and `--show-tunnels`.
4. Filter `console` levels and `log()` fields.
5. `run` forwards log settings to the sidecar.
6. Docs.

## Verification

- `go build ./...`, `go test -race ./...`, and `golangci-lint run ./...` pass.
  `go vet` passes for darwin and windows.
- Unit tests cover level parsing and defaults, unknown names, color selection, each audit decision level and its fields, filter console levels, and the sidecar args.
- A smoke run with `agentcon --log bouncer=debug --log audit=debug run` shows bouncer and audit lines, including tunnels, in `docker logs` on the sidecar, and `grep 'log=audit'` isolates the decisions.
