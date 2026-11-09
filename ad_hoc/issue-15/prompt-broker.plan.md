# Plan: Prompt broker for approvals and Bitwarden unlock (issue 15)

Issue: https://github.com/pastdev/agentcon/issues/15

## Goal

Give the sidecar one way to ask the human a question and wait for the answer.
Filter approvals and the Bitwarden unlock both use it.
The host answers questions generically and knows nothing about Bitwarden.

## Non-goals

Do not let filters ask for free text or secrets.
Do not add long polling or streaming to the management API.
Do not change how `password_env` supplies a master password.
Do not unify bouncer logging (issue 13).

## Problems this removes

- The master password stays in memory on the process-wide prompter after the unlock.
- A later lazy unlock or reload reuses that password, possibly for a different account.
- `SetPrompt` swaps a field that `masterPassword` and `verificationCode` read without the lock.
- The host speaks Bitwarden's protocol, including the 409 `need_code` retry.
- A vault that needs unlocking after startup cannot ask for its password.

## Decisions

### Broker

- New package `internal/bouncer/prompt` holds the generic broker.
- A question has a kind: `confirm`, `text`, or `secret`.
- `Raise(Question)` records a question and returns a ticket with its id without waiting.
  `Ticket.Wait(ctx)` blocks until the question is answered, declined, timed out, or ctx ends.
  `Ask(ctx, Question)` does both.
  Approvals need the id before blocking so a remembered answer can settle other pending asks.
- The broker has one timeout, set from config with `SetTimeout`.
  A per-call limit, such as the filter `ask()` option, is a ctx deadline.
- When ctx ends first, the question is withdrawn.
- `Answer(id, Answer)` and `Decline(id)` settle a pending question.
- `List()` returns pending questions oldest first.
- `Subscribe()` returns events for new and settled questions.
- Ids are random hex, as approvals use today.
- An answer is delivered only on the waiting asker's own channel.
  `Pending` and `Event` never carry an answer value.
  The broker drops the value once it is delivered.
- `Answer` checks that the answer fits the kind.
  A confirm takes `allow` and `remember`.
  A text or secret takes a non-empty `value`.
- `SetNotify` sets a function called for each new question with the question only.

### Approvals

- `approval.Manager` keeps its `chain.Approver` API, remember-for-session, dedupe of identical asks, and `ForgetSession`.
- It raises `confirm` questions on the broker instead of keeping its own pending map and wait loop.
- Filter `ask()` and rules `action: ask` stay confirm-only.
  Request-controlled text can never produce a prompt that asks for a value.
- The per-call `timeout` option on filter `ask()` keeps working.

### Bitwarden

- `Prompter` methods take a context and the attempt: `MasterPassword(ctx, label, attempt, attempts)` and `TwoFactorCode(ctx, label, method, attempt, attempts)`.
- `bitwarden.Configure` receives the prompter once and it never changes for the life of the process.
- `bitwarden.BrokerPrompter` is the broker-backed prompter, so it can be tested against the fake vault server.
- The daemon supplies a prompter that raises `secret` questions for the master password and `text` questions for a verification code.
- Prompt messages are fixed strings built in Go from the account label and two-factor method.
- The existing attempt loops (3 passwords, 5 codes) stay, and each attempt raises a new question.
  A retry message names the attempt, for example `Bitwarden master password (incorrect, attempt 2 of 3)`.
- Declining or a timeout ends the unlock with an error.
- Removed: `SetPrompt`, `StaticPrompter`, `NeedCodeError`, `stdPrompter`, `ErrNeedTerminal`, `creds.NeedPasswordError`, `mgmt.NeedCodeError`, and `mgmt.Client.UnlockBitwarden`.

### Startup and reload

- `apply` swaps the new config in without waiting for Bitwarden.
- Preparing credentials (unlocking every Bitwarden account in the config) runs in a background goroutine.
- A request that needs a vault still locking waits on the existing per-account lock, so each account raises at most one question at a time.
- `ready` on status reports whether the startup preparation finished successfully.
  Prompts raised later, including filter approvals, do not affect it.
- When startup preparation fails, status carries the error and `agentcon run` aborts with it.
- A reload that adds accounts prepares them in the background the same way.
  A wrong password on reload no longer keeps the previous config running.
  The new config applies and that account's credentials stay unavailable until it unlocks.

### Management API

```
GET    /_bouncer/status        {..., "ready": false, "pending_prompts": 1, "error": ""}
GET    /_bouncer/prompts       [{"id", "kind", "source", "message", "detail", "session_id", "session_label", "profile", "created", "expires"}]
POST   /_bouncer/prompts/{id}  {"allow": true, "remember": true} or {"value": "..."}
DELETE /_bouncer/prompts/{id}  decline
```

- Status reports a count of pending prompts, and `/prompts` is the only source of their details.
- Answering or declining an unknown or settled id returns 404.
- An answer that does not fit the kind returns 400.
- `prompts.cli: false` makes `POST` and `DELETE` return 403, as `approvals.cli: false` does today.
- Removed: `/_bouncer/approvals`, `/_bouncer/approvals/{id}`, `/_bouncer/credentials/sources/bitwarden/unlock`, `bitwarden_pending`, and `pending_approvals`.
- All prompt endpoints stay behind the admin token.

### Config

- `approvals:` is renamed `prompts:` with the same fields: `timeout`, `notify`, `terminal`, `cli`.
- The fields apply to every kind of question.
- `agentcon run` refuses to start a sidecar with `prompts.cli: false` when any credential uses Bitwarden without `password_env`, because nothing could answer.
- The old key is not kept as an alias.

### Answering

- `agentcon run`: `waitReady` polls status.
  When `pending_prompts` is above zero it lists prompts and answers each new one at the terminal.
  A `secret` is read without echo, a `text` is read as a line, and a `confirm` takes y, s, n, or d.
  An empty secret or Ctrl-C declines the prompt.
  A secret is used exactly as typed, and text is trimmed.
  Without a terminal, each prompt is listed once with the `agentcon bouncer answer` command to use.
  The wait times out after two minutes with nothing pending, and pending prompts restart that clock.
  The running record is written before the wait, so the CLI can reach the sidecar during startup.
- Terminal input uses `pkg/term`, moved from the reader `pkg/run` already had.
  It reads a keystroke at a time in raw mode, so Enter, Backspace, and Ctrl-C behave the same on Linux, macOS, and Windows.
  Its `Editor` assembles a line from keystrokes, and `ReadLine` uses it for a one-off read.
- Interactive `bouncer serve`: `RunTerminalApprover` becomes `RunTerminalPrompter` and handles all three kinds.
  One goroutine reads keystrokes from stdin for the life of the prompter.
  The terminal is in raw mode only while a prompt is showing.
  Keystrokes are echoed by the prompter, never for a secret.
  Enter answers, an empty text or secret declines, and Ctrl-C declines.
  The terminal returns to its normal mode between prompts, when a prompt is settled elsewhere, and before `Serve` returns.
- CLI: `agentcon bouncer prompts` lists pending prompts.
  `agentcon bouncer answer <id>` reads a value without echo for a secret, a line for text, or y/n for a confirm.
  `agentcon bouncer approve <id>` and `agentcon bouncer deny <id>` stay as shortcuts for a confirm, with `--session` for remember.
  `agentcon bouncer approvals` is removed in favor of `prompts`.

## Steps

Each step builds, passes `go test -race ./...`, and passes lint.

1. Add `internal/bouncer/prompt` with the broker and its tests.
2. Move `approval.Manager` onto the broker without changing approval behavior.
3. Add the prompt endpoints, CLI commands, and `mgmt` client methods.
   Remove the approvals endpoints and the `approvals` command.
   Rename the config section to `prompts`.
4. Move the terminal reader to `pkg/term` and generalize the terminal approver into `RunTerminalPrompter`.
5. Give the Bitwarden prompter a context and a broker-backed implementation.
   Run startup and reload preparation in the background and report `ready` and `error` on status.
   Remove the unlock endpoint, `SetPrompt`, and the other Bitwarden-specific types listed above.
   Remove `unlockBitwarden` and `completeBitwardenUnlock` from `pkg/run`, since they call the removed endpoint.
   Until step 6, `agentcon run` waits for `ready` and its prompts are answered with `agentcon bouncer answer`.
6. Make `agentcon run` answer prompts generically in `waitReady`.
7. Update `README.md`, `docs/bouncer.md`, and `docs/bouncer-filters.md` for the new API, CLI, and config key.

## Tests

- Broker: answer, decline, timeout, ctx cancel, unknown id, wrong-kind answer, and that events and listings never contain a value.
- Approvals: the existing approval tests pass unchanged apart from setup.
- Bitwarden: with a fake broker-backed prompter against the existing fake server, unlock with a password, with a retry after a wrong password, and with a two-factor code.
- Bitwarden: two accounts unlocking concurrently each receive only their own answer.
- Bitwarden: declining or timing out ends the unlock with an error.
- Daemon: status reports `ready: false` with a pending prompt during startup, `ready: true` after the answer, and the error when the unlock fails.
- Daemon: a vault first used after startup raises a prompt that the API can answer.
- Control: prompt endpoints return 404, 400, and 403 where described above.
- Run: `waitReady` answers a secret prompt and a text prompt from a scripted terminal.

## Smoke

Start an `agentcon run` sidecar with a Bitwarden credential against a real account.
Unlock it at the run terminal, including a two-factor code if the account has one.
Restart with a wrong password first and confirm the retry prompt.
Confirm a filter `ask()` can be answered with `agentcon bouncer approve` from another terminal.
