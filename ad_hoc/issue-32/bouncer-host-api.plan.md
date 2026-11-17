# Public bouncer host APIs

Issue: https://github.com/pastdev/agentcon/issues/32
Requirements: [bouncer-host-integration.plan.md](bouncer-host-integration.plan.md)

## Goal

A Go module outside agentcon can run the published bouncer executable under its own lifecycle.
It prepares credentials, manages the daemon, answers prompts, sets up the agent, compiles policy, and runs policy tests.
It uses the same implementations agentcon uses, and it never imports an `internal` path.
The release publishes matching Linux amd64 and arm64 executables with checksums.

## Decisions

- One PR for all of #32.
  The pieces only make sense together, because policy tests matter only when the caller can run the bouncer.
- Public types move to `pkg/bouncer/...` packages.
  They are not aliases of internal types.
  The daemon imports the moved types from their new packages.
- Credential preparation is one entry point that keeps agentcon's resolution order.
- The management client is public through `New` only, and every call takes a `context.Context`.
- Prompt command hints are a caller-supplied function.
- One `AgentLayout` drives both the agent payload and the agent environment.
- Credential command failures use a typed error whose `Error()` never holds stderr.
- The GitLab project lookup no longer sends credential errors to the agent.
- Release assets name their OS and architecture, keep the old names as aliases, and ship `SHA256SUMS`.

## Packages

| Today | Becomes |
|---|---|
| `internal/bouncer/prompt` | `pkg/bouncer/prompt` |
| `internal/bouncer/mgmt` client and `Status`, `Trust` | `pkg/bouncer/mgmt` |
| `daemon.SessionRecord`, `daemon.NewSession`, `chain.Session` | wire types in `pkg/bouncer/mgmt` |
| `mgmt.Dial`, `mgmt.DialContext`, `LoadToken`, `ReloadToken` | stay internal, wrapping `mgmt.New` |
| `internal/bouncer/envexport` | `pkg/bouncer/envexport`, unchanged |
| `app.Check`, `app.AnswerAtTerminal`, `run.waitReady`, `run.notifyPrompts` | `pkg/bouncer/host` |
| `hostEnvCreds`, `hostProvidedCreds`, `hostSSHAuthSock`, `checkPromptable`, `sshkey.go` | `pkg/bouncer/host` |
| `run.writeAgentPayload` | `pkg/bouncer/host` |
| `testrunner.Result` | `pkg/bouncertest.Result` |
| `cmd/agentcon/bouncer/tap.go` | `pkg/bouncertest.WriteTAP` |

`pkg/bouncer/host` does not import `pkg/config`.
The typed credential error lives in a leaf public package that `internal/bouncer/creds` can import without a cycle.

## Credentials

```go
type CredentialOptions struct {
    Policy   []byte            // materialized policy YAML
    Env      []string          // NAME=value overrides
    Provided map[string]string // values the caller already has
    Stdin    io.Reader         // SSH key passphrases
    Stderr   io.Writer
}

type Credentials struct {
    Env         map[string]string // send with client.PutEnv
    Provided    map[string]string // send with client.PutProvided, SSH keys decrypted
    SSHAuthSock string            // host socket to bind at SidecarSSHAuthSock, "" when unused
}

func CheckPromptable(policy []byte) error
func PrepareCredentials(ctx context.Context, o CredentialOptions) (Credentials, error)
```

`PrepareCredentials` calls `CheckPromptable` first, then resolves env sources, provided sources, SSH key unlocks, and the ssh-agent socket in today's order.
Callers may call `CheckPromptable` earlier to fail before preparing an image.

Guarantees, each covered by a test:

- It never changes the caller's `Env` slice or `Provided` map.
- On any error it returns a zero `Credentials`.
- No error text contains a secret value.
  A malformed `Env` entry is reported by position, not by content.

### Command errors

A failed `source: command` returns a typed error with the executable name, exit status, and stderr capped at 4 KiB.
`Error()` holds only the name and status, for example `op: exit status 1`, with no arguments, stdout, or stderr.
The doc comment says stderr may contain secrets.
agentcon prints stderr to the operator's terminal on the host and to the daemon log.
Nothing that reaches the agent includes it.

### GitLab lookup leak

Today a failed credential fetch during GitLab project resolution becomes a deny reason that the agent receives.
After this change the agent receives `agent-bouncer: credential for <service> is unavailable; see the bouncer log`, the same as `forward.go`.
The daemon log keeps the detail.

## Management client

```go
func New(baseURL, token string) *Client
func (c *Client) SetToken(token string)
func (c *Client) Status(ctx context.Context) (Status, error)
func (c *Client) Trust(ctx context.Context) (Trust, error)
func (c *Client) Sessions(ctx context.Context) ([]SessionRecord, error)
func (c *Client) CreateSession(ctx context.Context, id, profile, label, ttl string) (NewSession, error)
func (c *Client) EndSession(ctx context.Context, id string) error
func (c *Client) PutEnv(ctx context.Context, vars map[string]string) error
func (c *Client) PutProvided(ctx context.Context, values map[string]string) error
func (c *Client) Reload(ctx context.Context) error
func (c *Client) Prompts(ctx context.Context) ([]prompt.Pending, error)
func (c *Client) AnswerPrompt(ctx context.Context, id string, a prompt.Answer) error
func (c *Client) DeclinePrompt(ctx context.Context, id string) error
```

The existing HTTP timeouts remain an upper bound.

## Prompts

```go
type PromptHint func(p prompt.Pending) string
func AgentconHint(p prompt.Pending) string

type PromptOptions struct {
    Stdin   io.Reader
    Stderr  io.Writer
    Hint    PromptHint    // nil prints the prompt without a command
    Timeout time.Duration // WaitReady idle timeout, 0 means 2m
}

type PromptAnswerer interface {
    AnswerPrompt(ctx context.Context, id string, a prompt.Answer) error
    DeclinePrompt(ctx context.Context, id string) error
}

func WaitReady(ctx context.Context, c *mgmt.Client, o PromptOptions) error
func NotifyPrompts(ctx context.Context, c *mgmt.Client, o PromptOptions)
func AnswerAtTerminal(ctx context.Context, c PromptAnswerer, in *os.File, out io.Writer, p prompt.Pending) error
```

- `WaitReady` may answer prompts at a terminal.
  `NotifyPrompts` only reports them, and callers run it under a context cancelled when the session ends.
- `WaitReady` checks `status.Error` before `status.Ready`.
- `AnswerAtTerminal` keeps its secret input, confirm scopes, and decline behavior.

## Policy compilation

`host.Check(cfg *bouncercfg.Config) (CheckResult, error)` replaces `app.Check` with the same diagnostics.

## Agent payload and environment

```go
type AgentLayout struct {
    Binary, CACert, CABundle, SSHConfig, KnownHosts, SSHClient string
}

func DefaultAgentLayout() AgentLayout
func (l AgentLayout) Normalize() (AgentLayout, error)

type AgentPayload struct {
    Layout   AgentLayout
    Binary   string     // host path of the matching linux executable
    Trust    mgmt.Trust
    UID, GID int
}

func WriteAgentPayload(w io.Writer, p AgentPayload) error
func AgentEnv(l AgentLayout, s mgmt.NewSession, proxyAddr, sshAddr string) ([]string, error)
```

The defaults are today's `/opt/agentcon/...` paths and `/usr/bin/ssh`.
`Normalize` fills empty fields from the defaults, and both helpers call it.
It checks paths as Linux paths with the `path` package on every host OS:

- Each path is absolute and equal to its `path.Clean` form.
- The five payload files are distinct, and none lies inside another.
- Each path uses only `A-Z a-z 0-9 . _ - + / @`, so ssh_config, `ProxyCommand`, and `GIT_SSH_COMMAND` need no escaping.
  The generated output still quotes them.

## Policy tests

- `pkg/bouncertest.Result` replaces `testrunner.Result` in `SpecReport.Results`.
- `pkg/bouncertest.WriteTAP(io.Writer, Report) error` is today's TAP 14 writer.
  `agentcon bouncer test` calls it.
- `Report.Failed()` stays the pass/fail signal, so no caller parses TAP.

## Release

| Asset | Notes |
|---|---|
| `agentcon-linux-amd64`, `agentcon-linux-arm64` | sidecar and agent binaries |
| `agentcon-darwin-amd64`, `agentcon-darwin-arm64` | |
| `agentcon-windows-amd64.exe` | |
| `agentcon-linux`, `agentcon-darwin`, `agentcon-windows.exe` | legacy aliases of the amd64 builds |
| `SHA256SUMS` | `sha256sum -c` format over every asset |

The checksums are not signed.
On any Linux host, agentcon ships its own executable into the sidecar.
On other hosts, its error names the `agentcon-linux-<arch>` asset to pass.

## Non-goals

- Implementing another application's lifecycle or CLI.
- Changing the policy language, test specs, credential model, or filter behavior.
- Embedding the daemon in another executable.
- Detecting the container engine's architecture.
- Signing release checksums.

## Commits

1. Plan.
2. Move `prompt` and the management client to `pkg/bouncer`, with `ctx` on every call.
3. Public test results and `WriteTAP`.
4. Typed credential command errors, the env entry fix, and the GitLab lookup fix.
5. `pkg/bouncer/host` credentials.
6. `pkg/bouncer/host` prompts, readiness, and `Check`.
7. `pkg/bouncer/host` agent layout, payload, and environment, and public `envexport`.
8. Release artifacts and the Linux binary choice.
9. Documentation.

## Verification

- `go build ./...`, `go test -race ./...`, `golangci-lint run ./...`, and `go vet` for darwin and windows.
- An `ad_hoc/issue-32` module behind `//go:build issue32` imports only public packages and compiles a lifecycle sketch.
- A smoke `agentcon run` with a bouncer context still starts, answers prompts, and reaches a service.
- `agentcon bouncer test` output is unchanged on both docs examples.
