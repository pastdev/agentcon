# Plan: Initial Go CLI skeleton (issue 1)

Issue: https://github.com/pastdev/agentcon/issues/1

## Goal

Add a minimal Go Cobra CLI for `agentcon`.
Ship `agentcon config` and `agentcon version` only.
Keep existing shell and image assets beside the new Go tree.

## Non-goals

Do not port `agent_exec.sh` or Docker image logic into Go yet.
Do not add a rich harness configuration schema yet.
Do not remove or rewrite `image/` in this change.

## Decisions

- Module path: `github.com/pastdev/agentcon`
- Go version: `1.27`
- Default branch: `master`
- Commands: `config`, `version`
- Config loader: `github.com/pastdev/configloader`
- `pkg/config.Config` is an empty struct in this change
- Default config dirs:
  - `/etc/agentcon.d`
  - `~/.config/agentcon.d`
  - `./agentcon.d`
- Include `pkg/log` using the askai-style wrapper
- Include `.golangci.yml` based on askai
- Include GitHub Actions workflow for lint and test
- Keep `agent_exec.sh` and `image/` as-is
- Commit `ad_hoc/` to the repo as ephemeral project knowledge
- Do not gitignore `ad_hoc/`

## Layout

```text
agentcon/
  AGENTS.md
  .gitignore
  .golangci.yml
  .github/workflows/build.yml
  go.mod
  go.sum
  cmd/agentcon/main.go
  cmd/agentcon/root/root.go
  cmd/agentcon/config/config.go
  cmd/agentcon/version/version.go
  pkg/config/config.go
  pkg/log/logger.go
  pkg/version/version.go
  agent_exec.sh
  image/
  ad_hoc/issue-1/go-cli-skeleton.plan.md
```

## Layering

`cmd/**` is command wiring only.
Commands may parse flags and args, format user output, and call `pkg/**`.
Domain and config-loading logic live under `pkg/**`.

Compared to askai, keep unmarshal helpers and `ConfigLoader` setup in `pkg/config`.
`cmd/agentcon/config` should stay thin.

## Package responsibilities

### `cmd/agentcon/main.go`

Call `root.New().Execute()`.
Exit non-zero on error.

### `cmd/agentcon/root`

Build the root `cobra.Command` named `agentcon`.
Wire persistent `--log` and `--log-format`.
Call into `pkg` to attach config flags and the `config` subcommand.
Add `version` subcommand.

### `cmd/agentcon/config`

Expose a small helper used by root to register config CLI pieces.
Do not implement merge or unmarshal logic here.

### `cmd/agentcon/version`

Print `Version: <value>` using `pkg/version`.

### `pkg/config`

Define an empty `Config` struct.
Own default sources and configloader integration.
Own persistent flag registration for `--config` and `--config-dir`.
Own adding the `config` subcommand via configloader cobra helpers.

### `pkg/version`

Export `Version()` with a default like `0.0.0`.
Allow ldflags override in CI later.

### `pkg/log`

Provide askai-like level and format setters.
Assign logger into configloader's log package from root persistent pre-run.

## Code conventions

- Run `go fmt` on all Go files
- Pass `golangci-lint` with the project `.golangci.yml`
- Section order in each file:
  1. imports
  2. const
  3. var
  4. interface
  5. struct
  6. methods (sort by receiver type, then name)
  7. functions (alphabetical)
- Prefer `RunE` and wrapped errors where lint requires it
- Use `//nolint: revive` for cobra callback signatures when needed

## Tooling files

### `.golangci.yml`

Copy askai's enabled linter set as the baseline.
Adjust only if agentcon hits a justified false positive.

### `.github/workflows/build.yml`

Jobs: `lint`, `test`.
Use `go-version-file: go.mod`.
Target branch workflows against `master`.
Defer multi-platform release artifacts until we tag releases.

### `.gitignore`

Ignore `.agentcon/` for handoff artifacts.
Add normal Go ignores.
Do not ignore `ad_hoc/`.

### `go.mod`

Set `go 1.27`.
Require at least:

- `github.com/spf13/cobra`
- `github.com/pastdev/configloader`
- `github.com/rs/zerolog` (via `pkg/log`)

## Local git bootstrap

The workspace copy is not yet a git clone.
Bootstrap in place with handoff when implementation starts:

1. `git init`
2. Add `origin` as `git@github.com:pastdev/agentcon.git`
3. Fetch and set upstream tracking to `origin/master` when present

Preserve current worktree files.
Do not replace the tree with a fresh clone.

## Acceptance checks

- `go build ./...`
- `go test ./...`
- `golangci-lint run`
- `agentcon version` prints a version line
- `agentcon config` prints YAML for an empty or default config
- Existing `agent_exec.sh` and `image/` remain present and unchanged

## Implementation sequence

1. Bootstrap local git remote tracking via handoff
2. Add Go module and packages in the order above
3. Add lint config and CI workflow
4. Run acceptance checks
5. Create MR handoff script for the user
