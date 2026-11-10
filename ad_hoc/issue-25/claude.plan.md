# Plan: Claude Code example agent (issue 25)

Issue: https://github.com/pastdev/agentcon/issues/25

## Goal

Ship a Claude Code example agent with the same shape as the Cursor one.
A user copies the example image, adds an `agents.claude` entry, and runs `agentcon run`.
The host and the container share `~/.claude`, and both persist.

## Non-goals

Do not add Go code.
The example is an image, an entrypoint, config, and docs.
Do not add an `agents.<name>.environment` field.
Do not intercept `api.anthropic.com` or inject Anthropic credentials from the bouncer.
Do not support a macOS Keychain login in the container.
Do not replace bind mounts with named volumes.

## Decisions

### Image

- `docs/claude/image/` is a copy of `docs/cursor/image/`.
  The Dockerfile and install scripts are the same.
  Comments that name Cursor in the shared scripts become agent-neutral in both copies.
- The Dockerfile creates `/agent/claude` and `/agent/claude-install` with `chmod g=u`, as the Cursor one does for its targets.
- The image does not contain Claude Code.
  The entrypoint installs it into a bind on first start.

### Binds

| Host source | Container target | Holds |
|---|---|---|
| `{{home}}/.claude` | `/agent/claude` | config, credentials, sessions, history, settings, skills, plugins |
| `{{home}}/.local/share/agentcon/claude` | `/agent/claude-install` | the Linux install |

- `CLAUDE_CONFIG_DIR=/agent/claude` puts all of Claude's state, including `.claude.json`, in the shared bind.
- `CLAUDE_CONFIG_DIR` does not move the binary.
  The native installer writes versions to `$HOME/.local/share/claude/versions/<version>` and links `$HOME/.local/bin/claude`.
  The install bind keeps Linux binaries out of the shared `~/.claude`, so a macOS or Windows host is unaffected.

### Entrypoint

`docs/claude/image/contrib/entrypoint.sh` follows the Cursor entrypoint.

1. Append a passwd line for the container UID and create `$HOME`.
2. Source `/etc/profile`.
3. Export `CLAUDE_CONFIG_DIR=/agent/claude`.
4. Link `$HOME/.local/share/claude` to `/agent/claude-install/share`.
5. Link `$HOME/.local/bin/claude` to the newest file in `$HOME/.local/share/claude/versions`.
   Versions are files named by version, so the newest is chosen with `sort --version-sort`.
6. If no version exists, run `curl -fsSL https://claude.ai/install.sh | bash`.
7. `exec claude "$@"`.

`AGENTCON_XTRACE=1` writes the trace to `/agent/claude-install/entrypoint.xtrace`, so it never lands in the shared `~/.claude`.
`AGENTCON_XTRACE_LOG` overrides the path, as in the Cursor entrypoint.

Auto-update writes new versions into the install bind, and step 5 picks them up on the next start.

### Host CLAUDE_CONFIG_DIR

Setting it on the host is optional.
The docs say:

> Set `CLAUDE_CONFIG_DIR=~/.claude` on the host if you want the host and the container to share one `.claude.json`, including onboarding, project trust, and user MCP servers.
> Without it, both still share `~/.claude`, and each keeps its own `.claude.json`.

On a Linux host the credentials file is in `~/.claude`, so the login is shared either way.
Whether Claude also needs the account metadata in `.claude.json` to skip login is checked in the smoke.

### Network

- Anthropic hosts are tunneled on `agents.claude.tunnel`.
- The list comes from a smoke run with `unmatched: deny` and `--log audit=warn`.
  Each `DENY` line names a host Claude needs.
- A second smoke run with the list confirms that a prompt completes with no denied Anthropic host.

### Docs

- README getting started becomes agent-neutral.
  - Step 2 copies `docs/cursor/image` or `docs/claude/image` into `~/.config/agentcon.d/<agent>`.
  - Step 3 shows the `agents.yaml` shape with `image`, `build`, `mounts`, and `tunnel`, and links to `docs/cursor.md` and `docs/claude.md` for the full entry.
  - The `contexts.yaml` example names `agent: cursor` with a note that it can be `claude`.
  - Cursor-specific lines, such as `--resume` and the Cursor login note, move to `docs/cursor.md`.
- `docs/claude.md` covers the copy step, the full `agents.claude` entry, the binds, the entrypoint, the optional host `CLAUDE_CONFIG_DIR`, the tunnel list, the build, and login.
- `docs/cursor.md` takes the full `agents.cursor` entry from the README.
- `docs/development.md` and `docs/bouncer.md` mention the Claude example where they mention the Cursor one.

## Commits

1. Plan.
2. `docs/claude/image`, with agent-neutral comments in the shared scripts of both images.
3. Docs.
4. Tunnel list from the smoke, in `docs/claude.md`.
5. The smoke script under `ad_hoc/issue-25/smoke/` for the record.

## Verification

- `bash -n` and `shellcheck` pass on the entrypoint.
- `go build ./...`, `go test -race ./...`, and `golangci-lint run ./...` still pass.
- Smoke handoff, from the Docker-outside-of-Docker container:
  1. Build the image through `agentcon run` with the Claude example and `unmatched: deny`.
     Log in, send one prompt, and collect the `DENY` hosts from the sidecar log.
  2. Run again with the collected tunnel list.
     Confirm Claude Code is not reinstalled, the login is reused, a prompt completes, and no Anthropic host is denied.
