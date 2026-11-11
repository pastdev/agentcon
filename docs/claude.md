# Claude Code

`agentcon` does not embed Claude Code.
A Claude Code session is an agent image that starts `claude`, plus config that names the binds and the hosts the CLI must reach.
The image still has to honor the [workspace contract](../README.md#workspace-contract).
This example adds Claude binds and an entrypoint on top of that minimum.

The [README](../README.md#getting-started) is the install-to-`run` path.
This page is the Claude agent entry and the contract behind it.

## Get started

[docs/claude/image](claude/image) is a starting point, not a product image.
Copy it into `~/.config/agentcon.d/claude`, then edit that copy's Dockerfile to add project-specific tools.
That directory can later be its own git repo.

From a clone of this repository:

```bash
mkdir -p ~/.config/agentcon.d
cp -a docs/claude/image ~/.config/agentcon.d/claude
```

From a release-only install:

```bash
mkdir -p ~/.config/agentcon.d/claude
curl --fail --location \
  https://github.com/pastdev/agentcon/archive/refs/heads/master.tar.gz \
  | tar \
      --directory ~/.config/agentcon.d/claude \
      --extract \
      --gzip \
      --strip-components 4 \
      --wildcards \
      '*/docs/claude/image'
```

Then save the [agent entry](#agent-entry) as `~/.config/agentcon.d/claude.yaml`, and set `agent: claude` on a context as in the README.

## Agent entry

`~/.config/agentcon.d/claude.yaml`:

```yaml
agents:
  claude:
    image: pastdev.com/agentcon-claude:latest
    build:
      context: '{{relativeDir "claude"}}'
    mounts:
      - source: "{{home}}/.claude"
        target: /agent/claude
      - source: "{{home}}/.local/share/agentcon/claude"
        target: /agent/claude-install
    tunnel:
      - api.anthropic.com
      - claude.ai
      - claude.com
      - platform.claude.com
      - sso.claude.com
      - downloads.claude.ai
      - mcp-proxy.anthropic.com
      - storage.googleapis.com
      - registry.npmjs.org
      - raw.githubusercontent.com
      - code.claude.com
      - "*.frame.claudeusercontent.com"
      - http-intake.logs.us5.datadoghq.com
      - browser-intake-us5-datadoghq.com
```

`{{relativeDir "claude"}}` resolves against the file it is in, so it finds the `claude` image copy beside `claude.yaml`.

## Binds

| Host source | Container target | Holds |
|---|---|---|
| `~/.claude` | `/agent/claude` | config, credentials, sessions, history, settings, skills, plugins |
| `~/.local/share/agentcon/claude` | `/agent/claude-install` | the Linux install of Claude Code |

The entrypoint sets `CLAUDE_CONFIG_DIR=/agent/claude`.
That puts all of Claude's state, including `.claude.json`, in the first bind.
The host and the container share `~/.claude`, and both persist.

Set `CLAUDE_CONFIG_DIR=~/.claude` on the host if you want the host and the container to share one `.claude.json`, including onboarding, project trust, and user MCP servers.
Without it, both still share `~/.claude`, and each keeps its own `.claude.json`.

`CLAUDE_CONFIG_DIR` does not move the binary.
The native installer writes versions to `~/.local/share/claude/versions` and links `~/.local/bin/claude`.
The second bind holds that tree for the container, so Linux binaries stay out of the shared `~/.claude`.
A macOS or Windows host keeps its own install where it always has.

`run` creates the host directories if they are missing.

## Login and sessions

The first start asks you to log in inside the session.
On a Linux host the login is stored in `~/.claude/.credentials.json`, which the host CLI uses too.
A macOS host keeps its login in the Keychain, so the container logs in once on its own and stores it in `~/.claude`.

Sessions are kept per working directory.
The container works under `/workspace`, so its sessions sit apart from the ones the host made for the same project.
`agentcon run -- --resume` lists the container's sessions for the current project.

## Tunnel

Claude Code hosts must be tunneled or the CLI cannot install, log in, or complete.
Put that list on `agents.claude.tunnel`.
Root bouncer profiles that do not `extends` another profile receive it.

Anthropic keeps the list in [Network access requirements](https://code.claude.com/docs/en/network-config#network-access-requirements).
The [agent entry](#agent-entry) takes that list with these changes:

- The two Datadog intake hosts are optional telemetry.
  They are listed so the bouncer does not log a denial for each event.
- `formulae.brew.sh` is left out, because it serves Homebrew installs only.
- `*-review.googlesource.com` and `bridge.claudeusercontent.com` are left out, because they serve Claude Desktop and the Chrome extension only.
- `github.com` is left out, because tunneling it would bypass a GitHub policy such as [docs/bouncer/github](bouncer/github).
  Plugin marketplaces hosted on GitHub need it.
  Add it to the agent `tunnel` list, or allow those repositories in your GitHub policy.

If a host is missing, a profile with `unmatched: deny` refuses it, and the sidecar logs it at `warn`:

```bash
docker logs agentcon-<bounded>-<slug>-bouncer 2>&1 | grep 'decision=deny'
```

Add it on the agent `tunnel` list or on the profile `tunnel` list.
See [bouncer.md](bouncer.md).

## Build

If `build` is set, `run` always builds and tags the image, then starts it.
Docker layer cache makes an unchanged Dockerfile cheap.
Set `pull_policy: always` or pass `--pull=always` to also refresh the base image.
Edit `~/.config/agentcon.d/claude/Dockerfile` when the agent needs more tools.
On a network that inspects TLS, add the inspection CA to your copy's Dockerfile right after `FROM`, as in [Trusting a TLS inspection CA](bouncer.md#trusting-a-tls-inspection-ca), so build-time downloads succeed.

The image does not contain Claude Code.
The [workspace contract](../README.md#workspace-contract) is what `run` always does.
This example also bind-mounts the directories above and uses this entrypoint:

1. Gives that UID a writable `$HOME` and a passwd line
2. Sets `CLAUDE_CONFIG_DIR=/agent/claude`
3. Links `$HOME/.local/share/claude` to `/agent/claude-install/share`
4. Links `$HOME/.local/bin/claude` to the newest installed version
5. Runs the native installer from `claude.ai/install.sh` when no version is installed
6. `exec claude` with the container args

Claude Code updates itself into the install bind, and the next start links the new version.

Entrypoint xtrace is off unless `AGENTCON_XTRACE=1`.
When that is set, bash writes the trace to `/agent/claude-install/entrypoint.xtrace`.

Build by hand if you want a tag without `agentcon run`:

```bash
docker build --progress plain --tag pastdev.com/agentcon-claude:latest ~/.config/agentcon.d/claude
```

The example Dockerfile also installs Go, Node, golangci-lint, and CLI tools agents use (`rg`, `fd`, `jq`, `yq`, `gh`, `shellcheck`).
Add more toolchains in later layers, or edit the copy in the config directory and let `run` rebuild.
