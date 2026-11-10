# Cursor

`agentcon` does not embed Cursor.
A Cursor session is an agent image that starts `agent`, plus config that names the binds and the hosts the CLI must reach.
The image still has to honor the [workspace contract](../README.md#workspace-contract).
This example adds Cursor binds and an entrypoint on top of that minimum.

The [README](../README.md#getting-started) is the install-to-`run` path.
This page is the Cursor entry for `agents.yaml` and the contract behind it.

## Get started

[docs/cursor/image](cursor/image) is a starting point, not a product image.
Copy it into `~/.config/agentcon.d/cursor`, then edit that copy's Dockerfile to add project-specific tools.
That directory can later be its own git repo.

From a clone of this repository:

```bash
mkdir -p ~/.config/agentcon.d
cp -a docs/cursor/image ~/.config/agentcon.d/cursor
```

From a release-only install:

```bash
mkdir -p ~/.config/agentcon.d/cursor
curl --fail --location \
  https://github.com/pastdev/agentcon/archive/refs/heads/master.tar.gz \
  | tar \
      --directory ~/.config/agentcon.d/cursor \
      --extract \
      --gzip \
      --strip-components 4 \
      --wildcards \
      '*/docs/cursor/image'
```

Then add the [agent entry](#agent-entry) to `agents.yaml`, and set `agent: cursor` on a context as in the README.

## Agent entry

`~/.config/agentcon.d/agents.yaml`:

```yaml
agents:
  cursor:
    image: pastdev.com/agentcon-cursor:latest
    build:
      context: '{{relativeDir "cursor"}}'
    mounts:
      - source: "{{home}}/.cursor"
        target: /agent/cursor
      - source: "{{home}}/.config/cursor"
        target: /agent/cursor-config
    tunnel:
      - cursor.com
      - "*.cursor.com"
      - "*.cursor.sh"
      - "*.cursor-cdn.com"
      - "*.cursorapi.com"
      - "*.cursorvm.com"
      - accounts.spacex.ai
      - accounts.x.ai
      - anysphere-binaries.s3.us-east-1.amazonaws.com
      - agent-stores.s3.us-east-1.amazonaws.com
      - cloud-agent-artifacts.s3.us-east-1.amazonaws.com
      - cursor.blob.core.windows.net
```

`{{relativeDir "cursor"}}` resolves against that copy of the image, next to `agents.yaml`.

## Image and binds

Linux CLI chats live in `~/.cursor`.
Linux CLI login lives in `~/.config/cursor/auth.json`.
Those are separate host directories.
Container targets stay under `/agent`.
The example entrypoint links them to `$HOME/.cursor` and `$HOME/.config/cursor`.

`run` creates the host directories if they are missing.
It bind-mounts them and unions `tunnel` onto root bouncer profiles.

`agentcon run -- --resume` continues the previous Cursor chat.
It needs an existing chat and a stored login.
First start in a new login location still needs `agent login` inside the session.
Linux CLI login is stored on the `~/.config/cursor` bind, so a later container can reuse it.

## Tunnel

Cursor product hosts must be tunneled or the CLI cannot log in or complete.
Put that list on `agents.cursor.tunnel`.
Root bouncer profiles that do not `extends` another profile receive it.

If a vendor host is missing, add it on the agent `tunnel` list or on the profile `tunnel` list.
See [bouncer.md](bouncer.md).

The list in the [agent entry](#agent-entry) is the current set:

- `cursor.com`
- `*.cursor.com`
- `*.cursor.sh`
- `*.cursor-cdn.com`
- `*.cursorapi.com`
- `*.cursorvm.com`
- `accounts.spacex.ai`
- `accounts.x.ai`
- `anysphere-binaries.s3.us-east-1.amazonaws.com`
- `agent-stores.s3.us-east-1.amazonaws.com`
- `cloud-agent-artifacts.s3.us-east-1.amazonaws.com`
- `cursor.blob.core.windows.net`

## Build

If `build` is set, `run` always builds and tags the image, then starts it.
Progress is logged at info, the same shape as `docker build --progress plain`.
Docker layer cache makes an unchanged Dockerfile cheap.
Set `pull_policy: always` or pass `--pull=always` to also refresh the base image.
Edit `~/.config/agentcon.d/cursor/Dockerfile` when the agent needs more tools.

The [workspace contract](../README.md#workspace-contract) is what `run` always does.
This example also bind-mounts the Cursor dirs above and uses this entrypoint:

1. Gives that UID a writable `$HOME` and a passwd line
2. Links `/agent/cursor` to `$HOME/.cursor`
3. Links `/agent/cursor-config` to `$HOME/.config/cursor`
4. Links `$HOME/.local/share/cursor-agent` to `/agent/cursor/local/share/cursor-agent` on that same bind.
   `cursor.com/install` unpacks the CLI there and puts `agent` in `~/.local/bin`.
   On later starts, the entrypoint recreates that wrapper from the persisted version dir.
5. `exec agent` with the container args

`AGENT_CLI_CREDENTIAL_STORE=file` keeps Linux login on disk instead of a keyring.

Entrypoint xtrace is off unless `AGENTCON_XTRACE=1`.
When that is set, bash writes the trace to `/agent/cursor/entrypoint.xtrace`.

Build by hand if you want a tag without `agentcon run`:

```bash
docker build --progress plain --tag pastdev.com/agentcon-cursor:latest ~/.config/agentcon.d/cursor
```

The example Dockerfile also installs Go, Node, golangci-lint, and CLI tools agents use (`rg`, `fd`, `jq`, `yq`, `gh`, `shellcheck`).
Add more toolchains in later layers, or edit the copy in the config directory and let `run` rebuild.
