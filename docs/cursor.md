# Cursor

`agentcon` does not embed Cursor.
A Cursor session is an agent image that starts `agent`, plus config that names the binds and the hosts the CLI must reach.
The image still has to honor the [workspace contract](../README.md#workspace-contract).
This example adds Cursor binds and an entrypoint on top of that minimum.

The [README](../README.md) is the install-to-`run` path, including the example `agents.yaml` and `contexts.yaml`.
This page is the Cursor-specific contract behind those files.

This repository's [image](image) is a maintained working example.
It is not a product image.

## Image and binds

Copy the example image into the config directory.
That directory can later be its own git repo.

```bash
cp -a docs/cursor/image ~/.config/agentcon.d/cursor
```

Linux CLI chats live in `~/.cursor`.
Linux CLI login lives in `~/.config/cursor/auth.json`.
Those are separate host directories.
Container targets stay under `/agent`.
The example entrypoint links them to `$HOME/.cursor` and `$HOME/.config/cursor`.

`run` creates the host directories if they are missing.
It bind-mounts them and unions `tunnel` onto root bouncer profiles.

`--resume` continues the previous Cursor chat.
It needs an existing chat and a stored login.
First start in a new login location still needs `agent login`.

## Tunnel

Cursor product hosts must be tunneled or the CLI cannot log in or complete.
Put that list on `agents.cursor.tunnel`.
Root bouncer profiles that do not `extends` another profile receive it.

If a vendor host is missing, add it on the agent `tunnel` list or on the profile `tunnel` list.
See [bouncer.md](bouncer.md).

The list in the README getting-started `agents.yaml` is the current set:

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
