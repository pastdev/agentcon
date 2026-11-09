# agentcon

Containerized agent workspace.
The host CLI is `agentcon`.
It starts a container against a configured context, bind-mounts a host tree at `/workspace`, and runs an agent.

You need Docker Engine, with permission to talk to its socket.
Command flags live in `--help`.

## Getting started

This path starts from the Cursor example image.
Any Linux image that honors the [workspace contract](#workspace-contract) can replace it later.

### 1. Install the CLI

`agentcon` is a self-contained binary.
[Pre-built releases](https://github.com/pastdev/agentcon/releases) cover linux, darwin, and windows.

```bash
binary="${HOME}/.local/bin/agentcon"
platform="$(uname -s | tr '[:upper:]' '[:lower:]')"
mkdir -p "$(dirname "${binary}")"
curl \
  --fail \
  --location \
  --output "${binary}" \
  "https://github.com/pastdev/agentcon/releases/latest/download/agentcon-${platform}"
chmod 0755 "${binary}"
```

Add `~/.local/bin` to `PATH` if it is not already there.
See [docs/development.md](docs/development.md) to build from source.

### 2. Copy the example image

[docs/cursor/image](docs/cursor/image) is a starting point, not a product image.
Copy it into `~/.config/agentcon.d/cursor`, then edit that copy's Dockerfile to add project-specific tools.

Config is loaded from `/etc/agentcon.d`, `~/.config/agentcon.d`, and `./agentcon.d`.
Maps merge.
Slices replace.
Name the YAML files `agents.yaml`, `bouncers.yaml`, and `contexts.yaml`.
Put the image next to the YAML so `build.context` does not point at a checkout you might delete.

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

### 3. Write agent and context files

Home in YAML is `{{home}}`.
`~` is not expanded.
`{{relativeDir "cursor"}}` resolves against the file that contains it, before overlays merge.

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

`~/.config/agentcon.d/contexts.yaml`:

```yaml
default_context: git
contexts:
  git:
    agent: cursor
    root: "{{home}}/git"
```

`image` is the tag `run` starts.
`build` is Compose-shaped.
When it is set, `run` always builds and tags that image before start, then relies on the Docker layer cache.
If `image` is omitted, the tag is `agentcon/<agent-name>`.

`run` always applies the [workspace contract](#workspace-contract).
The Cursor binds and tunnel hosts in the YAML above are extra.
Why they exist is in [docs/cursor.md](docs/cursor.md).

### 4. Confirm the merge

```bash
agentcon config
```

`build.context` should be the absolute `cursor` directory under `~/.config/agentcon.d`.

### 5. Run from a repo under `root`

```bash
cd ~/git/github.com/you/your-repo
agentcon run
```

`--context` selects another named context.
Omitting it uses `default_context`.
Cwd must be at or under that `root`.
`--agent` and `--bouncer` override the names on the context.

The first start builds the image.
Progress is logged at info:

```text
2:58PM INF building pastdev.com/agentcon-cursor:latest
2:58PM INF #1 [internal] load remote build context
2:58PM INF #1 DONE 0.0s
```

That can take a while.
Later starts replay cache (`CACHED`) unless the Dockerfile changed.
`--log warn` hides the build lines.
`--log-format json` emits the same lines as JSON.

Arguments after `--` go to the agent.

```bash
agentcon run -- --resume
```

Each `run` is a new container.
`--resume` asks Cursor to continue the previous chat.
The first start in a new login location still needs `agent login` inside the session.
Linux CLI login is stored on the `~/.config/cursor` bind, so a later container can reuse it.

You can run more than one project under the same `root` at once.
Start each from that project's directory.
Host commands such as `agentcon bouncer approve` pick the session from cwd.
`--project` and `--slug` are only needed when that is ambiguous.

## Workspace contract

`run` does not pick an agent binary.
It starts the image named by the context with a fixed host layout.
The image entrypoint or `CMD` is the agent.

### What `run` always does

- Starts a Linux container from `agents.<name>.image`
- Sets the container user to the host UID and GID
- Adds the container to group `0` (`group-add 0`)
- Bind-mounts the context `root` at `/workspace`
- Sets the working directory to `/workspace` plus the host cwd relative to `root`
- Sets `AGENTCON_HOST_ROOT` to that host `root` path
- Forwards `AGENTCON_XTRACE` when it is set on the host
- Bind-mounts each `agents.<name>.mounts` entry (and creates missing host source dirs)
- Passes arguments after `--` as the container command
- Allocates a TTY when stdin is a terminal
- Leaves the image `ENTRYPOINT` in place unless the run request overrides it

`run` does not run as root.
The numeric UID usually has no `/etc/passwd` line and no home.

### What the image must provide

- A Linux rootfs
- An `ENTRYPOINT` or `CMD` that starts the agent process and forwards container args
- A way for that unprivileged UID to exist as a user, usually by appending a passwd line
- A writable home for that user
- Tools that can work with the project at `/workspace`

Because the user is in group `0`, the usual setup is `chmod g=u` on `/etc/passwd` and on a home parent such as `/home`.
The entrypoint then appends a passwd line, creates `$HOME`, and `exec`s the agent.

Treat `/workspace` as the mounted host tree.
When the agent must name a host path, join `AGENTCON_HOST_ROOT` with the path under `/workspace`.

The image does not need Cursor, `/agent/*` binds, or a particular distro.
Those are agent-specific.
Declare extra binds on `agents.<name>.mounts` and document them with that agent.

[`docs/workspace/Dockerfile`](docs/workspace/Dockerfile) is that minimum.
It only creates a user and home, then starts a mock agent.

### When a bouncer is attached

The sidecar is a separate image.
`run` still starts your agent image under this contract, then adds:

- Proxy and CA environment (`HTTPS_PROXY`, `SSL_CERT_FILE`, `GIT_SSH_COMMAND`, `BOUNCER_*`, and related vars)
- Files under `/opt/agentcon` (binary, CA, SSH config)
- An isolated Docker network

Honor those proxy and CA variables.
If the agent uses git over SSH, the image needs `/usr/bin/ssh`.
`GIT_SSH_COMMAND` is `ssh -F /opt/agentcon/ssh/config`.

## Bouncer

A named bouncer is a credential collection and its profiles.
Add `contexts.<name>.bouncer` after a session already starts.
That starts a sidecar next to the agent.
Credentials stay in the sidecar.
The agent reaches the network through that proxy.

`default_profile` is required.
[docs/bouncer/github](docs/bouncer/github) is a starting point for a GitHub allowlist, including filters.
Copy it into `~/.config/agentcon.d`, then edit `bouncers.yaml` for your repo and Bitwarden items.
Keep one `bouncers.yaml`.
A leftover `bouncer.yaml` loses, because later files replace slices.

From a clone of this repository:

```bash
mkdir -p ~/.config/agentcon.d
cp -a docs/bouncer/github/. ~/.config/agentcon.d/
```

From a release-only install:

```bash
mkdir -p ~/.config/agentcon.d
curl --fail --location \
  https://github.com/pastdev/agentcon/archive/refs/heads/master.tar.gz \
  | tar \
      --directory ~/.config/agentcon.d \
      --extract \
      --gzip \
      --strip-components 4 \
      --wildcards \
      '*/docs/bouncer/github'
```

That overlay is additive.
It does not set `agent` or `root`.
If your context is not named `git`, rename that key in `bouncers.yaml`.

How to write TypeScript filters is in [docs/bouncer-filters.md](docs/bouncer-filters.md).

Agent `tunnel` hosts are unioned onto root bouncer profiles.
Unknown hosts follow `unmatched`.
[Choosing `unmatched`](docs/bouncer.md#choosing-unmatched) covers when to use `tunnel` or `deny`.
Leftover paths on an intercepted host do not get the credential.

`agentcon run` asks for the Bitwarden master password at its terminal when that source is used.
Answer an `ask` rule with `agentcon bouncer approve` from the project directory.

Policy shape, credentials, sessions, and the sidecar layout are in [docs/bouncer.md](docs/bouncer.md).

## See also

- [Workspace contract](#workspace-contract) for the minimum agent image
- [docs/workspace/Dockerfile](docs/workspace/Dockerfile) for a mock image that only honors that contract
- [docs/cursor.md](docs/cursor.md) for the Cursor image, binds, and vendor hosts
- [docs/bouncer.md](docs/bouncer.md) for bouncer design and policy details
- [docs/bouncer-filters.md](docs/bouncer-filters.md) for TypeScript filters
- [docs/bouncer/github](docs/bouncer/github) for a GitHub allowlist starting point
- [docs/development.md](docs/development.md) for building, testing, and snapshots
- `agentcon --help` and `agentcon bouncer --help` for flags
