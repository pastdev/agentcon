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

`pull_policy` decides when `run` fetches images from a registry.
`missing` (the default) pulls `image` only when it is not present locally.
`always` pulls it before every start, and a `build` refreshes its base images.
`never` never pulls `image` and fails when it is missing, though a `build` still fetches base images it does not have.
`run` pulls without registry credentials, so run `docker pull` yourself for a private image.

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
`--pull` overrides every `pull_policy` for one run, including `sidecar.pull_policy`.

The first start builds the image.
Progress is logged at info:

```text
2:58PM INF building pastdev.com/agentcon-cursor:latest log=cli
2:58PM INF #1 [internal] load remote build context log=cli
2:58PM INF #1 DONE 0.0s log=cli
```

That can take a while.
Later starts replay cache (`CACHED`) unless the Dockerfile changed.
`--log warn` hides the build lines.
`--log-format json` emits the same lines as JSON.
[Logging](#logging) covers the log flags.

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

- Pulls `agents.<name>.image` first when `pull_policy` calls for it
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
It defaults to `registry.access.redhat.com/ubi10/ubi-minimal:10.2`, and `sidecar` replaces it.
[Sidecar image](docs/bouncer.md#sidecar-image) has the fields.
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

On a network that inspects TLS, the sidecar needs the inspection CA in its image.
[Trusting a TLS inspection CA](docs/bouncer.md#trusting-a-tls-inspection-ca) shows the Dockerfile.

Policy shape, credentials, sessions, and the sidecar layout are in [docs/bouncer.md](docs/bouncer.md).

## Logging

agentcon logs to stderr through three loggers.
Every line has a `log` field that names its logger.

| Log | Covers | Default level |
|---|---|---|
| `cli` | the agentcon process: config, image builds, container setup | `info` |
| `bouncer` | the bouncer: listeners, credentials, filters, reloads | the `cli` level |
| `audit` | one line per bouncer decision | `info` |

`--log` takes `[name=]level` and can repeat.
A level without a name sets `cli`.
Levels are `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic`, and `disabled`.

```bash
agentcon --log warn --log bouncer=debug --log audit=warn run
```

Each decision logs at a level that matches it.
Tunnels log at `debug`, allows at `info`, denials at `warn`, and errors at `error`.
`--log audit=warn` shows only what was blocked or failed, and `--log audit=debug` adds tunnels.

`--log-format` is `pretty` or `json` for all three loggers.
Pretty output is colored only on a terminal, so `grep 'log=audit'` works on redirected output.

`run` passes the bouncer and audit levels and the format to the sidecar.
Sidecar output goes to its container log, not your terminal:

```bash
docker logs -f agentcon-<bounded>-<slug>-bouncer 2>&1 | grep 'log=audit'
```

Nothing is written to disk.
The sidecar is removed when `run` exits, so follow its log during the session to keep a record.
Redirect stderr from `agentcon bouncer serve` to keep its log.

## Docker-outside-of-Docker

`agentcon run` can itself run inside a container that drives the host's Docker daemon.
Two kinds of environment variables describe that setup.
Without them, `run` assumes it shares a host with the daemon.

- `DOOD_NETWORK=<network>` names a Docker network the calling container is attached to.
  Its presence means `agentcon` runs inside a container, and that network has egress to the internet.
- `DOOD_MOUNT_<NAME>=<volume>:<path>` says that `<path>` inside the calling container is the Docker volume `<volume>`.
  Set any number of them.
  `<NAME>` is only a label.

With any `DOOD_MOUNT_*` set, `run` translates every bind source before it creates a container.
That covers the context `root`, `agents.<name>.mounts`, and the sidecar's `SSH_AUTH_SOCK`.
A source at or under a `<path>` becomes a mount of `<volume>` with the matching subpath.
The longest matching `<path>` wins.
A source under no `<path>` fails with its name, because the Docker host cannot resolve it.
Volume subpaths need Docker Engine 26 or later.
Build contexts are read by `agentcon` and sent to the daemon, so they need no translation.

With `DOOD_NETWORK` set, the bouncer sidecar uses it as its external network instead of a network `run` creates.
`run` publishes no host port and reaches the sidecar by container name on that network.
`agentcon bouncer` commands in the same container reach it the same way.
The agent stays on the internal agent network only.
`run` refuses a `DOOD_NETWORK` that is marked internal, because the sidecar would have no egress.
Other containers on `DOOD_NETWORK` can reach the sidecar's management port, though they still need its admin token.

## See also

- [Workspace contract](#workspace-contract) for the minimum agent image
- [docs/workspace/Dockerfile](docs/workspace/Dockerfile) for a mock image that only honors that contract
- [docs/cursor.md](docs/cursor.md) for the Cursor image, binds, and vendor hosts
- [docs/bouncer.md](docs/bouncer.md) for bouncer design and policy details
- [docs/bouncer-filters.md](docs/bouncer-filters.md) for TypeScript filters
- [docs/bouncer/github](docs/bouncer/github) for a GitHub allowlist starting point
- [docs/development.md](docs/development.md) for building, testing, and snapshots
- `agentcon --help` and `agentcon bouncer --help` for flags
