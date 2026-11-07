# agentcon

Containerized agent workspace.
The host CLI is `agentcon`.
It starts a container against a configured context, bind-mounts a host tree at `/workspace`, and runs an agent.

You need Docker Engine, with permission to talk to its socket.
Command flags live in `--help`.

## Getting started

This path uses the maintained Cursor example image.
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

Config is loaded from `/etc/agentcon.d`, `~/.config/agentcon.d`, and `./agentcon.d`.
Maps merge.
Slices replace.
Put the image next to the YAML so `build.context` does not point at a checkout you might delete.

From a clone of this repository:

```bash
mkdir -p ~/.config/agentcon.d
cp -a docs/cursor/image ~/.config/agentcon.d/cursor
```

From a release-only install:

```bash
mkdir -p ~/.config/agentcon.d
git clone --depth 1 https://github.com/pastdev/agentcon.git /tmp/agentcon
cp -a /tmp/agentcon/docs/cursor/image ~/.config/agentcon.d/cursor
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
This overlay is additive on the getting-started files.
It lets git and GitHub API traffic through for one repo, injects a Bitwarden PAT, and runs a branch-protection filter.
Put filter files next to the YAML, under `ts/filters/`.

`~/.config/agentcon.d/bouncers.yaml`:

```yaml
bouncers:
  github:
    default_profile: default
    credentials:
      github-pat:
        token:
          source: bitwarden
          email: you@example.com
          item: pat-github-agent
          path: $.notes
        export_env: [GH_TOKEN, GITHUB_TOKEN]
    profiles:
      default:
        unmatched: tunnel
        http:
          - name: github
            hosts: [github.com, api.github.com]
            credential: github-pat
            inject:
              bearer: true
              git: {basic: {username: x-access-token}}
            rules:
              - action: allow
                git: {}
                github_repo: [your-org/your-repo]
                filters:
                  - path: ts/filters/git-protect-branches.ts
                    config: {branches: [main, master]}
```

Point the context at it in `contexts.yaml`:

```yaml
contexts:
  git:
    agent: cursor
    root: "{{home}}/git"
    bouncer: github
```

Agent `tunnel` hosts are unioned onto root bouncer profiles.
Unknown hosts follow `unmatched`.
Leftover paths on an intercepted host do not get the credential.

The host prompts for Bitwarden unlock when that source is used.
Answer an `ask` rule with `agentcon bouncer approve` from the project directory.

Policy shape, credentials, sessions, filters, and the sidecar layout are in [docs/bouncer.md](docs/bouncer.md).

## See also

- [Workspace contract](#workspace-contract) for the minimum agent image
- [docs/cursor.md](docs/cursor.md) for the Cursor image, binds, and vendor hosts
- [docs/bouncer.md](docs/bouncer.md) for bouncer design and policy details
- [docs/development.md](docs/development.md) for building, testing, and snapshots
- `agentcon --help` and `agentcon bouncer --help` for flags
