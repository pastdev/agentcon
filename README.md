# agentcon

Containerized agent workspace.
The host CLI is `agentcon`.
It starts a container against a configured context, bind-mounts a host tree at `/workspace`, and runs a harness.

Command flags live in `--help`.
This page is the short path from install to a running session.

## Getting started

### Install

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

See [docs/development.md](docs/development.md) for building the CLI from source.

### Configure

Config is loaded from `/etc/agentcon.d`, `~/.config/agentcon.d`, and `./agentcon.d`.
Maps merge.
Slices replace.

`image` is any Linux image that honors the workspace contract.
`run` starts it as your host UID, mounts the context `root` at `/workspace`, sets `AGENTCON_HOST_ROOT` to that host path, and for Cursor bind-mounts host `~/.cursor` at `/agent/cursor`.
The image entrypoint is responsible for a writable home and for starting the harness.

This repository's `image/base` is one implementation of that contract.

```yaml
default_context: git
contexts:
  git:
    image: pastdev.com/agentcon:latest
    root: ~/git
```

`agentcon run` uses `default_context`.
`agentcon run NAME` uses that context.
Cwd must be at or under the selected `root`.

### Run

```bash
cd ~/git/github.com/you/your-repo
agentcon run
```

Arguments after `--` go to the harness.

```bash
agentcon run -- --resume
```

Each `run` is a new container.
`--resume` asks Cursor to continue the previous chat.
Linux CLI login is stored on the same `~/.cursor` bind, so a later container can reuse it.

You can run more than one project under the same `root` at once.
Start each from that project's directory.
Host commands such as `agentcon bouncer approve` pick the session from cwd.
`--project` and `--slug` are only needed when that is ambiguous.

## Bouncer

A `bouncer` section on a context starts a sidecar next to the agent.
Credentials stay in the sidecar.
The agent reaches the network through that proxy.
HTTP and SSH can be allowed, asked, or denied.
TypeScript filters can inspect a matched request, including git-smart-HTTP and GraphQL.

Enable it by adding `bouncer` to the context.
`default_profile` is required.
This overlay is additive on the `git` context from getting started.
It lets git and GitHub API traffic through for one repo, injects a Bitwarden PAT, and runs a branch-protection filter.
Put filter files next to the YAML, under `ts/filters/`.

```yaml
contexts:
  git:
    bouncer:
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

Cursor product hosts are tunneled by default.
Unknown hosts follow `unmatched`.
Leftover paths on an intercepted host do not get the credential.

The host prompts for Bitwarden unlock when that source is used.
Answer an `ask` rule with `agentcon bouncer approve` from the project directory.

Policy shape, credentials, sessions, filters, and the sidecar layout are in [docs/bouncer.md](docs/bouncer.md).

## See also

- [docs/bouncer.md](docs/bouncer.md) for bouncer design and policy details
- [docs/development.md](docs/development.md) for building, testing, and image work
- `agentcon --help` and `agentcon bouncer --help` for flags
