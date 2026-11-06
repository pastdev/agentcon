# Plan: Re-home agent-bouncer and start it from agentcon run (issue 9)

Issue: https://github.com/pastdev/agentcon/issues/9

Upstream design notes: [DESIGN.md](./DESIGN.md)

## Goal

Re-home agent-bouncer into this repository as `agentcon bouncer`.
When a context has bouncer config, `agentcon run` starts a bouncer sidecar
with two Docker networks so the agent cannot reach the internet except
through bouncer.

## Non-goals

Do not export a public Go API in the first release.
Do not bind-mount filter trees into the sidecar.
Do not bake bundled JavaScript into `agentcon config` output.
Do not signal pending approvals to the agent.
Do not attach `run` to a bouncer already running on the host.
Do not have `agentcon bouncer` create containers or networks.

## Decisions

### Re-home

- This repo is the canonical home.
- Keep bouncer under `internal/bouncer/` so it is not an accidental public API.
- Thin `cmd/agentcon/bouncer` is the v1 consumer boundary.
- A later Go import, if any, is the main of an isolated process, not an
  in-process proxy next to the agent.
- Preserve tests, examples, and the design notes in this folder.

### Launch modes

- `agentcon bouncer` is the bouncer process.
  It runs wherever it is invoked (host, VM, or a container the caller already
  started).
- `agentcon run` is the supervisor.
  With bouncer config it creates two networks, a bouncer container, then the
  agent container.
- Without bouncer config, `run` stays one agent container on the default
  bridge.
- `run` always starts its own sidecar when the context asks for bouncer.
- `run` owns sidecar lifetime: start before the agent, tear down after.

### Networks and mgmt

- Agent network: Docker `internal`, agent and bouncer only.
- External network: bouncer only, egress plus mgmt.
- `run` passes `AGENT_NETWORK` and `MANAGEMENT_NETWORK` CIDRs plus
  `MANAGEMENT_PORT`.
- `serve` inspects its own addresses and binds the agent proxy on the
  agent-network IP and mgmt on the external-network IP.
- Publish mgmt as `127.0.0.1:$PORT:$PORT`.
- `run` talks to mgmt over HTTP on the host.
  No `docker exec` for unlock or approvals.
- Confirm published-port forwarding lands on the external-network listen
  address.
  If it does not, fix the listen/publish mapping, not the two-network model.

### Sidecar bootstrap

- Start a generic pause/sleep container on both networks.
- Copy in a linux `agentcon` (host binary when `GOOS/GOARCH` match, otherwise
  the matching GitHub release asset for this CLI version).
- Copy in the merged bouncer YAML and one merged `ts/` tree.
- `exec -d` `agentcon bouncer serve`.
- `run` polls mgmt status.
  On pending Bitwarden it prompts on the host TTY and POSTs the passphrase.
  Never log the body.
- After status is ready, start the agent on the agent network only and copy
  the TTY to that attach.
- `serve` never gets the TTY.
- Inject bouncer env into the agent (`HTTPS_PROXY`, CA bundle, SSH routing).
- Do not mount bouncer state into the agent.

### Approvals

- Mgmt `GET` lists pending asks.
- Mgmt `POST` approve/deny.
- Unanswered asks fail closed on `approvals.timeout` (default 2m).
- State is in-process in `serve` (map plus channel).
- `run` may poll to notify the user.
  Do not overlay prompts on the agent TTY.

### Config

- A context opts in with an embedded `bouncer` section (the real policy, not
  paths to other YAML).
- Filter source lives under `agentcon.d/ts/filters/` plus
  `agentcon.d/ts/node_modules/`.
- Overlay lookup matches config dirs.
  Later path wins.
  Host merges into one `ts/` tree, then copies it.
- `{{ tsFilter "name.ts" }}` (configloader `YamlValueTemplateUnmarshal`)
  resolves a name in those dirs.
- Templates run on the host.
  `serve` still esbuild-bundles from the copied tree at start
  (`github.com/evanw/esbuild`, then goja, never Node).
- State directory is derived: `~/.local/state/agentcon/<context>/bouncer`.
  Reused across runs.
  Bind-mounted only into the bouncer container.
- No `config:` or `state:` keys.
- `pkg/config` maps the embedded section onto bouncer types.
  Other `pkg/**` packages do not import `pkg/config`.

### Container API

- Extend `pkg/container.Runtime` for network create/remove, copy-in, exec,
  and port publish.
- Keep using `github.com/moby/moby/client` and `github.com/moby/moby/api`.
- Do not shell out to the `docker` CLI.

## Layout

```text
ad_hoc/issue-9/bouncer.plan.md
ad_hoc/issue-9/DESIGN.md
cmd/agentcon/bouncer/
internal/bouncer/
pkg/config/
pkg/run/
pkg/container/
pkg/container/moby/
```

## Acceptance

- `agentcon bouncer` exposes the existing bouncer CLI against embedded
  context config.
- `agentcon run` with a `bouncer` section starts two networks, a sidecar,
  and an agent that has no route off the agent network.
- `agentcon run` without a `bouncer` section is unchanged.
- Bitwarden unlock and approvals work through published mgmt, not
  `docker exec`.
- `go test ./...` and `golangci-lint run` pass.
