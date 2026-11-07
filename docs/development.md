# Development

Usage is in the [README](../README.md).
Bouncer policy and sidecar layout are in [bouncer.md](bouncer.md).
[AGENTS.md](../AGENTS.md) is the contract for automated agents working in this repository.

## CLI from source

```bash
go build -o "${HOME}/.local/bin/agentcon" ./cmd/agentcon
```

`go run ./cmd/agentcon` works from a checkout.
`go run` of this module from another directory does not.
Build the binary, then invoke it so cwd stays the project you want to open.

## Tests and lint

```bash
go test ./...
golangci-lint run
```

## Image

A context may use any Linux image that honors the workspace contract in the [README](../README.md).
This tree ships one implementation.

```bash
docker build --progress plain --tag pastdev.com/agentcon:latest image/base/
```

That entrypoint prepares a writable home for an arbitrary container UID, links harness state under `/agent`, and starts the harness.
When bouncer is enabled, `run` starts the sidecar from `registry.access.redhat.com/ubi10/ubi-minimal:10.2` and replaces the entrypoint with a copied `agentcon` binary.
Entrypoint xtrace is off unless `AGENTCON_XTRACE=1`.
When that is set, bash writes the trace to `/agent/<harness>/entrypoint.xtrace` (host `~/.cursor/entrypoint.xtrace` for Cursor).
Override the path with `AGENTCON_XTRACE_LOG`.

## Go layout

Code under `cmd/**` is for commands only.
Commands may only process user input and format user output.
They may call services under `pkg/**`.
They must not hold domain logic that belongs in `pkg/**`.

Do not import `pkg/config` from other packages under `pkg/**`.
That package maps loaded config into the types each service package already owns.

## Handoff

The agent in the container does not have host Docker or GitHub credentials except through bouncer.
Actions that need credentials or elevated host access can use a handoff script under `.agentcon/` at the project root.
That directory is gitignored.
See [AGENTS.md](../AGENTS.md) for the script shape.

If you want the agent to write `.agentcon/` without approval prompts, add allow rules in host `~/.cursor/cli-config.json`.

```json
{
  "permissions": {
    "allow": [
      "Read(.agentcon/**)",
      "Write(.agentcon/**)",
      "Delete(.agentcon/**)"
    ]
  }
}
```

Restart the agent session after you change that file.
Keep `approvalMode` as `allowlist` unless you intend a broader grant.
