# Development

Usage is in the [README](../README.md).
Bouncer policy and sidecar layout are in [bouncer.md](bouncer.md).
[AGENTS.md](../AGENTS.md) is the contract for automated agents working in this repository.

## CLI from source

This tree has an `agentcons` snapshot script, the same idea as `askais`.
It builds `agentcon-snapshot` under `~/.local/bin` and leaves a released `agentcon` alone.
Symlink it onto your `PATH`:

```bash
ln -s "$(pwd)/agentcons" "${HOME}/.local/bin/agentcons"
```

Then run from the project you want to open:

```bash
agentcons run
```

Rebuild when the source changes:

```bash
REBUILD=1 agentcons run
```

`go run ./cmd/agentcon` works from a checkout.
`go run` of this module from another directory does not.
The snapshot binary keeps the caller's cwd.

## Tests and lint

```bash
go test ./...
golangci-lint run
```

## Image

A context may use any Linux image that honors the workspace contract in the [README](../README.md).
This tree does not ship a product image.
[docs/cursor/image](cursor/image) is a maintained Cursor example.

```bash
docker build --progress plain --tag pastdev.com/agentcon-cursor:latest docs/cursor/image
```

Copy that tree into the config directory for a real agent.
The [README](../README.md) getting-started path does that copy and the YAML.
Set `build.context` with `{{relativeDir "cursor"}}` so it resolves against that file before configs merge.
When `build` is set, `run` always builds and relies on the daemon cache.
Build progress is logged at info.

When bouncer is enabled, `run` starts the sidecar from `registry.access.redhat.com/ubi10/ubi-minimal:10.2` and replaces the entrypoint with a copied `agentcon` binary.
Entrypoint xtrace is off unless `AGENTCON_XTRACE=1`.
When that is set, the Cursor example writes the trace to `/agent/cursor/entrypoint.xtrace` (host `~/.cursor/entrypoint.xtrace`).
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
