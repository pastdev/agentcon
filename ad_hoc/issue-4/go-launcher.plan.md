# Plan: Replace agent_exec.sh with agentcon run (issue 4)

Issue: https://github.com/pastdev/agentcon/issues/4

## Goal

Add `agentcon run` so the host CLI starts an agent container from a named context.
A context is an image plus one host root bind-mounted at `/workspace`.

## Non-goals

Do not filter or remap subpaths under the root.
Do not rebuild an image on every run.
Do not change the image entrypoint.
Do not talk to Docker from inside the agent container.

## Decisions

- Config key `contexts` is a map of name to `{image, root}`
- Top-level `default_context` names the context for bare `agentcon run`
- Expand `~` in `root`
- `agentcon run NAME` uses that context
- Error if cwd is not at or under the selected `root`
- One bind: expanded `root` to `/workspace`
- Container cwd is `/workspace` plus the path relative to `root`
- Inject `AGENTCON_HOST_ROOT` with the expanded host `root`
- Harness state stays a separate mount (`~/.cursor` to `/agent/cursor` for cursor)
- Extra args after `--` go to the harness
- `cmd/**` is CLI I/O only
- Domain packages do not import `pkg/config`
- `pkg/config.NewRunRequest` maps a named or default context onto `run.Request`
- `pkg/run` does not know about the map of configured contexts
- Container create/start lives behind `pkg/container.Runtime`
- Default implementation uses `github.com/moby/moby/client` and `github.com/moby/moby/api`
- Do not use `github.com/docker/docker` or shell out to the `docker` CLI
- Only `agentcon run`, not a bare `agentcon` default

## Layout

```text
ad_hoc/issue-4/go-launcher.plan.md
cmd/agentcon/run/run.go
pkg/config/config.go
pkg/config/run.go
pkg/container/runtime.go
pkg/container/moby/runtime.go
pkg/run/run.go
pkg/run/run_test.go
```

## Acceptance

- From a directory under the selected `root`, `agentcon run` starts that context's image
- The container has `AGENTCON_HOST_ROOT` set to that host root
- `go test ./...` and `golangci-lint run` pass
