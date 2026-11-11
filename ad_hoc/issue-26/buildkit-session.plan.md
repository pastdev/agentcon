# Plan: Build images through a BuildKit session (issue 26)

Issue: https://github.com/pastdev/agentcon/issues/26

## Goal

`moby.Runtime.Build` sends its context through a BuildKit session, as `docker build` does, instead of uploading a tar body on `POST /build`.
Builds stop stalling in `load remote build context` on Docker Desktop.

## Non-goals

Do not change `container.Runtime`, `container.Build`, or anything in `pkg/run`.
Do not add registry authentication to builds.
Builds pull without credentials, as they do today.
Do not keep the tar upload as a fallback.
A stall never surfaces as an error, so a fallback could not tell when to take over.
Do not support a remote context such as a git URL.

## Decisions

### Session build

`Build` in `pkg/container/moby/build.go`:

1. Create a session with `session.NewSession`.
2. Attach `filesync.NewFSSyncProvider` with two directories:
   - `context`: the build context, filtered by the ignore patterns below.
   - `dockerfile`: the directory that holds the Dockerfile.
3. Run the session in a goroutine over `DialHijack(ctx, "/session", proto, meta)`.
4. Call `ImageBuild` with a nil body, `SessionID` set to the session ID, `RemoteContext: "client-session"`, the Dockerfile's base name, `Version: BuilderBuildKit`, and the tags and `PullParent` as today.
5. Display the progress stream as today.
6. Close the session when the build ends, whether it succeeded or failed, and wait for the session goroutine to return.

`container.Build.Dockerfile` stays relative to the context.
The `dockerfile` directory is the context joined with the Dockerfile's directory, and the build gets the base name.

`tarDirectory` and its tests are removed.
`apiClient` gains `DialHijack`.

### Ignore files

The context honors ignore patterns, as `docker build` does.

- `<Dockerfile>.dockerignore` beside the Dockerfile wins when it exists.
- Otherwise `.dockerignore` at the context root is used.
- With neither, nothing is excluded.

Patterns are parsed with the same reader `docker build` uses and passed to the context's filter as exclude patterns.

### Dependencies

`moby/buildkit` is already a direct dependency.
Its `session` and `session/filesync` packages are new imports.
`tonistiigi/fsutil` becomes a direct dependency for the filtered context.
`google.golang.org/grpc` moves from indirect to direct if the session code needs it at the call site.

## Tests

### Unit

`pkg/container/moby/build_test.go`, with the existing fake API, which gains `DialHijack`:

- The build request has no body, a `SessionID` equal to the session's ID, `RemoteContext: "client-session"`, the tags, and the Dockerfile's base name.
- A Dockerfile in a subdirectory gives that subdirectory as the `dockerfile` directory and its base name to the build.
- Ignore patterns come from `<Dockerfile>.dockerignore` when present, else `.dockerignore`, else none.
- The session is closed after a successful build and after a failed one.
- The existing progress display tests still pass.

### Integration

`pkg/container/moby/build_integration_test.go` starts with `//go:build integration`.
Plain `go test ./...` and lint skip it.
`go test -tags integration ./pkg/container/moby/...` runs it.

- `requireDocker(t)` creates a client from the environment and pings it with a short timeout.
  When that fails, it calls `t.Skip` with the reason.
- `testdata/session-build/` holds a Dockerfile, a `.dockerignore`, a kept file, and an ignored file.
  The Dockerfile starts `FROM registry.access.redhat.com/ubi10/ubi-minimal:10.2`.
  It uses a heredoc and `RUN --mount=type=cache`, which need BuildKit.
  It copies the context and runs `test -e` on the kept file and `test ! -e` on the ignored file, so a wrong context fails the build.
- The test builds through `Runtime.Build` five times, each under a 90 second context timeout, so a stall fails the test instead of hanging it.
- It removes the image it tagged when it finishes.

## Commits

1. Plan.
2. Session build, ignore files, unit tests, and the removal of `tarDirectory`.
3. Integration test.

## Verification

- `go build ./...`, `go test -race ./...`, and `golangci-lint run ./...` pass.
  `go vet` passes for darwin and windows.
- `go test -tags integration ./pkg/container/moby/...` skips where Docker is not available.
- Handoff, on the Docker Desktop host:
  1. Run the integration test binary, built with `go test -c -tags integration`.
     All five builds pass.
  2. Run `ad_hoc/issue-25/smoke/build-stall.handoff.sh` again for comparison, to show the tar upload path still stalls on the same host.
  3. Run `agentcon run` with `build` set on the Claude example, and confirm it builds and starts.
