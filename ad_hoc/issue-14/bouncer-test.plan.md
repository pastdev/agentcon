# Plan: Test bouncer policy with `agentcon bouncer test` (issue 14)

Issue: https://github.com/pastdev/agentcon/issues/14

## Goal

Users can test their own bouncer policy with `agentcon bouncer test`.
The bouncer examples live under `docs/bouncer/` as documentation, and `go test ./...` runs their tests through the same code as the command.
Spec cases are isolated, and ordered steps inside a case share state.

## Non-goals

Do not add a way to select single spec files or cases, such as `--run`.
Do not add an output format other than TAP.
Do not make a missing tests directory tolerable.
`relativeDir` errors on it, and that stays.
Do not change how `-d` and `-c` compute overlay directories.
Today the default overlay directories stay in that list when `-d` is given, so their `ts/` trees are collected too.
That is #29, which waits on pastdev/configloader#16.
Do not build the docs images in CI.

## Decisions

### Spec format (`internal/bouncer/testrunner`)

```go
type Spec struct {
	Filter           string           `yaml:"filter"`
	FilterConfig     map[string]any   `yaml:"filter_config"`
	Profile          string           `yaml:"profile"`
	GitLabProjectIDs map[string]int64 `yaml:"gitlab_project_ids"`
	Cases            []Case           `yaml:"cases"`
}

type Case struct {
	Name         string         `yaml:"name"`
	FilterConfig map[string]any `yaml:"filter_config"`
	Profile      string         `yaml:"profile"`
	Steps        []Step         `yaml:"steps"`
}

type Step struct {
	Name     string       `yaml:"name"`
	Request  *HTTPRequest `yaml:"request"`
	SSH      *SSHRequest  `yaml:"ssh"`
	Upstream *Upstream    `yaml:"upstream"`
	Approve  *bool        `yaml:"approve"`
	// Expect* fields move here from today's Case unchanged.
	ExpectCredential *bool `yaml:"expect_credential"`
}
```

`expect_credential` was added in commit 3, so specs can test that leftover paths under `unmatched: tunnel` do not carry the service's credential.
The fake upstream records whether the request reached it with `SkipCredential` set.
A step has the credential when the request reached the upstream, `SkipCredential` is not set, and its service names a credential.

- Each case gets a fresh KV store and a freshly loaded filter or compiled policy.
- Steps run in order and share the case's KV store, filter instance and approver.
- A case's `filter_config` replaces the file's when it is set, including `{}`.
  It does not merge.
- A case's `profile` replaces the file's when it is not empty.
- `gitlab_project_ids` is file-level only.
- A step without `name` is named by its 1-based index as a string, such as `"2"`.
- Decoding stays strict, so an old-format spec fails to load instead of being ignored.

Results gain the failing step:

```go
type Result struct {
	Name      string
	Passed    bool
	Step      int    // 1-based index of the failing step, 0 when passed or not step-specific
	StepName  string
	Message   string
	FilterLog string
}
```

`FilterLog` is the captured filter console output of the failing case.
It is no longer folded into `Message`.

### Spec kinds and the filter convention

`RunFile(path string, opts Options) ([]Result, error)` with:

```go
type Options struct {
	// TestsDir is the directory the spec was found under. Its parent is
	// the root that conventional filter paths resolve against.
	TestsDir string
	// Policy is the daemon policy file bouncer specs compile.
	Policy string
}
```

A spec's kind is decided in this order:

1. `filter:` set: a filter spec.
   The path is relative to the spec file, as today.
2. `TestsDir` set and the conventional filter exists: a filter spec.
   The convention takes the spec's path relative to `TestsDir`, drops `.test.yaml` or `.test.yml`, and adds `.ts`, under the parent of `TestsDir`.
   `tests/ts/filters/x.test.yaml` tests `ts/filters/x.ts`.
3. Otherwise: a bouncer spec.
   It compiles `Policy`, and every case must resolve a non-empty profile.
   An empty `Policy` is an error that names the spec.

`config:` is removed in commit 4, once nothing uses it.
Until then it still names a daemon policy file relative to the spec.

### `tests` on a bouncer (`pkg/config`)

```go
// BouncerSpec is a bouncer as agentcon config holds it: the daemon policy
// plus settings that never reach the daemon.
type BouncerSpec struct {
	bouncercfg.Config `yaml:",inline"`
	// Tests is the directory of *.test.yaml specs for this bouncer.
	Tests string `json:"tests,omitempty" yaml:"tests,omitempty"`
}
```

`Config.Bouncers` becomes `map[string]*BouncerSpec`.
`MaterializeBouncer` marshals only the embedded `bouncercfg.Config`, so `tests` never reaches the daemon policy.
No strip step exists.

The factory method:

```go
// BouncerTests returns the test suite for a context's bouncer.
func (c *Config) BouncerTests(context string) (bouncertest.Suite, error)
```

- It reuses `MaterializeBouncer` with an empty `AgentSpec`, so the policy under test is the one `agentcon run` ships, without agent tunnel hosts.
- An unknown context, a context without a bouncer, and a bouncer with an empty `tests` are errors.

### Service (`pkg/bouncertest`, new)

```go
type Suite struct {
	Bouncer    string
	PolicyYAML []byte
	TSFiles    map[string]string
	TestsDir   string
}

type Report struct {
	Bouncer string
	Specs   []SpecReport
}

type SpecReport struct {
	Path    string // relative to the parent of TestsDir, such as tests/bouncers.test.yaml
	Results []testrunner.Result
	Err     error  // the spec failed to load or run
}

func Run(suite Suite, dir string) (Report, error)
```

- `Run` writes the layout into `dir` with `bouncercfg.WriteLayout`, finds specs under `TestsDir` with `testrunner.Find`, and runs each with `Options{TestsDir, Policy: dir/config.yaml}`.
- The caller owns `dir`.
  The docs test passes `t.TempDir()`.
  The command uses `os.MkdirTemp` and a deferred `os.RemoveAll`.
- A spec that fails to load is recorded in its `SpecReport` and the run continues.
  `Run` returns an error only when it cannot write the layout or walk `TestsDir`.
- It does not import `pkg/config`.

### Command (`cmd/agentcon/bouncer/test.go`)

`agentcon bouncer test`

- It tests the current context's bouncer, like `check` checks it.
  The context comes from `--context`, then `default_context`, through the group's shared setup, with no exemption.
  `--file` is not supported, because a daemon policy has no `tests`.
- It loads the config with the shared loader, so `-d` and `-c` work.
- It calls `BouncerTests(context)`, then `bouncertest.Run`, then prints TAP.
- It returns an error naming the failure count when any case fails or any spec fails to load, so the exit code is nonzero.
- The group's `Long` help lists the command.
- Failures do not print usage.
- The group's shared setup reports an unknown `--context` by name, instead of the generic "bouncer policy not set" error.

TAP 14 output is formatted in the command package (`tap.go`), with its own unit tests:

```
TAP version 14
# Subtest: tests/bouncers.test.yaml
    1..2
    ok 1 - tag push asks
    not ok 2 - leftover api paths do not get the token
      ---
      step: 2
      step_name: repos endpoint
      message: expected deny, got allow
      filter_log: |
        info github-graphql-guard: no denied field
      ...
not ok 1 - tests/bouncers.test.yaml
1..1
```

- One top-level test per spec file, named by its path relative to the parent of the tests directory.
- A spec that fails to load is a top-level `not ok` with `message` in its diagnostic block and no subtest.
- Diagnostic keys are emitted only when set.
- The YAML block is produced with `yaml.v3` so that values are quoted correctly.

### Examples as documentation

Layout of each example:

```
docs/bouncer/<name>/
  bouncers.yaml          # sets bouncers.<name>.tests: '{{ relativeDir "tests" }}'
  ts/
    tsconfig.json        # include: ["**/*.ts"]
    bouncer.d.ts         # copy of internal/bouncer/types/bouncer.d.ts
    filters/*.ts
  tests/
    bouncers.test.yaml
    ts/filters/*.test.yaml
```

- The header of each `bouncers.yaml` says to copy the whole directory, or to delete the `tests:` line.
- `tsconfig.json` keeps today's compiler options (`ES2020`, `ESNext`, `Bundler`, `strict`, `noEmit`).
- `docs/bouncer/github`:
  - Filter specs for its three filters, under `tests/ts/filters/`.
  - `tests/bouncers.test.yaml` covers each claim the GitHub section of `docs/bouncer.md` makes, including tag pushes asking, GraphQL `mergePullRequest` asking before the `/graphql` allow, protected branch pushes being denied, and leftover paths not receiving the PAT.
- `docs/bouncer/reference` replaces `internal/bouncer/examples`.
  - The body of `config.yaml` moves under `bouncers.reference` in `bouncers.yaml`.
  - `listen` and `ssh_listen` are dropped.
  - It binds `contexts.reference: {bouncer: reference}`, a name that does not clash with the GitHub example's `git`.
    Like that example, it sets only `bouncer`.
    The header says to add `root` and `agent` to run with it.
  - Filter paths change from `filters/x.ts` to `ts/filters/x.ts`.
  - Profiles, prompts, every credential source and the comments stay.
  - `config.test.yaml` and `locked-down.test.yaml` merge into `tests/bouncers.test.yaml`, with per-case `profile:` for the `locked-down` cases.
  - The eleven filter specs move to `tests/ts/filters/` and drop `filter:`.
- `internal/bouncer/examples` and `internal/bouncer/testrunner/examples_test.go` are removed.

### Docs test (`pkg/config/docs_test.go`)

- For each directory matching `../../docs/bouncer/*`, it loads that directory alone with a `DirSource` and the same template unmarshal the loader uses, and sets `OverlayDirs` to it.
- It calls `BouncerTests` for each context in the example that has a bouncer, which are `git` and `reference`, and requires at least one.
- It runs each suite with `bouncertest.Run(suite, t.TempDir())`, with one `t.Run` per spec and per case.
- It asserts that each example's `ts/bouncer.d.ts` equals `types.BouncerDTS`.

### Documentation

- `docs/bouncer-filters.md`:
  - A section on testing: the `tests` field, the layout, the spec format, the filter convention, and `agentcon bouncer test` with an example of its TAP output.
  - The editor types section says to copy `bouncer.d.ts` and a `tsconfig.json` into `ts/`, as the examples do.
  - It links both examples.
- `docs/bouncer.md` lists `agentcon bouncer test` where it lists `check`.

## Tests

- `internal/bouncer/testrunner` (testdata under `testdata/`):
  - Cases are isolated.
    A KV write in one case is not seen by the next.
  - Steps share state.
    A KV write in one step is seen by the next.
  - A case's `filter_config` replaces the file's, and `{}` clears it.
  - A case's `profile` replaces the file's.
  - The filter convention resolves `tests/ts/filters/x.test.yaml` to `ts/filters/x.ts`, for both `.test.yaml` and `.test.yml`.
  - `filter:` overrides the convention.
  - A bouncer spec without `Policy` is an error, as is a case with no profile.
  - A failing step reports its index, name and filter log.
  - An old-format spec, with `request` directly on a case, fails to load.
- `pkg/bouncertest`:
  - It writes the layout into the given directory and runs every spec under `TestsDir`.
  - A spec that fails to load is recorded and the others still run.
- `pkg/config`:
  - `tests` decodes into `BouncerSpec` and does not appear in the materialized policy.
  - `BouncerTests` errors on an unknown context, a context without a bouncer, and a bouncer without tests.
  - Existing `Bouncers:` fixtures move to `BouncerSpec`.
- `cmd/agentcon/bouncer`: TAP output for passing specs, a failing step with a filter log, and a spec that fails to load.
- The docs test, above.

## Commits

1. Plan.
2. Spec format: isolated cases, ordered steps, per-case overrides and step results.
   The specs under `internal/bouncer/examples` are converted in place and keep passing through `examples_test.go`.
3. `bouncers.<name>.tests`, `BouncerSpec`, `RunFile` options and the filter convention, `pkg/bouncertest`, the command with TAP output, and the docs test.
   `docs/bouncer/github` gets its `tests` field, `tests/` tree, `tsconfig.json`, `bouncer.d.ts` and header as the first user.
4. `docs/bouncer/reference` from `internal/bouncer/examples`, the `bouncer.d.ts` check in the docs test, and removal of `config:`, `internal/bouncer/examples` and `examples_test.go`.
5. Documentation.

## Verification

- `go build ./...`, `go test -race ./...`, and `golangci-lint run ./...` pass.
  `go vet` passes for darwin and windows.
- `go run ./cmd/agentcon bouncer test -d docs/bouncer/github --context git` and `-d docs/bouncer/reference --context reference` print TAP with every test `ok` and exit 0.
- With one expectation in a scratch copy of an example flipped, the command prints `not ok` with the step, message and filter log, and exits nonzero.
- `go run ./cmd/agentcon bouncer test -d docs/bouncer/github --context nope` fails, naming the unknown context.
- No handoff is needed.
  The command compiles policy and runs filters offline, and resolves no credentials.
