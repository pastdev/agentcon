# Bouncer filters

A filter is a TypeScript (or JavaScript) module that default-exports `defineFilter({...})`.
It runs inside the sidecar, in an embedded JS VM.
`await` on `next()`, `ask()`, and body reads blocks that filter, not the daemon.

The type surface is [`internal/bouncer/types/bouncer.d.ts`](../internal/bouncer/types/bouncer.d.ts).
A concrete GitHub overlay that uses filters is [docs/bouncer/github](bouncer/github).
[docs/bouncer/reference](bouncer/reference) shows every policy feature and every example filter, with tests.

## Where files live

Put sources under `ts/` in an `agentcon.d` overlay directory.

```text
~/.config/agentcon.d/
  bouncers.yaml
  claude.yaml
  contexts.yaml
  ts/
    tsconfig.json
    bouncer.d.ts
    filters/
      git-protect-branches.ts
  tests/
    bouncers.test.yaml
    ts/
      filters/
        git-protect-branches.test.yaml
```

YAML paths are relative to that overlay, starting with `ts/`.
`run` merges every overlay `ts/` tree (later directory wins) and copies the result into the sidecar.
`agentcon bouncer check` compiles the merged tree.

Relative imports work.
Packages under `ts/node_modules/` work.
esbuild bundles the entry point before goja runs it.

## Attach a filter

Filters can hang on a profile, a service, or a rule.

- Profile `filters` run on every intercepted request in that profile, before HTTP and SSH service filters.
- Service `filters` run on every request to that service, before rules.
- Rule `filters` run only after that rule matches with `allow`, or after an approved `ask`.
  They do not run on `deny`.

```yaml
filters:
  - path: ts/filters/redact-response.ts
http:
  - name: github
    hosts: [github.com, api.github.com]
    filters:
      - path: ts/filters/read-only.ts
    rules:
      - action: ask
        git: {service: receive-pack, refs: [refs/tags/*]}
        github_repo: [your-org/your-repo]
        prompt: "Push a git tag?"
      - action: allow
        git: {}
        github_repo: [your-org/your-repo]
        filters:
          - path: ts/filters/git-protect-branches.ts
            config: {branches: [main, master]}
```

`path` is required.
`config` is the object the filter sees as `ctx.config`.
`timeout` bounds CPU time for one invocation.
Default is 2s.
Time spent in `next()`, `ask()`, or body reads does not count.

## Write a filter

Import from the virtual module `bouncer`.
That module is not on disk at runtime.
For editor types, copy `bouncer.d.ts` and a `tsconfig.json` into `ts/`, as the examples do.
`bouncer.d.ts` declares the `bouncer` module, so the `tsconfig.json` only needs `"include": ["**/*.ts"]`.
Both files are copied into the sidecar with the rest of `ts/`, and neither is bundled.

```typescript
import { defineFilter, deny, ask } from "bouncer";

interface Config {
  branches?: string[];
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    if (req.git?.service === "receive-pack") {
      const blocked = ctx.config.branches ?? ["main"];
      for (const u of await req.git.refUpdates()) {
        const branch = u.ref.replace(/^refs\/heads\//, "");
        if (blocked.includes(branch)) {
          return deny(`push to ${branch} is not allowed`);
        }
      }
    }
    return next(req);
  },
});
```

Export `defineFilter(...)` as `default`.
At least one of `onRequest`, `onResponse`, or `onSSH` must exist.

### Hooks

`onRequest` sees HTTP (and git-over-HTTP).
Call `next(req)` to continue the chain, or return `deny()` / `respond()`.
You may pass a modified `req` to `next`.

`onResponse` sees the HTTP response after the rest of the chain.
Return nothing to keep it.
Return `deny()` or `respond()` to replace it.

`onSSH` sees SSH channel requests (`git`, `exec`, `shell`, `sftp`, `forward`).
`next()` continues.
`deny()` refuses the channel.

### Results

`deny(reason, { status? })` refuses the request.
HTTP clients get `status` (default 403) and the reason as text.

`respond(status, body?, headers?)` answers without contacting upstream.

`ask(prompt, { key?, timeout? })` prompts the human.
It resolves `true` if approved.
It times out to a deny after `prompts.timeout` (default 2m) unless `timeout` is set.
`key` groups decisions so "allow for this session" applies to all of them.
Without `key`, a decision covers only the same prompt for the same request.
Answer from another terminal with `agentcon bouncer approve`, or see [Prompts](bouncer.md#prompts) for every way to answer.

A YAML rule can also use `action: ask`.
Use a filter `ask()` when the decision needs the body, GraphQL fields, or git refs.

### Context and helpers

`ctx.name` is the filter `name` field, or the file name.
`ctx.config` is the YAML `config:` block.

`log(message, fields?)` writes to the bouncer log at `info`, with `fields` as structured fields.
`console.debug`, `console.log`, `console.info`, `console.warn`, and `console.error` log their arguments at `debug`, `info`, `info`, `warn`, and `error`.
Every line names the filter.
[Logging](../README.md#logging) covers the levels.

`credential(name)` returns that credential's secret.
Filters are trusted.
The request object does not include secrets unless a filter puts one in a `respond()` body.

`kv` is persistent storage, namespaced per filter.
Module-level variables are per VM, not shared across requests.
Use `kv` for counters and session state.

```typescript
kv.set("seen", true, { ttl: "1h" });
kv.incr("pushes", { ttl: "1h" });
```

### Request shape

HTTP requests have `method`, `path`, `rawPath`, `url`, `query`, `headers`, and `body`.
`body.peek` / `peekText` look at the front without consuming.
`body.bytes` / `text` / `json` buffer up to 16 MiB.
`body.set` replaces the body.

`req.git` is set for git over HTTP or SSH.
`git.refUpdates()` and `git.push()` parse receive-pack.
Prefer those helpers over peeking at the raw pack.

`req.graphql()` parses a GraphQL body, with fragments expanded.
It is `null` when the request is not GraphQL.
It rejects on parse errors.
Unparseable or hash-only persisted queries should be denied if you cannot vet them.

SSH requests have `req.ssh` (`kind`, `command`, `user`, `host`).

## Check

```bash
agentcon bouncer check
```

That compiles every referenced filter against the merged overlay.
Fix errors before `run`.
The sidecar compiles again at start.

## Test

A bouncer opts into tests with a `tests` directory.

```yaml
bouncers:
  github:
    default_profile: default
    tests: '{{ relativeDir "tests" }}'
```

`relativeDir` resolves against the YAML file that names it.
A missing directory fails the config load, so copy `tests/` with the overlay or delete the `tests:` line.
`tests` is not part of the policy the sidecar loads.

Put specs in `tests/`, mirroring the overlay.
The config loader skips subdirectories, so specs are never loaded as config.
Every `*.test.yaml` and `*.test.yml` under `tests/` runs.

### Run

```bash
agentcon bouncer test
```

That tests the bouncer of the current context, from `--context` or `default_context`.
It runs against the policy `run` would ship, without the agent's tunnel hosts.
The tests resolve no credentials and need no network or Docker.
Output is [TAP 14](https://testanything.org/tap-version-14-specification.html), with one test per spec file and one subtest per case.
A failure names the step and includes the filter log.
The command exits nonzero when any case fails or any spec fails to load.

```text
TAP version 14
# Subtest: tests/bouncers.test.yaml
    1..2
    ok 1 - tag push asks
    not ok 2 - graphql queries carry the PAT
      ---
      step: 1
      step_name: "1"
      message: expected deny, got allow
      ...
not ok 1 - tests/bouncers.test.yaml
1..1
```

### Specs

A spec tests one filter or the whole bouncer.

A filter spec at `tests/ts/filters/x.test.yaml` tests `ts/filters/x.ts`.
Set `filter:` to a path relative to the spec to test another file.
`filter_config` is the filter's `config:` block.

```yaml
filter_config: {branches: [main, master]}
cases:
  - name: feature branch push is allowed
    steps:
      - request:
          method: POST
          url: https://github.com/your-org/your-repo.git/git-receive-pack
          git_push: [{ref: refs/heads/feature}]
        expect: allow
  - name: release globs are protected
    filter_config: {branches: ["release/*"]}
    steps:
      - request:
          method: POST
          url: https://github.com/your-org/your-repo.git/git-receive-pack
          git_push: [{ref: refs/heads/release/2.0}]
        expect: deny
```

Any other spec tests the bouncer, such as `tests/bouncers.test.yaml`.
`profile` names the profile its cases run against.

```yaml
profile: default
cases:
  - name: leftover paths go through without the PAT
    steps:
      - request: {url: "https://api.github.com/repos/other-org/other-repo/pulls"}
        expect: allow
        expect_credential: false
```

Each case is isolated, with fresh `kv` state and a freshly loaded filter or policy.
Steps in a case run in order and share that state.
Use several steps to test a sequence, such as a rate limit.
A case's `filter_config` or `profile` replaces the file's.
`filter_config: {}` runs the filter with no config.
A step without `name` is named by its position, starting at 1.
The first failing step ends its case.

`gitlab_project_ids` maps GitLab project paths to the numeric IDs that `gitlab_project` rules resolve.

A step sends one request.

- `request`: `method` (default `GET`), `url`, `headers`, `body`, and `git_push`, a list of `{ref, type}` ref updates where `type` is `create` or `delete`.
- `ssh`: `host`, `user`, `command`, `subsystem`, `target`, `kind`, and `git_push`.
  `kind` is inferred when empty.
- `upstream`: the fake upstream's `status`, `headers`, and `body`.
  Default is 200 with a short body.
- `approve`: the answer to every `ask()` in the step.
  Unset means asks are denied.

A step checks any of these.

- `expect`: `allow` or `deny`.
- `expect_reason`: text the deny reason contains.
- `expect_status`: the response status.
- `expect_body_contains` and `expect_body_excludes`: text the response body must or must not contain.
- `expect_asked`: whether an `ask()` happened.
- `expect_upstream_header`: headers the upstream received.
- `expect_credential`: whether the request reached the upstream with its service's credential.
  Leftover paths under `unmatched: tunnel` do not carry it.

## Starting point

Copy [docs/bouncer/github](bouncer/github) into `~/.config/agentcon.d` as described in [bouncer.md](bouncer.md#github-starting-point).
That overlay attaches `git-protect-branches.ts`, `github-graphql-guard.ts`, and `require-approval-merge.ts`.
Edit `github_repo`, Bitwarden identity, and the GraphQL `deny` list for your repo.
Update its tests to match, then run `agentcon bouncer test --context git`.

[docs/bouncer/reference](bouncer/reference) binds a `reference` context and has tests for every example filter.
Copy the filters and specs you want from it.
