# Bouncer filters

A filter is a TypeScript (or JavaScript) module that default-exports `defineFilter({...})`.
It runs inside the sidecar, in an embedded JS VM.
`await` on `next()`, `ask()`, `requestClaim()`, and body reads blocks that filter, not the daemon.

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
With `-d` or `-c`, only those directories are overlays, the same as for the YAML.
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

### Session claims

A claim is a trusted `(type, value)` fact about a session, such as `repository = gitlab.example.com/group/project`.
Claims say what the session is about.
What may be done with that stays in filter policy.
agentcon never interprets claim types or values.

`req.session.claims` maps each claim type to its values.

```typescript
const repos = req.session?.claims.repository ?? [];
if (repos.includes(`${req.host}/${project}`)) return next(req);
```

It is a deeply frozen copy taken when the request arrived.
Changing it has no effect on the session.
The shared anonymous session always has `{}`.

Claims are added in exactly two ways.

- The host seeds them when it creates the session through the [control API](bouncer.md#management-api).
- An operator answers a filter's `requestClaim()` with "add claim for session".

Nothing removes or replaces a claim.
Claims end with their session, and they survive a daemon restart along with it.

`requestClaim(type, value, prompt, { timeout? })` asks the operator to add a claim.

```typescript
if (await requestClaim("repository", repo, `Let the agent create issues in ${repo}?`)) return next(req);
return deny(`${repo} is not one of this session's repositories`);
```

- It resolves `true` without asking when the session already holds the claim.
- The operator sees the prompt, the requested claim, and the session's current claims grouped by type.
- "Add claim for session" adds the claim and resolves `true`.
  Later requests see it in `req.session.claims`.
- "Allow once" resolves `true` and adds nothing.
- Deny, decline, or no answer before the timeout resolves `false`.
  A denial is not remembered, so the next request asks again.
- Identical concurrent requests in a session share one prompt.
- On the shared anonymous session, "add claim for session" counts as once.

Claim rules are exact.

- A type matches `^[a-z][a-z0-9_]*$` and has at most 64 characters.
- A value is non-empty valid UTF-8 without control characters, at most 1024 bytes.
- A session holds at most 32 types and 256 values per type.
- Values are a set, so adding one twice is a no-op.
- Nothing is case-folded, trimmed, or cleaned.
  Canonicalize values the same way in the host and in filters.

`requestClaim()` throws, without asking, when the type or value breaks these rules or the session is at a limit.
Claims still waiting on an answer count toward the limits, so a grant the operator approves always fits.
An uncaught throw denies the request.

[gitlab-issue-scope.ts](bouncer/reference/ts/filters/gitlab-issue-scope.ts) allows GitLab issue creation in the session's repositories and asks for any other.
It denies GraphQL mutations not listed in its `allowMutations` config, since a mutation can create an issue in any project.

### Subrequests

`subrequest(init)` sends an HTTP request through Bouncer as the current session.
A push filter can use it to check the provider's branch rules before the push goes upstream.

```typescript
import { defineFilter, deny, subrequest } from "bouncer";

export default defineFilter({
  async onRequest(req, next) {
    if (req.git?.service !== "receive-pack") return next(req);
    for (const u of await req.git.refUpdates()) {
      const branch = u.ref.replace(/^refs\/heads\//, "");
      const path = branch.split("/").map(encodeURIComponent).join("/");
      const r = await subrequest({ url: `https://api.github.com/repos/${req.git.repo}/rules/branches/${path}` });
      if (r.denied || r.status !== 200) return deny(`cannot check the rules for ${branch}`);
      if ((await r.body.json()).length > 0) return deny(`${branch} has rules`);
    }
    return next(req);
  },
});
```

A subrequest is just another request from the session.
It has exactly the session's authority, no more.

- It runs the full chain of the HTTP service its host matches in the session's profile.
  That is profile filters, service filters, rules, rule filters, and credential injection.
  The service's rules must allow it, as they would an agent request.
- A host with no `http` service follows the profile's `unmatched`, `tunnel`, and `allow_private` settings, with no credential.
- `ask()` rules and filter prompts work as usual.
  The prompt adds an `origin` line naming the filter and the request that caused the subrequest.
- It works from `onRequest`, `onResponse`, and `onSSH`.
  An SSH push filter reaches the provider's API through the profile's HTTP service for it.
  At module top level it throws.
- It sees the session's claims as they are now, including claims added earlier in the same request.

`init` takes `url`, and optionally `method` (default `GET`), `headers`, `body`, `redirect`, and `timeout`.
An object `body` is JSON-encoded, with `Content-Type: application/json` unless you set one.

The result has the same shape as the response from `next()`, plus `url`, the final URL.
It resolves for every response, including upstream errors and Bouncer denials.
`denied` is `{by, reason}` when Bouncer's chain refused the subrequest, and `null` otherwise.
It rejects only when there is no response at all.
That covers an invalid URL or method, nesting too deep, too many redirects, a connection failure, a timeout, or a cancelled parent request.
An uncaught rejection denies the request being filtered, so a failed lookup fails closed.

Redirects are followed by default, up to 5.
Each hop goes through the chain again, with the credential of the service it reaches.
A hop to another host drops the `Authorization`, `Private-Token`, and `Cookie` headers the filter set.
`redirect: "manual"` returns the 3xx instead.

There is no default timeout.
A subrequest ends with its parent request, for example when the agent's git client gives up.
`timeout` (`"10s"` or seconds) bounds the whole subrequest, redirects and prompts included.
Time spent waiting does not count toward the filter's CPU budget.

Body reads keep the 16 MiB limit.
Bouncer closes a body the filter did not read when the filter returns.

A filter on the target service sees `req.subrequest`, a frozen `{filter, depth, parent}`.
It is `null` for a request from the agent, and the agent cannot set it.
Use it when a filter should treat a filter's own lookup differently.

```typescript
if (req.subrequest?.filter === "github-branch-rules") return next(req);
```

Subrequests nest at most 4 deep.
A filter that runs on the service it calls, and calls it on every request, would otherwise loop.
Past the limit, `subrequest()` rejects with `subrequest: depth 5 exceeds limit 4`.

Values from the request are the agent's choice.
Encode them before you put them in a URL.
A branch name can contain `/`, `#`, or `%`.
[github-branch-rules.ts](bouncer/reference/ts/filters/github-branch-rules.ts) encodes each path segment.

A service without an `inject` spec only replaces its credential's placeholder, which the agent's environment carries.
A filter sends the placeholder itself with `placeholder(name)`.

```typescript
await subrequest({
  url: "https://gitlab.example.com/api/v4/projects/42/protected_branches",
  headers: { "Private-Token": placeholder("gitlab") },
});
```

`placeholder()` throws for an unknown credential or an `internal: true` one.

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
A credential with [`internal: true`](bouncer.md#internal) is never readable this way.

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
A case's `claims` seeds its session, validated like the control API.
Its steps share them, so a claim added in one step is held in the next.
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
- `claim_answer`: the answer to every `requestClaim()` in the step that the session does not already satisfy.
  It is `session`, `once`, `deny`, or `timeout`.
  Unset means deny.
- `subrequests`: fixtures that answer the step's `subrequest()` calls.

A step checks any of these.

- `expect`: `allow` or `deny`.
- `expect_reason`: text the deny reason contains.
- `expect_status`: the response status.
- `expect_body_contains` and `expect_body_excludes`: text the response body must or must not contain.
- `expect_asked`: whether an `ask()` happened.
- `expect_claim_requested`: whether a `requestClaim()` asked the operator, or the `{type, value}` it asked for.
- `expect_claims`: the session's full claim set after the step.
  `{}` asserts no claims.
- `expect_upstream_header`: headers the upstream received.
- `expect_credential`: whether the request reached the upstream with its service's credential.
  Leftover paths under `unmatched: tunnel` do not carry it.

### Subrequest fixtures

A step's `subrequests` answer every `subrequest()` its filters make.
Nothing reaches the network.

```yaml
steps:
  - request:
      method: POST
      url: https://github.com/myorg/myrepo.git/git-receive-pack
      git_push: [{ref: refs/heads/main}]
    subrequests:
      - url: https://api.github.com/repos/myorg/myrepo/rules/branches/main
        body: '[{"type": "update"}]'
        expect_header: {Accept: application/vnd.github+json}
        expect_credential: true
      - url: https://api.github.com/repos/myorg/myrepo/rules/branches/other
        error: connection refused
    expect: deny
```

- A fixture matches by `method` (default `GET`) and the exact `url`, query included.
  A default port and a fragment are ignored.
  It answers every call that matches.
- It answers with `status` (default 200), `headers`, and `body`.
  `error` makes the subrequest reject with that message instead.
- `expect_header` checks headers the fixture received, after the chain ran.
- `expect_credential` checks whether the subrequest arrived with its service's credential.
  It needs a bouncer spec.
- A subrequest without a fixture fails the step, and so does a fixture nothing called.
- In a bouncer spec, a subrequest runs through the profile's real chain before it reaches its fixture.
  A tunneled host is answered by a fixture too.
  In a filter spec there is no chain, so a subrequest goes straight to its fixture.
- A redirect is a fixture whose `Location` another fixture matches.

## Starting point

Copy [docs/bouncer/github](bouncer/github) into `~/.config/agentcon.d` as described in [bouncer.md](bouncer.md#github-starting-point).
That overlay attaches `git-protect-branches.ts`, `github-graphql-guard.ts`, and `require-approval-merge.ts`.
Edit `github_repo`, Bitwarden identity, and the GraphQL `deny` list for your repo.
Update its tests to match, then run `agentcon bouncer test --context git`.

[docs/bouncer/reference](bouncer/reference) binds a `reference` context and has tests for every example filter.
Copy the filters and specs you want from it.
