# Bouncer filters

A filter is a TypeScript (or JavaScript) module that default-exports `defineFilter({...})`.
It runs inside the sidecar, in an embedded JS VM.
`await` on `next()`, `ask()`, and body reads blocks that filter, not the daemon.

The type surface is [`internal/bouncer/types/bouncer.d.ts`](../internal/bouncer/types/bouncer.d.ts).
A concrete GitHub overlay that uses filters is [docs/bouncer/github](bouncer/github).

## Where files live

Put sources under `ts/` in an `agentcon.d` overlay directory.

```text
~/.config/agentcon.d/
  agents.yaml
  bouncers.yaml
  contexts.yaml
  ts/
    filters/
      git-protect-branches.ts
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
`bouncer.d.ts` is editor types in this repository.
It is not copied into the overlay.

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

## Starting point

Copy [docs/bouncer/github](bouncer/github) into `~/.config/agentcon.d` as described in [bouncer.md](bouncer.md#github-starting-point).
That overlay attaches `git-protect-branches.ts`, `github-graphql-guard.ts`, and `require-approval-merge.ts`.
Edit `github_repo`, Bitwarden identity, and the GraphQL `deny` list for your repo.
