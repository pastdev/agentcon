# Credentials limited to filter subrequests

Issue: https://github.com/pastdev/agentcon/issues/44 (Let credentials be limited to filter subrequests)

## Goal

A filter can look up data that the agent's own credential must not read, such as Actions secrets or classic branch protection.
It does so with a credential that only subrequests may use.
The agent cannot name that credential, by accident or on purpose.

## Decisions

- Each credential has a required `allow` list of request kinds: `agent`, `subrequest`, `internal`.
  `internal` stands alone and replaces `internal: true`.
- A service lists `credentials` and names its injected one in `inject.credential`.
  The singular `credential:` is removed.
- A service's `lookup_credential` names the credential Bouncer itself uses when a matcher needs data from the service.
  Today only the GitLab project resolver uses it, to map `gitlab_project.path` to a numeric ID.
  It is a typed field, not an options map, so strict decoding catches a misspelled key.
  It must allow `agent`, because agent requests trigger lookups, so a lookup never uses an elevated credential.
  It is on the service rather than top level, so a profile never causes a lookup with a credential its services do not list.
- `inject.git` uses `inject.credential`.
  A `credential` key under `inject.git` fails the policy load.
- `placeholder(name)` returns a one-time string per call, valid for that filter run only.
  It is replaced in a subrequest's headers, query, and body.
- In a subrequest, only one-time placeholders and `inject` attach a credential.
  The static `bouncer-placeholder-<name>` passes through unchanged, so agent text never chooses a subrequest's credential.
  A filter that copies the agent's `Authorization` into a subrequest gets `inject`, or nothing on a service without `inject`.
- Agent requests keep the static placeholder, replaced only in headers, as today.
- `placeholder(name)` throws for an unknown credential and for one whose `allow` lacks `subrequest`.
  Failing at the call is clearer than a string that is never replaced.
- An elevated credential is one whose `allow` lacks `agent`, such as `allow: [subrequest]`.
- A rule's `subrequest` block makes it match only subrequests.
  `subrequest.filters` limits it to subrequests from the filter placements with those ids.
  `subrequest.credentials` lists the elevated credentials a matching subrequest may use on that route.
  An elevated credential is usable nowhere else, so the policy file shows every route it can reach.
  This guards against filter mistakes, such as naming the wrong credential or building a URL from unchecked agent data.
- Credentials that allow both `agent` and `subrequest` stay usable on any route the service allows, with no rule listing.
- A filter placement (`FilterRef`) has an optional policy-assigned `id`.
  `subrequest.filters` names ids, never filter names.
  A filter's name comes from its file's basename or from `defineFilter({name})`, so distinct filters, or one file placed twice, can share it.
- `credential(name)` and `chain.Env.Credential` are removed.
- Old keys fail the load with a message naming the replacement.
  There is no compatibility shim.

## Config

```yaml
credentials:
  github:       {token: ..., allow: [agent, subrequest], export_env: [GH_TOKEN]}
  github-audit: {token: ..., allow: [subrequest]}
  signing:      {private_key: ..., password: ..., allow: [internal]}

bouncers:
  - profiles:
      - http:
          - name: github
            hosts: [github.com, api.github.com]
            credentials: [github, github-audit]
            inject:
              bearer: true
              credential: github
              git: {basic: {username: x-access-token}}
            rules:
              - action: allow                     # filter's lookup, elevated token
                methods: [GET]
                github_repo: [myorg/myrepo]
                github_subpaths: ["actions/secrets"]
                subrequest:
                  filters: [github-ci-safety]     # optional: only these filters
                  credentials: [github-audit]     # elevated creds usable on this route
              - action: allow                     # agent's own access, ordinary token
                methods: [GET]
                github_repo: [myorg/myrepo]
                github_subpaths: ["actions/secrets"]
              - action: allow                     # pushes, checked by the filter
                git: {}
                github_repo: [myorg/myrepo]
                filters:
                  - path: ts/filters/github-ci-safety.ts
                    id: github-ci-safety          # policy-assigned, unique
```

When the agent and a filter use the same endpoint with different tokens, the subrequest rule comes first.
The agent's request skips it and falls through to its own rule.

A GitLab service whose rules match projects by path:

```yaml
          - name: gitlab
            hosts: [gitlab.example.com]
            credentials: [gitlab, gitlab-audit]
            inject: {header: PRIVATE-TOKEN, credential: gitlab}
            lookup_credential: gitlab     # used only for project path to ID lookups
            rules:
              - action: allow
                methods: [GET]
                gitlab_project: {path: myorg/myrepo, subpaths: [issues]}
```

### Load checks

Each check fails with a message in the existing `credential %q: ...` or `http %q: ...` form.

- `allow` missing or empty.
- `allow` has an unknown value, or `internal` with another value.
- `internal: true` is set (`use allow: [internal]`).
- `export_env` without `agent`.
- An SSH service's credential without `agent`.
- A signer key's credential that is not `allow: [internal]`.
- `http` service `credential:` is set (`use credentials and inject.credential`).
- A `credentials` entry that is unknown or `internal`.
- `inject` without `inject.credential`, or `inject.credential` not in `credentials`.
- `inject.git.credential` is set.
- A rule `subrequest` block with neither `filters` nor `credentials`, or an empty list in either.
- A filter `id` used by more than one placement anywhere in the policy.
- A `subrequest.filters` entry that is not the `id` of any placement.
- A `subrequest` block on an `ssh` rule.
- A `subrequest.credentials` entry that is not in the service's `credentials`, or that allows `agent`.
- `inject.credential` that is elevated.
- `lookup_credential` that is not in the service's `credentials`, or that is elevated.
- A rule using `gitlab_project.path` without `id` on a service with no `lookup_credential` (`http %q: gitlab_project path lookups need lookup_credential`).

## Forwarder

`forwarder` in `internal/bouncer/proxy/forward.go` decides per request which credentials it may use.

1. The request kind is `subrequest` when `req.Subrequest != nil`, else `agent`.
2. The usable set is every credential in `svc.Config.Credentials` whose `allow` has that kind.
   For a subrequest, an elevated credential is usable only when it is in `req.RuleCredentials`.
3. For an agent request, replace the static placeholder of each usable credential in the placeholder headers, as `Inject` does today.
4. For a subrequest, replace each one-time placeholder in `req.Placeholders` whose credential is usable, in headers, query, and body.
   Body replacement escapes the secret for `application/json` and `application/x-www-form-urlencoded`, and is raw otherwise.
   The body length is recomputed.
5. Apply `inject` when its credential is usable and the header it writes does not already hold a usable placeholder.
6. With `SkipCredential`, strip usable placeholders from headers and query instead, as `stripPlaceholder` does today.
7. The plain-HTTP and `allow_upgrade` checks apply when any credential is used.
8. Scrub every secret placed in the query from the response headers, as `scrubSecret` does now for query inject.
9. Record the names of the credentials used on the response for the audit entry.

`creds.Store.Get` takes the request kind and refuses a credential whose `allow` lacks it.
`ErrInternal` becomes a general refusal that names the kind.

## One-time placeholders

`chain.Request` gains `Placeholders map[string]string`, mapping each issued string to a credential name.
`jsfilter` keeps a map per filter run (one `onRequest`, `onResponse`, or `onSSH` call).
`placeholder()` adds `bouncer-placeholder-<name>-<16 hex chars from crypto/rand>` to it.
`subrequest()` passes the run's map to the router, which sets it on every hop's `chain.Request`.
A nested subrequest's filters have their own runs and maps.
The map is dropped when the run returns, so a string kept in a closure or KV matches nothing later.

`chain.Env.Placeholder` becomes `func(name string) error`, a check only, and the binding builds the string.

## Rules

`config.Rule` gains `Subrequest *SubrequestMatch` with `Filters []string` and `Credentials []string`.
`config.FilterRef` gains `ID string`, passed through `policy` to the `jsfilter.Filter` for that placement.
`chain.Subrequest` gains `ID`, set by the router from the calling placement, and `req.subrequest.id` exposes it to filters (`null` when the placement has none).
`filter` stays the display name.
`chain` rule matching skips a rule with `Subrequest` when `req.Subrequest` is nil, or when `Filters` is set and does not list `req.Subrequest.ID`.
The TypeScript `name` plays no part in matching.
A matched rule sets `req.RuleCredentials` from `Subrequest.Credentials`, the same way it sets `SkipCredential`.
Each redirect hop is matched again, so a same-host redirect to another route loses the elevated credential.
A rule's `Subrequest` check runs before its other matchers, so an agent request never starts a GitLab lookup for a subrequest-only rule.

## GitLab project resolver

The resolver moves from `internal/bouncer/daemon/daemon.go` (`resolveGitLabProject`) into a new package, `internal/bouncer/gitlab`.
It takes a transport, a credential getter, and the service lookup, and keeps its per service, host, and project cache.
The daemon only wires it into `chain.Env.Resolver`.

The lookup sends `GET https://<host>/api/v4/projects/<path>` with `Authorization: Bearer <lookup_credential>`.
GitLab accepts Bearer for personal, project, and group access tokens and for OAuth tokens, while `PRIVATE-TOKEN` does not take OAuth tokens.
It no longer uses `inject`, and the bearer fallback for a service without `inject` is gone.
It reads the secret with request kind `agent`, so the store refuses an elevated credential even if the load check were bypassed.

## Audit and tests

- `audit.Entry` gains `Credentials []string`.
  The summary shows `[subrequest from <id or filter> as <cred>,...]`, and `[as <cred>]` for agent requests.
- `audit.Subrequest` gains `ID`.
- `expect_credential` (bool) becomes `expect_credentials` (list compared as a set) in steps and subrequest fixtures.
  `[]` means unauthenticated, and an omitted key skips the check.
  The test runner's fake terminal applies the same usable-set logic, so it reports the same names as the forwarder.

## Removal

- `credential()` binding, `chain.Env.Credential`, the daemon's wiring, and `bouncer.d.ts` entries.
- `Credential.Internal`, `HTTPService.Credential`.
- `Daemon.resolveGitLabProject`, replaced by `internal/bouncer/gitlab`.

## Docs and examples

- `docs/bouncer.md`: credential `allow`, service `credentials`, `inject.credential`, `lookup_credential`, subrequest rules.
- `docs/bouncer-filters.md`: one-time placeholders, the static placeholder not working in subrequests, removal of `credential()`, and the responsibility and latency notes from the issue.
- Migrate every config under `docs/bouncer/**` and test data.
- Add a reference example: a `github-ci-safety` filter that denies a push when the repo has Actions secrets, using `github-audit`, with tests.

## Tests

- Config: every load check above, one case each.
- Forwarder: agent vs subrequest usable sets, static placeholder ignored in subrequests, one-time placeholder in header, query, JSON body, and form body, inject precedence, `SkipCredential` stripping, query scrubbing, credentials recorded.
- jsfilter: `placeholder()` uniqueness, throws for non-`subrequest` credentials, strings expire after the run.
- Rules: `subrequest` matches only subrequests, only the listed ids when set, and lets agent requests fall through.
  A filter whose basename or `defineFilter({name})` equals a listed id, but whose placement has a different or no id, does not match.
- Config: duplicate and unknown ids fail the load.
- Config: `lookup_credential` not listed, elevated, or missing for a path lookup fails the load.
- GitLab resolver: an agent request with a numeric project ID, on a service whose subrequest rule lists `gitlab-audit`, sends only the `lookup_credential` token.
  An agent request never calls the resolver for a subrequest-only rule.
  The existing `daemon_test.go` resolver test moves to the new package.
- Elevated credentials: a placeholder is replaced on a rule listing the credential, and left as text on another allowed route of the same service and on a redirect hop to one.
- Store: `Get` refuses by kind.
- Test runner: `expect_credentials` in steps and fixtures.

## Smoke

A handoff that runs the bouncer against real GitHub with a fine-grained `github` token and a separate `github-audit` token.

1. An agent `GET .../actions/secrets` with `github-audit`'s static placeholder is denied by rules or sent unauthenticated (expect 401/404).
2. A push to a repo with no Actions secrets passes the `github-ci-safety` filter.
3. The audit log shows `as github-audit` on the subrequest and never on an agent request.
