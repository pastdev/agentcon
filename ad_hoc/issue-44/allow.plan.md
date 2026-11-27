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
  `subrequest.filters` limits it to subrequests from those filters.
  `subrequest.credentials` lists the elevated credentials a matching subrequest may use on that route.
  An elevated credential is usable nowhere else, so the policy file shows every route it can reach.
  This guards against filter mistakes, such as naming the wrong credential or building a URL from unchecked agent data.
- Credentials that allow both `agent` and `subrequest` stay usable on any route the service allows, with no rule listing.
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
```

When the agent and a filter use the same endpoint with different tokens, the subrequest rule comes first.
The agent's request skips it and falls through to its own rule.

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
- A `subrequest` block on an `ssh` rule.
- A `subrequest.credentials` entry that is not in the service's `credentials`, or that allows `agent`.
- `inject.credential` that is elevated.

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
`chain` rule matching skips a rule with `Subrequest` when `req.Subrequest` is nil, or when `Filters` is set and does not list `req.Subrequest.Filter`.
A matched rule sets `req.RuleCredentials` from `Subrequest.Credentials`, the same way it sets `SkipCredential`.
Each redirect hop is matched again, so a same-host redirect to another route loses the elevated credential.

## Audit and tests

- `audit.Entry` gains `Credentials []string`.
  The summary shows `[subrequest from <filter> as <cred>,...]`, and `[as <cred>]` for agent requests.
- `expect_credential` (bool) becomes `expect_credentials` (list compared as a set) in steps and subrequest fixtures.
  `[]` means unauthenticated, and an omitted key skips the check.
  The test runner's fake terminal applies the same usable-set logic, so it reports the same names as the forwarder.

## Removal

- `credential()` binding, `chain.Env.Credential`, the daemon's wiring, and `bouncer.d.ts` entries.
- `Credential.Internal`, `HTTPService.Credential`.

## Docs and examples

- `docs/bouncer.md`: credential `allow`, service `credentials`, `inject.credential`, subrequest rules.
- `docs/bouncer-filters.md`: one-time placeholders, the static placeholder not working in subrequests, removal of `credential()`, and the responsibility and latency notes from the issue.
- Migrate every config under `docs/bouncer/**` and test data.
- Add a reference example: a `github-ci-safety` filter that denies a push when the repo has Actions secrets, using `github-audit`, with tests.

## Tests

- Config: every load check above, one case each.
- Forwarder: agent vs subrequest usable sets, static placeholder ignored in subrequests, one-time placeholder in header, query, JSON body, and form body, inject precedence, `SkipCredential` stripping, query scrubbing, credentials recorded.
- jsfilter: `placeholder()` uniqueness, throws for non-`subrequest` credentials, strings expire after the run.
- Rules: `subrequest` matches only subrequests, only the listed filters when set, and lets agent requests fall through.
- Elevated credentials: a placeholder is replaced on a rule listing the credential, and left as text on another allowed route of the same service and on a redirect hop to one.
- Store: `Get` refuses by kind.
- Test runner: `expect_credentials` in steps and fixtures.

## Smoke

A handoff that runs the bouncer against real GitHub with a fine-grained `github` token and a separate `github-audit` token.

1. An agent `GET .../actions/secrets` with `github-audit`'s static placeholder is denied by rules or sent unauthenticated (expect 401/404).
2. A push to a repo with no Actions secrets passes the `github-ci-safety` filter.
3. The audit log shows `as github-audit` on the subrequest and never on an agent request.
