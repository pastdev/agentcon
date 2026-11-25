# Filter subrequests

Issue: https://github.com/pastdev/agentcon/issues/42 (Allow Bouncer filters to make policy-scoped HTTP subrequests)

## Goal

A filter can make an HTTP request through Bouncer and use the response to decide on the original request.
The motivating case is a push filter that looks up the provider's current branch rules before forwarding a `git push`, over HTTP or SSH.
A subrequest is just another request from the session.
It gets the same policy, credentials, and tunnel rules as a request the agent sends.

## Decisions

- A subrequest runs the full chain of the HTTP service its host matches in the session's profile.
  That is profile filters, service filters, rules, rule filters, then the forwarder.
  It has exactly the session's authority, no more.
- There is no per-filter allowlist.
  A filter is part of the config, and the config author is responsible for it.
  The issue text asks for an allowlist, so record the change on the issue.
- A host with no `http` service follows the profile's `unmatched`, `tunnel`, and `allow_private` settings, as an agent request would.
- Bouncer marks a subrequest with `req.subrequest = {filter, depth, parent}`.
  It is `null` for an agent request.
  It is set by Bouncer, never by a header, so the agent cannot forge it.
  It is not a claim, because claims belong to the whole session.
- Nesting is capped at a fixed depth of 4.
  A subrequest past the cap rejects with `subrequest: depth 5 exceeds limit 4`.
- `ask()`, `requestClaim()`, and `action: ask` rules work inside a subrequest.
  The prompt shows the subrequest's origin.
- The filter API is `import { subrequest, placeholder } from "bouncer"`.
- `subrequest()` resolves with a response shaped like the one `next()` returns, including `denied`.
  It rejects only when there is no response.
- Redirects are followed by default, with each hop a fresh pass through the chain.
  `redirect: "manual"` returns the 3xx instead.
- Body reads keep the existing 16 MiB inspection limit.
- A subrequest runs under the parent request's context, with an optional `timeout`.
- Credential injection is identical to agent requests.
  `placeholder(name)` returns a credential's placeholder for services without an `inject` spec.
- `subrequest()` works in `onRequest`, `onResponse`, and `onSSH`.
  At module top level it throws.
- A subrequest reads the session's live claims, not the parent's frozen copy.
- Test specs gain strict `subrequests` fixtures per step.

## Filter API

```typescript
import { defineFilter, deny, subrequest, placeholder } from "bouncer";

const resp = await subrequest({
  method: "GET",                       // default GET
  url: `https://api.github.com/repos/${repo}/rules/branches/${branch.split("/").map(encodeURIComponent).join("/")}`,
  headers: { Accept: "application/vnd.github+json" },
  body: undefined,                     // string, Uint8Array, or object (JSON-encoded)
  redirect: "follow",                  // or "manual"
  timeout: "10s",                      // optional, string or seconds
});

resp.status;                           // final status
resp.url;                              // final URL after redirects
resp.headers.get("content-type");
await resp.body.json();
resp.denied;                           // {by, reason} when Bouncer's chain denied it, else null
```

`subrequest()` resolves for every response, including upstream 4xx and 5xx and Bouncer denials.
It rejects when there is no response.
That covers an invalid URL or method, depth past the cap, too many redirects, a connection failure, a timeout, or a cancelled parent.
An uncaught rejection denies the original request, so a failed lookup fails closed.

`placeholder(name)` returns `bouncer-placeholder-<name>`.
It throws when the credential does not exist.
A placeholder is not a secret.
The forwarder replaces it only when the request reaches that credential's service through an allowed rule.

`req.subrequest` is `null` or a frozen `{filter, depth, parent}`.
`parent` is the `describe()` text of the request that caused it.
`depth` is 1 for a subrequest made while handling an agent request.

The time a filter spends waiting in `subrequest()` does not count toward its CPU budget, the same as `next()`.

## Dispatch

A new package `internal/bouncer/subreq` holds the routing logic, so the proxy and the test runner share it.

```go
// in chain
type SubrequestSpec struct {
	Method  string
	URL     string
	Header  http.Header
	Body    []byte
	Manual  bool
	Timeout time.Duration
}

type SubrequestFunc func(parent *Request, filter string, spec SubrequestSpec) (*Response, *url.URL, error)

// in subreq
type Router struct {
	// Session returns the live session for sess, with current claims.
	Session  func(sess *chain.Session) (*chain.Session, bool)
	Profile  func(name string) (*policy.Profile, bool)
	// Terminal is the end of an intercepted service's chain.
	Terminal func(svc *policy.Service, length int64) chain.Handler
	// Tunnel forwards a request to an unmatched host.
	Tunnel   func(prof *policy.Profile, req *chain.Request) (*chain.Response, error)
	// Direct answers every hop when Profile is nil, for filter specs.
	Direct   chain.Handler
	Audit    func(e audit.Entry)
}

func (r *Router) Do(parent *chain.Request, filter string, spec chain.SubrequestSpec) (*chain.Response, *url.URL, error)
```

`chain.Env` gains `Subrequest chain.SubrequestFunc` and `Placeholder func(name string) (string, error)`.
The spec types live in `chain`, because `subreq` imports `chain`.

The forwarder turns an upstream failure into a synthetic 502 for the agent.
It also sets `chain.Response.UpstreamErr`, so the router can reject instead.

`Do` works as follows.

1. Reject when `parent.Subrequest` depth is already 4.
2. Apply `spec.Timeout` to `parent.Ctx`.
3. Re-resolve the session and its profile.
   A session that ended or a profile that is gone rejects.
4. For each hop, up to 5 redirects:
   - Parse and check the URL.
     Only `http` and `https` are allowed.
     Default ports follow the proxy's rules.
   - Run the same method and path checks `intercept` runs.
     Factor them out of `proxy.intercept` into a shared function.
   - If the profile has an HTTP service for the host, build a `chain.Request` with the live session and `Subrequest` set.
     Then run `chain.Build(svc.Filters, Terminal(svc, length))`.
   - Otherwise, if the profile tunnels the host, send it through `Tunnel` with no credential.
   - Otherwise, return a Bouncer denial response (`host not allowed by profile <name>`).
     This resolves with `denied` set, as the agent would see a 403.
   - Write an audit entry for the hop with the subrequest fields.
   - On 301, 302, 303, 307, or 308 with a `Location`, and redirects not manual, close the body and continue.
     303 becomes GET with no body.
     301 and 302 become GET with no body when the method was POST.
     307 and 308 keep the method and body.
     A hop to a different host drops `Authorization`, `Private-Token`, and `Cookie` that the filter set.
5. Return the final response with its URL.

The proxy implements `Terminal` with its existing `terminal(svc, len)`, and `Tunnel` with `tunnelTransport`.
The daemon wires `env.Subrequest` before the proxy starts serving.
The SSH proxy needs no change, since the parent request already carries the session and context.

### Response bodies

The jsfilter instance tracks every subrequest response body it hands out during a run.
It closes the ones still open when the run ends.

## Audit

`audit.Entry` gains an optional `subrequest` object with `filter`, `depth`, and `parent`.
Each hop of a followed redirect is its own entry.

## Prompts

`chain.AskRequest` and `chain.ClaimRequest` gain an `Origin` string.
It is empty for an agent request.
For a subrequest it reads `subrequest from <filter> for <parent>`.
`prompt.Question` and `prompt.Pending` carry it as `origin`.
Every prompt view shows it on one escaped line under the request.

```text
Merge a pull request?
request: PUT api.github.com/repos/your-org/your-repo/pulls/7/merge
origin: subrequest from git-protect-branches for POST github.com/your-org/your-repo.git/git-receive-pack
```

An agent prompt and a subrequest prompt for the same request do not share one pending question, since they show different origins.
A remembered "allow for this session" answer still covers both.

## Types

`internal/bouncer/types/bouncer.d.ts` gains `subrequest`, `placeholder`, `SubrequestInit`, `SubrequestInfo`, and `Request.subrequest`.
Copy it to `docs/bouncer/reference/ts/bouncer.d.ts` and `docs/bouncer/github/ts/bouncer.d.ts`, which are identical today.

## Test runner

A step gains `subrequests`, a list of fixtures.

```yaml
steps:
  - request:
      method: POST
      url: https://github.com/your-org/your-repo.git/git-receive-pack
      git_push: [{ref: refs/heads/main}]
    subrequests:
      - url: https://api.github.com/repos/your-org/your-repo/rules/branches/main
        status: 200
        body: '[{"type": "update"}]'
        expect_header: {Accept: application/vnd.github+json}
        expect_credential: true
      - method: GET
        url: https://api.github.com/repos/your-org/your-repo/rules/branches/feature
        error: connection refused
    expect: deny
```

- A fixture matches by `method` (default `GET`) and exact `url`, query included.
  It answers every matching call.
- Fields are `status` (default 200), `headers`, `body`, or `error`, which makes `subrequest()` reject.
- `expect_header` checks headers the fixture received, after the chain ran.
- `expect_credential` checks whether the subrequest arrived with its service's credential.
  It needs a bouncer spec.
  The test runner injects no secrets, so a header check cannot show the credential.
- A subrequest with no fixture fails the step with `unexpected subrequest <method> <url>`.
- A fixture nothing called fails the step with `subrequest fixture <method> <url> was not used`.
- In a bouncer spec, subrequests go through `subreq.Router` with the profile's real chain.
  The terminal answers from fixtures instead of the step's `upstream`.
  A tunneled host also answers from fixtures.
- In a filter spec there is no chain.
  A subrequest goes straight to its fixture, with the depth and redirect logic still applied.
- Redirects work by chaining fixtures through `Location`.

## Reference policy and docs

- Add `docs/bouncer/reference/ts/filters/github-branch-rules.ts`.
  For each pushed branch it calls `GET /repos/{repo}/rules/branches/{branch}` and denies when any returned rule is `update`, `deletion`, or `non_fast_forward` for the matching update type.
  It denies when the lookup fails or is denied.
  It skips the lookup when `req.subrequest` is set, as an example of the marker.
  It encodes each segment of the branch with `encodeURIComponent`, so a branch like `smoke/protected` keeps its slash and `#` or `%` cannot change the URL.
- Attach it in `docs/bouncer/reference/bouncers.yaml` on the GitHub HTTP git rule and on a new `github-ssh` service.
  The existing `github_repo` allow rule already covers the lookup, so no new rule is needed.
- Add `docs/bouncer/reference/tests/ts/filters/github-branch-rules.test.yaml` and bouncer-level cases covering protected, unprotected, lookup error, lookup denied, and SSH.
- Document `subrequest()`, `placeholder()`, `req.subrequest`, and the fixtures in `docs/bouncer-filters.md`.
  Say plainly that a subrequest has the session's authority and goes through the normal chain.
  Note that values from the request must be URL-encoded when spliced into a URL.

## Implementation order

1. `chain`: `Subrequest` info on `Request`, the spec type, and `Env.Subrequest`.
2. `subreq.Router` with unit tests for depth, redirects, tunnel, deny, header dropping, timeout, and live claims.
3. Proxy and daemon wiring, with the shared request checks factored out of `intercept`.
4. Audit field and prompt origin.
5. jsfilter `subrequest`, `placeholder`, `req.subrequest`, and body cleanup.
6. Types.
7. Test runner fixtures.
8. Reference filter, policy, tests, and docs.

## Tests

- `subreq`: table tests with a fake terminal and tunnel.
- `jsfilter`: resolve versus reject, `denied`, `req.subrequest` frozen and present only on subrequests, use at top level throws, use after the run rejects, body cleanup, CPU budget paused while waiting.
- `proxy`: an end-to-end subrequest through an `httptest` TLS upstream with credential injection, from an HTTP hook and from an SSH hook.
- `testrunner`: strict fixture failures, redirects through fixtures, filter spec versus bouncer spec.
- `agentcon bouncer test` passes on `docs/bouncer/reference` and `docs/bouncer/github`.

## Smoke check

The smoke runs on the host through a handoff, against `pastdev/agentcon`.
It never pushes to `master`.

### One-time setup by the operator

In the GitHub web UI on `pastdev/agentcon`:

1. Create branch `smoke/protected` from `master`.
2. Add a branch ruleset:
   - Name `smoke-protected`.
   - Enforcement status active.
   - Target `refs/heads/smoke/protected` only.
   - Rules "Restrict updates" and "Restrict deletions".
   - Empty bypass list.

The rules endpoint needs only read access, so the smoke PAT needs no admin scope.

### Script

`.agentcon/smoke-subrequest.handoff.sh` builds `agentcon`, starts Bouncer with a smoke policy that attaches `github-branch-rules.ts` to git pushes for `pastdev/agentcon`, and uses a fresh clone in a temp directory.

1. Commit an empty change and push it to `smoke/protected` through Bouncer over HTTPS.
   Pass when git reports `denied by github-branch-rules`.
   Fail when the push succeeds or when the rejection comes from GitHub rather than Bouncer.
2. Push to `smoke/subrequest-<random>` through Bouncer.
   Pass when the push succeeds.
3. Delete `smoke/subrequest-<random>` through Bouncer.
   Pass when the delete succeeds.
4. Check the Bouncer audit log for subrequest entries with `filter: github-branch-rules`.
5. Repeat step 1 over SSH when an SSH key credential is configured, and skip it otherwise with a note.

It writes `status`, `step`, and `message` to the result file through a `write_result` trap.
It ends with `SMOKE PASSED` or `SMOKE FAILED: <reason>`.
