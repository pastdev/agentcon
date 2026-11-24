# Session claims

Issue: https://github.com/pastdev/agentcon/issues/38 (Session claims: trusted, typed facts about a Bouncer session for filters)

## Goal

A host seeds trusted `(type, value)` facts on a session when it creates it.
Filters read them as `session.claims` and can ask the operator to add one with `requestClaim`.
Claims only grow, live exactly as long as their session, and are never interpreted by agentcon.

## Decisions

- One PR for all of #38, branched from `master`.
- Claim rules live in a new leaf package `pkg/bouncer/claims`.
  It holds the limits, `ValidType`, `ValidValue`, and a `Set` type (`map[string][]string`, values sorted, never nil).
  The daemon, the approval manager, the control API, and the test runner all validate through it.
- `chain.Session` gains `Claims map[string][]string` with JSON name `claims`.
  The daemon hands every request a deep copy taken under its lock, so a request sees a fixed snapshot.
  A claim added mid-request is visible to later requests, not to the current request's frozen object.
- The daemon owns claim storage on `SessionRecord`.
  It adds a claim under its write lock, re-checks the limits, saves `sessions.json`, and writes an audit event.
  `sessions.json` already survives restarts, so claims added through `requestClaim` survive with it.
  A missing `claims` field in an older `sessions.json` loads as an empty set.
- Filters reach claims through a new `chain.Env.Claims` interface.
  `approval.Manager` implements `RequestClaim` and delegates storage to a small store interface the daemon implements.
  Concurrent `requestClaim` calls for the same session, type, and value share one prompt, like `ask`.
- `mgmt.Client.CreateSession` keeps its signature and gains variadic options, with `mgmt.WithClaims(claims.Set)`.
  Existing hosts compile unchanged.
- Shared (anonymous) sessions always have empty claims.
  "For this session" on a shared session acts as "once".
- If an approved "for this session" addition fails at write time, because a concurrent addition hit a limit or the session ended, `requestClaim` resolves `true` for this request only and logs a warning.
  The operator approved this request, so that is the least surprising result.
- `session.claims` is built from JSON and deeply frozen with `Object.freeze` before the filter sees it.
- Session creation gets an audit event for the first time, carrying the initial claims.

## Claim prompts

`requestClaim` raises a prompt with the new `prompt.KindClaim` (`"kind": "claim"`).
`prompt.Pending` gains `claim` (`{"type", "value"}`) and `session_claims` (a snapshot grouped by type), both omitted for other kinds.

```json
{
  "id": "a1b2c3",
  "kind": "claim",
  "source": "filter:gitlab-issue-scope",
  "message": "Create issues in gitlab.example.com/group/other?",
  "detail": "POST gitlab.example.com/api/v4/projects/group%2Fother/issues",
  "session_id": "deadbeef",
  "claim": {"type": "repository", "value": "gitlab.example.com/group/other"},
  "session_claims": {"repository": ["gitlab.example.com/group/project"]}
}
```

- Answers: `allow=true, remember=true` adds the claim for the session, `allow=true, remember=false` allows once, and `allow=false, remember=false` denies.
- `allow=false, remember=true` is rejected with `ErrInvalidAnswer`, because claim denials are never remembered.
- Terminals offer `[y] allow once  [s] add claim for session  [n] deny` through a new `prompt.ParseClaim`.
- Every place that switches on `Kind` handles `KindClaim`: the daemon terminal prompter, `host.AnswerAtTerminal`, host prompt hints, the admin CLI, and desktop notifications.
- Hosts built against an older `pkg/bouncer/host` report an unknown kind until they upgrade.
  That is accepted.

## Audit events

Every audit line carries an `event` field.
Existing decision lines gain `event: "decision"` and are otherwise unchanged.
These field names are a stable contract for log ingestion.

```json
{"level":"info","event":"session_created","session":"deadbeef","label":"agentcon","profile":"agent",
 "claims":{"repository":["gitlab.example.com/group/project"]},
 "message":"SESSION [agentcon] created profile=agent claims=1"}

{"level":"info","event":"claim_added","session":"deadbeef","label":"agentcon",
 "claim_type":"repository","claim_value":"gitlab.example.com/group/project","added_by":"seeded",
 "message":"CLAIM  [agentcon] repository=gitlab.example.com/group/project (seeded)"}

{"level":"info","event":"claim_added","session":"deadbeef","label":"agentcon",
 "claim_type":"repository","claim_value":"gitlab.example.com/group/other","added_by":"operator",
 "filter":"gitlab-issue-scope","prompt":"a1b2c3",
 "message":"CLAIM  [agentcon] repository=gitlab.example.com/group/other (operator)"}
```

- `session_created` always carries `claims`, `{}` when empty.
- Each seeded claim also emits its own `claim_added` with `added_by: seeded`.
- Operator additions also carry `filter` and `prompt`.
- The shared anonymous session never emits these events.

## Policy test fixtures

```yaml
cases:
  - name: unscoped project, operator adds it for the session
    claims:
      repository: [gitlab.example.com/group/project]
    steps:
      - request: {method: POST, url: "https://gitlab.example.com/api/v4/projects/group%2Fother/issues", body: "{}"}
        claim_answer: session
        expect: allow
        expect_claim_requested: {type: repository, value: gitlab.example.com/group/other}
        expect_claims:
          repository: [gitlab.example.com/group/other, gitlab.example.com/group/project]
      - name: second issue in the same project no longer prompts
        request: {method: POST, url: "https://gitlab.example.com/api/v4/projects/group%2Fother/issues", body: "{}"}
        expect: allow
        expect_claim_requested: false
```

- `claims` is per case and shared by its steps, like the KV store.
  Invalid seed claims fail the spec load.
- `claim_answer` is `session`, `once`, `deny`, or `timeout`, and unset means deny.
  It is independent of `approve`, which still answers only `ask`.
- `deny` and `timeout` both resolve `false` and add nothing.
- `expect_claim_requested` is a boolean or `{type, value}`.
- `expect_claims` compares the full set, and `{}` asserts no claims.
- There is no spec-level `claims` default.

## Reference filter

`docs/bouncer/reference/ts/filters/gitlab-issue-scope.ts` handles only `POST /api/v4/projects/:id/issues`.
Every other request passes to `next`.

- It builds the claim value as `<req.host>/<decoded project path>` and compares it exactly with the session's `repository` claims.
- A match is allowed without a prompt.
- A path that does not match calls `requestClaim("repository", value, ...)`, then allows or denies on the result.
- A numeric project ID is denied, because the filter cannot resolve it to a path without guessing.
- A GraphQL `createIssue` mutation is denied for the same reason.

## Implementation order

1. `pkg/bouncer/claims`: limits, validation, `Set`, copy, and add with limit checks.
2. `pkg/bouncer/prompt`: `KindClaim`, `ParseClaim`, the `Claim`/`SessionClaims` fields on `Question` and `Pending`, and answer validation.
3. `internal/bouncer/audit`: the `event` field, `SessionCreated`, and `ClaimAdded`.
4. `chain`: `Session.Claims`, `Env.Claims`, and `ClaimRequest`.
5. `daemon`: storage on `SessionRecord`, deep copies, `AddClaim`, the create-time seed, persistence, and the control API (`POST`/`GET /_bouncer/sessions`).
6. `approval`: `RequestClaim` with join, shared-session, and limit handling.
7. `jsfilter`: frozen `session.claims`, and `requestClaim` in the host bindings and the `bouncer` module.
8. `pkg/bouncer/mgmt`: `SessionRecord.Claims`, `WithClaims`, and the `CreateSession` options.
9. Prompt display: daemon terminal, `pkg/bouncer/host`, admin CLI, and notifications.
10. `testrunner`: fixture fields and the scripted claim answerer.
11. Docs: `bouncer.d.ts`, `bouncer-filters.md`, the reference filter, and its test fixture.

## Tests

- `claims`: invalid types (empty, uppercase, leading digit, 65 characters), invalid values (empty, 1025 bytes, invalid UTF-8, `\r`, `\n`, `\t`, other control characters), 33 types, 257 values, and duplicate values.
- Control API: a seed that is partly invalid returns 4xx and creates no session.
  Claims appear in `GET /_bouncer/sessions`.
  The create audit event carries them.
- Daemon: claims vanish after end and after expiry, survive a reload from `sessions.json`, and are absent on the anonymous session.
- Approval: already-held claims resolve without prompting, session/once/deny/timeout behave as specified, a repeated denial prompts again, concurrent identical requests share one prompt, shared sessions never gain claims, and deny-for-session is rejected.
- jsfilter: mutation attempts (assignment, `push`, `delete`, nested arrays) leave the session unchanged, and invalid arguments to `requestClaim` throw without prompting.
- Test runner fixtures for the reference filter cover each `claim_answer` and `expect_claims`.
- An end-to-end smoke check runs `bouncer serve` in the container, seeds claims through `mgmt.Client`, sends a request through the proxy, and answers the claim prompt through the control API.
