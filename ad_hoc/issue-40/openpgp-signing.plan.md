# OpenPGP signing

Issue: https://github.com/pastdev/agentcon/issues/40 (Add in-process OpenPGP commit signing to Bouncer)

## Goal

An agent signs its own git commits and tags with an OpenPGP key that only Bouncer holds.
The signer is a pseudo service.
Bouncer core treats it like any other intercepted HTTP service, except that its terminal handler signs the request body instead of forwarding it upstream.
Policy about who may sign what lives in filters and rules, as it does for every other service.

## Decisions

- The signer is an `http` service with a `signer` block in place of an upstream.
  Its `hosts` are chosen by policy.
  Docs and the reference policy use `signer.bouncer.internal`.
  The agent reaches it through the existing proxy, session token, and CA.
- The request is the raw object bytes as the body, with `repository` and `key` in the query.
  The response is an ASCII-armored detached signature.
- The handler never reads claims and never prompts.
  Repository scoping is a filter concern.
  The reference policy ships a filter that checks `repository` against `session.claims.repository` and offers `requestClaim()` for an unheld one.
  A signer service with no filters or rules signs for every session that reaches it.
  The docs say so plainly.
- The handler signs only well-formed, unsigned git commit or tag objects.
  It refuses everything else, so the key can never vouch for arbitrary bytes.
- A credential with `internal: true` may be used only by an in-process handler.
  It is never injected, never exported, and never readable by a filter.
- A signer lists its keys with explicit IDs.
  Git's `-u <user.signingkey>` selects one, so per-repository keys chosen by the agent's own git config keep working.
- The agent helper is a hidden `agentcon bouncer git-sign` subcommand behind a one-line Bash wrapper shipped in the agent payload.
- `agentcon run` does not touch the agent's git config.
  It sets only `BOUNCER_SIGNER_URL`.
  The operator sets `gpg.openpgp.program` wherever the agent's git config lives.
- The test runner runs the real payload check and key lookup, and fakes only the signature.
- The library is GopenPGP v3.
  `golang.org/x/crypto/openpgp` and its subpackages must not be in the binary's dependency graph.
- The issue text says the handler requires the repository claim.
  That moved to policy.
  Record the change on the issue so the acceptance criterion reads as met by the reference policy.

## Policy

```yaml
credentials:
  signing-work:
    internal: true
    private_key: {source: bitwarden, account: agent, item: gpg-work, path: $.notes}
    password:    {source: bitwarden, account: agent, item: gpg-work, path: $.login.password}
  signing-pastdev:
    internal: true
    private_key: {source: bitwarden, account: agent, item: gpg-pastdev, path: $.notes}
    password:    {source: bitwarden, account: agent, item: gpg-pastdev, path: $.login.password}
profiles:
  default:
    http:
      - name: commit-signing
        hosts: [signer.bouncer.internal]
        signer:
          openpgp:
            keys:
              - {id: 7C44826B7B1878A0, credential: signing-work}
              - {id: C26E02CE599B53FF, credential: signing-pastdev}
        filters: [ts/filters/signing-repository-scope.ts]
```

### `internal: true`

- Policy load refuses an internal credential named by an HTTP or SSH service `credential`.
- Policy load refuses an internal credential with `export_env`.
- `credential(name)` in a filter returns the same unavailable error as a missing credential, and the daemon logs the attempt at warn.
- Only a handler such as `signer.openpgp.keys[].credential` may name it.
- The flag puts no limit on slots.
  The signer checks the slots it needs.

### `signer.openpgp`

- `keys` is required and non-empty.
- Each `id` is a 16-hex long key ID or a 40-hex (v4) or 64-hex (v6) fingerprint.
  Case is ignored and a `0x` prefix is accepted.
  IDs are stored normalized to uppercase without `0x`.
  Two entries with the same normalized ID are refused.
- Each `credential` must exist, must be `internal: true`, must have `private_key`, and may have `password`.
  No other slot is allowed on a credential a signer names.
- A service with `signer` may not set `credential`, `inject`, `allow_upgrade`, or `insecure`.
- A resolved profile may have at most one service with `signer`.
  `BOUNCER_SIGNER_URL` then has one unambiguous value.
- A signer service's `hosts` must be exact names, with no `*`, so the first host forms a URL.
- `rules`, `filters`, and `default` work as on any service.

## Request

```
POST https://signer.bouncer.internal/openpgp/sign?repository=github.com%2Fpastdev%2Fagentcon&key=C26E02CE599B53FF
Content-Type: application/x-git-object

tree 9bedf67800b2923982bdf60c89c57ce6986c4c5b
parent bd3539c4e2f1...
author Agent <agent@example.com> 1764000000 +0000
committer Agent <agent@example.com> 1764000000 +0000

Add the signer service.
```

```
HTTP/1.1 200 OK
Content-Type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----
```

- `repository` is a hint for filters.
  The handler ignores it.
- `key` is required by the handler.
- `Content-Type` is not checked, so filters and tests can omit it.

## Handler

The handler is the terminal of the service's chain, in place of the forwarder.
It runs only after every profile, service, and rule filter called `next`.
Every refusal is a `chain.Denial` with `By: "signer"`, so it reaches the agent and the audit log through the existing denial path.

Checks, in order:

1. The request did not arrive with `SkipCredential` set.
   A leftover path under `unmatched: tunnel` would otherwise mean "forward upstream", and a signer never forwards.
2. The URL scheme is `https`.
3. Method is `POST` and path is exactly `/openpgp/sign`.
   Anything else is 404.
4. `key` is present and matches a configured `id` after normalization.
   A long key ID also matches a configured fingerprint that ends with it.
   An unknown key is 403 with a message that lists no configured keys.
5. The body is at most 1 MiB and passes the payload check below.
   A malformed payload is 400.
6. The matched credential's `private_key` and optional `password` are fetched through `creds.Store.GetSlot`.
   The key is parsed and unlocked.
   The handler confirms the key or one of its signing-capable subkeys has the requested ID.
   A mismatch is 500 with a message naming the configured `id`, not the key material.
7. GopenPGP produces a detached, armored signature over the exact body bytes.
   Hash and algorithm come from the key.
   Signing time is now.

The unlocked key is cached per credential for the credential's `cache` TTL, default 5m, the same as other slots.
A credential update or reload drops it.

### Payload check

The body must be a git object as git hands it to `gpg.program`.

- Valid UTF-8 is not required, because a commit with an `encoding` header may carry other bytes.
- Headers end at the first empty line.
  A body with no empty line is refused.
- No header line may be empty, and no NUL byte may appear in the headers.
- A commit starts with one `tree <hex>`, then zero or more `parent <hex>`, then one `author <ident>` and one `committer <ident>`.
  Object IDs are 40-hex (SHA-1) or 64-hex (SHA-256).
- A tag starts with one `object <hex>`, one `type <commit|tree|blob|tag>`, one `tag <name>`, and one `tagger <ident>`.
- `<ident>` is `name <email> <seconds> <+|-HHMM>`.
- Other headers may follow, such as `encoding`, `mergetag`, and continuation lines that start with a space.
- `gpgsig` or `gpgsig-sha256` anywhere in the headers means the object is already signed and is refused.
- A tag body containing `-----BEGIN PGP SIGNATURE-----` is already signed and is refused.
- Git push certificates (`certificate version`) do not match either shape and are refused.

### Audit

`Describe()` for a signer request adds `key=<ID> sha256=<hex> bytes=<n> type=<commit|tag>`.
That lands in the existing `decision` line.
The object contents are never logged.
The audit event contract gains no new fields.

## Agent helper

### Wrapper

`/opt/agentcon/bin/git-sign` is shipped in the agent tar.

```bash
#!/usr/bin/env bash
exec /opt/agentcon/bin/agentcon bouncer git-sign "$@"
```

`host.AgentLayout` gains a `GitSign` path, normalized and validated like the other payload paths.
`WriteAgentPayload` writes it mode `0755`, with the binary path taken from the layout.

### `agentcon bouncer git-sign`

The command is `Hidden: true`, like `ssh-connect`.
`--help` still works and describes exactly what it reads, sends, and prints.
`cmd/` only parses arguments and formats output.
The client logic lives in `pkg/bouncer/gitsign`.

Git invokes it two ways.

Sign:

```
git-sign --status-fd=2 -bsau <key>
```

- Read the object from stdin.
- Read `BOUNCER_SIGNER_URL`.
  If it is unset, exit 1 with `bouncer: BOUNCER_SIGNER_URL is not set (no signer service in this session's profile)`.
- Work out `repository`.
  Use `git config agentcon.signing.repository` when set.
  Otherwise normalize `git remote get-url origin`.
  If neither works, send no `repository` and let policy decide.
- POST through the proxy from the environment, trusting `SSL_CERT_FILE`.
- On 200, write the signature to stdout, then write `\n[GNUPG:] SIG_CREATED D <algo> <hash> 00 <time> <fingerprint>\n` to the status fd.
  Git only looks for the `SIG_CREATED ` prefix, but the line follows gpg's format.
  The algorithm, hash, fingerprint, and creation time come from response headers `X-Bouncer-Signer-Key-Algorithm`, `X-Bouncer-Signer-Hash`, `X-Bouncer-Signer-Fingerprint`, and `X-Bouncer-Signer-Created`, so the helper never parses the signature.
  `X-Bouncer-Signer-Type` names the object type for the stderr line.
- Write `bouncer: signed <type> for <repository> with <key> via <host>` to stderr.
  Git shows stderr only on failure.
- On any other status, write the response body to stderr and exit 1.
  Git then aborts and the index is unchanged.

Verify:

```
git-sign --keyid-format=long --status-fd=1 --verify <sigfile> -
```

- `exec` the real `gpg` found on `PATH` with the same arguments.
- If no `gpg` is on `PATH`, exit 1 with `bouncer: git-sign does not verify signatures and no gpg is installed`.

Other invocations exit 2 with a usage message.

`--dry-run` is a flag for a human.
It reads stdin, prints method, URL, repository, key, payload SHA-256, and byte count to stderr, and sends nothing.

### Repository normalization

`pkg/bouncer/gitsign.NormalizeRemote` turns a remote URL into `host/path`.

| Remote | Result |
| --- | --- |
| `https://github.com/pastdev/agentcon.git` | `github.com/pastdev/agentcon` |
| `http://github.com/pastdev/agentcon` | `github.com/pastdev/agentcon` |
| `ssh://git@github.com/pastdev/agentcon.git` | `github.com/pastdev/agentcon` |
| `ssh://git@github.com:22/pastdev/agentcon.git` | `github.com/pastdev/agentcon` |
| `git@github.com:pastdev/agentcon.git` | `github.com/pastdev/agentcon` |
| `git@GitHub.Com:PastDev/Agentcon.git` | `github.com/PastDev/Agentcon` |
| `https://gitlab.example.com/group/sub/project.git` | `gitlab.example.com/group/sub/project` |

- The host is lowercased and the port dropped.
- The path is cleaned, `.git` is trimmed, and its case is kept.
- A query, a fragment, an empty host, or an empty path is an error.

The reference filter compares the way `gitlab-issue-scope.ts` does after the lowercasing change, so a remote with different path case still matches a lowercase claim.

### Agent environment

`envexport.Params` gains `SignerURL`.
When set, `Build` adds `BOUNCER_SIGNER_URL`.
The sidecar knows the session's profile, so its create-session response carries `signer_url`, `https://<first host>/openpgp/sign`, when that profile has a signer service.
`mgmt.NewSession.SignerURL` holds it, and `host.AgentEnv` passes it to `envexport`.
`agentcon run` already calls `AgentEnv`, so it needs no change.
Nothing else in the agent's git config or environment changes.

The operator's git config needs:

```ini
[gpg]
        format = openpgp
[gpg "openpgp"]
        program = /opt/agentcon/bin/git-sign
```

## Host side

- `PrepareCredentials` already passes a non-SSH `private_key` through unchanged.
  Add a test that an armored OpenPGP key in a `file` or `provided` slot is PUT unchanged and never prompts for an SSH passphrase.
- The signer reads the OpenPGP passphrase from the credential's `password` slot.
  No host prompt is added for OpenPGP passphrases.

## Test runner

- A signer service's terminal is a test signer.
  It runs the same checks as the real handler, including key lookup by `id`, without fetching a credential.
- An allowed request gets 200 with the fixed body `-----BEGIN PGP SIGNATURE-----\nbouncer-test-signature\n-----END PGP SIGNATURE-----\n` and the same `X-Bouncer-Signer-*` headers with fixed values.
- A step with `upstream` on a signer service fails spec loading.
- `expect_credential` on a signer step fails spec loading.

## Reference policy and docs

- `docs/bouncer/reference` gains the signer service and `ts/filters/signing-repository-scope.ts`.
  - It handles only `POST /openpgp/sign`.
  - A held `repository` claim passes to `next` with no prompt.
  - An unheld one calls `requestClaim("repository", value, ...)`.
  - A missing `repository` is denied.
- Its test fixture covers a held claim, an operator adding a claim for the session, a denied claim, a missing repository, an unknown key, a malformed payload, an already-signed commit, and a tag.
- `docs/bouncer.md` gains a signing section covering `internal`, `signer.openpgp`, `BOUNCER_SIGNER_URL`, the git config lines, and a warning that an unfiltered signer signs for every session.
- `docs/bouncer-filters.md` notes that `credential()` cannot read internal credentials.
- `bouncer.d.ts` needs no change.

## Dependency guard

A Go test runs `go list -deps ./cmd/agentcon` and fails if any package path is `golang.org/x/crypto/openpgp` or starts with `golang.org/x/crypto/openpgp/`.
It references Go advisory GO-2026-5932.
GopenPGP v3 depends on `github.com/ProtonMail/go-crypto`, which is a different module path.

## Implementation order

1. `pkg/bouncer/config`: `Credential.Internal`, `Service.Signer`, `OpenPGPSigner`, key ID normalization, and every load-time check above.
2. `internal/bouncer/creds` and `daemon`: `credential()` refuses internal credentials.
3. `internal/bouncer/gitobject`: the payload check, returning the object type.
4. `internal/bouncer/signer`: key lookup, unlock, cache, and GopenPGP signing.
5. `proxy`: choose the signer terminal for a signer service, and the `SkipCredential` refusal.
6. `chain`: signer fields in `Describe()`.
7. `pkg/bouncer/gitsign`: `NormalizeRemote`, argument parsing, the HTTP client, and status output.
8. `cmd/agentcon/bouncer`: hidden `git-sign`.
9. `pkg/bouncer/host` and `envexport`: the wrapper in the agent payload, `AgentLayout.GitSign`, and `BOUNCER_SIGNER_URL`.
10. `daemon` and `mgmt`: `signer_url` in the create-session response.
11. `testrunner`: the test signer and spec load checks.
12. Dependency guard test.
13. Reference policy, filter, fixture, and docs.

## Tests

- Config: each refusal above, with one case per rule.
- `credential()`: an internal credential reads as unavailable and logs a warning.
- `gitobject`: valid commits (root, merge, SHA-256, `encoding`, `mergetag`), valid tags, and refusals (no blank line, missing `tree`, wrong header order, bad ident, `gpgsig`, `gpgsig-sha256`, signed tag body, push certificate, arbitrary bytes, NUL in headers, oversize).
- `signer`: sign and verify with a generated passphrase-protected key, a wrong passphrase fails with no signature, a key whose ID does not match its configured `id` fails, a subkey ID matches, the cache is used within TTL and dropped on update.
- `proxy`: a signer service never dials upstream, `SkipCredential` is refused, non-POST and wrong path are refused, a filter `deny` produces no signature.
- `gitsign`: the normalization table, argument parsing for sign and verify, the status line format, the stderr line, `--dry-run` sends nothing, and a non-200 exits 1 with the body on stderr.
- `host`: the wrapper is in the agent tar at the layout path with mode `0755`, and `BOUNCER_SIGNER_URL` is set only with a signer.
- Test runner: reference fixture passes, and `upstream` or `expect_credential` on a signer step fails loading.
- Dependency guard as above.

## Smoke check

`ad_hoc/issue-40/smoke` runs in the agent container with no credentials.
It starts a real `agentcon bouncer serve`, PUTs a generated passphrase-protected key as `provided` values, and unpacks the real agent payload and environment.
It covers every check below except the Bitwarden source.

The Bitwarden source needs a handoff script, because it needs the operator's vault and a passphrase-protected key in it.
It runs a real `agentcon run` session against a throwaway repository with a seeded `repository` claim.

- `git commit -S` with `gpg.openpgp.program=/opt/agentcon/bin/git-sign` succeeds.
  `git verify-commit HEAD` passes against the exported public key.
- `git tag -s` succeeds and `git verify-tag` passes.
- No extra unlock prompt or `gpg-agent` is involved after the vault unlock at session start.
- A repository with no claim, where the operator denies the claim prompt, fails the commit.
  `git diff --cached` still shows the staged change.
- An unknown `user.signingkey` fails the commit with the staged change intact.
- Expected failures are labeled as expected, and the script ends with `SMOKE PASSED` or `SMOKE FAILED: <reason>`.
