# Bouncer

The [README](../README.md) getting-started path ends with a GitHub overlay you can add after a session already starts.
This page is policy shape, credentials, sessions, and the sidecar layout `agentcon run` implements.

`agentcon bouncer --help` lists flags.
Host commands pick a live session by `--slug`, then `--project`, then cwd.

## Policy

`default_profile` is required.
A session with no profile uses that name.

Each HTTP service is a host list, the credentials that may be sent to it, inject rules, and an ordered `rules` list.
Each SSH service names the one credential it signs in with.
The first matching rule wins.
`unmatched` applies to hosts that no service claims.
`tunnel` splices those hosts.
`deny` blocks them.
Leftover paths on an intercepted host carry no credential and have placeholder auth stripped.

`git: {}` is a git-smart-HTTP matcher, not an HTTP method.
It matches info/refs, git-upload-pack, and git-receive-pack.
Path globs are not a substitute.
They miss receive-pack and nested `.git` paths.
`git-protect-branches` only looks at `refs/heads/`.
A tag push is `refs/tags/*`.
Put a `refs` rule before a blanket `git: {}` allow if tags should ask or deny.

`github_repo` is a YAML list of `owner/repo`.
`github_subpaths` limits REST paths under that repo.
Git traffic never matches a subpath rule.

TypeScript filters hang on a profile, a service, or a rule.
Rule filters run only after that rule matches.
A filter may call `next()`, `deny()`, `respond()`, or `ask()`.
Put files under `ts/` next to the overlay YAML.
How to write them is in [bouncer-filters.md](bouncer-filters.md).

Agent `tunnel` hosts are unioned onto root profiles.
`agentcon config` prints that list under `agents`.
There is no builtin host list in the binary.

## Choosing `unmatched`

`unmatched` decides what happens to HTTP and HTTPS traffic for a host that no `http` service claims and no `tunnel` entry lists.
It does not apply to SSH.
SSH to a host without an `ssh` entry is always refused.

Credentials stay in the sidecar either way.
The choice is about where else the agent can send data.

With `tunnel`, the sidecar splices the connection to the destination without terminating TLS.
No filter sees the traffic and no credential is attached.
The audit log records only the host and port, with decision `tunnel`.
Loopback, private, link-local, CGNAT, and other reserved destinations are still refused unless the profile sets `allow_private: true`.

With `deny`, the agent reaches only intercepted services and the hosts on the profile `tunnel` list.
That list includes the agent `tunnel` hosts described in [Agent tunnels](#agent-tunnels).
Everything else gets a 403 that names the profile.
The agent network has no route out except through the sidecar.

Choose `tunnel` when:

- The agent needs package registries, documentation, or other hosts you cannot list in advance.
- Nothing in the workspace would matter if it left the machine.
- You are bringing up a new agent or project and want to learn which hosts it uses.

Choose `deny` when:

- The workspace holds source, data, or secrets that must not leave.
- The work fits a known set of hosts.
- Every new outbound host should be a reviewed decision.

`deny` limits destinations, not content.
An agent allowed to push to a GitHub repo can still put data in that repo.
It can also run code in that repo's CI.
See [GitHub](github.md) for the settings that keep CI from exposing secrets.
Use `rules` and filters on intercepted services to control what reaches them.

To move from `tunnel` to `deny`, run with `tunnel` and `--log audit=debug`, and collect the tunneled hosts from the sidecar log.
Then put the ones you accept on the profile `tunnel` list and switch to `deny`.

```bash
docker logs agentcon-<bounded>-<slug>-bouncer 2>&1 | grep 'decision=tunnel'
```

The sidecar log is removed with the sidecar, so collect it before the session ends.
Container names are described in [Sessions](#sessions).

## Credentials

Each credential is a composite of slots (`username`, `password`, `token`, `private_key`, `certificate`).
Each slot has a `source` and the fields that source needs.

`allow` is required.
It lists the kinds of requests that may use the credential, as described in [allow](#allow).

`export_env` lists agent environment variables set to that credential's placeholder.
`cache` is how long a fetched slot is kept.
Default is 5m.
`0s` disables it.

`path` is a JSONPath on the source payload.
Empty means the payload is the value.
Bitwarden requires `path` because the payload is the whole decrypted cipher JSON.

`file`, `keyring`, `command`, and `provided` are resolved on the host and PUT as `credential.slot` keys, for example `github-pat.token`.

### bitwarden

The sidecar unlocks the vault.
Accounts are defined once, in the top-level `bitwarden` map, and slots name one with `account`.
Each account's vault is synced and unlocked once, and every slot that names it shares that vault.

Account fields:
Required: `email`.
Optional: `server` (default bitwarden.com), `password` (unset, so the sidecar prompts).
Two accounts may not share an email and server.

`password` is a value source for the master password: `env`, `file`, `keyring`, `command`, or `provided`.
`agentcon run` resolves it on the host, once per account, and PUTs it to the sidecar.
An `env` password is PUT with the `source: env` values.
The others are PUT as `bitwarden.<account>`, for example `bitwarden.agent`.
That key is also the default keyring account for a `keyring` password.
The master password never reaches the policy file or the container environment.
A configured password is tried once.

Without `password`, the sidecar raises a [prompt](#prompts) for the master password.
`agentcon run` answers it at its terminal and starts the agent once every vault is unlocked.
The master password is asked for up to three times.
Either way, the sidecar raises another prompt for a verification code when the account asks for one.

Slot fields:
Required: `account`, `item`, `path`.
Optional: `folder` (unset).

The named item must already exist in that account's vault.
`path` must select exactly one string from the decrypted cipher JSON.
Examples: `$.notes`, `$.login.password`, `$.login.username`, `$.sshKey.privateKey`, `$.fields[?(@.name=='API Key')].value`.

```yaml
bitwarden:
  agent:
    email: you@example.com
    password:
      source: command
      command: [rbw, get, agent-vault-master]
credentials:
  github-pat:
    allow: [agent]
    token:
      source: bitwarden
      account: agent
      item: pat-github-agent
      path: $.notes
    export_env: [GH_TOKEN, GITHUB_TOKEN]
  gitlab-login:
    allow: [agent]
    username:
      source: bitwarden
      account: agent
      item: GitLab
      path: $.login.username
    password:
      source: bitwarden
      account: agent
      item: GitLab
      path: $.login.password
```

Through v0.3.0, slots set `email`, `server`, and `password_env` themselves.
Those slot fields are now rejected.
Move them to an account, and replace `password_env: NAME` with `password: {source: env, env: NAME}`.

### env

Reads a host environment variable.
`agentcon run` PUTs those names after status is up.

Required: `env`.

```yaml
credentials:
  slack:
    allow: [agent]
    token:
      source: env
      env: SLACK_BOT_TOKEN
    export_env: [SLACK_TOKEN]
```

### file

Reads a file on the host.

Required: `file`.

In `agentcon.d` YAML, home is `{{home}}`.
Configloader does not expand `~`.
Relative paths resolve against the config file.

```yaml
credentials:
  sandbox-key:
    allow: [agent]
    private_key:
      source: file
      file: "{{home}}/.ssh/id_ed25519_sandbox"
```

### keyring

Reads the OS keyring.
The service name is always `agent-bouncer`.
That name is not a YAML field.

Required: none beyond `source`.
Optional: `account` (default is the credential name).

Store the secret under service `agent-bouncer` and that account before `run`.

```yaml
credentials:
  gitlab:
    allow: [agent]
    token:
      source: keyring
      account: gitlab
    export_env: [GITLAB_TOKEN]
```

### command

Runs an argv on the host.
Stdout, minus trailing newlines, is the payload.

Required: `command`.

```yaml
credentials:
  github-cli:
    allow: [agent]
    token:
      source: command
      command: [gh, auth, token]
    cache: 15m
    export_env: [GH_TOKEN]
```

A failed command reports only its executable and exit status, such as `gh: exit status 1`.
Its stderr, capped at 4 KiB, goes to the operator's terminal and the bouncer log, never to the agent.
Stderr can contain secrets, so treat both as sensitive.

### ssh-agent

Valid only on `private_key`.
The YAML does not name a key file or a socket.
`agentcon run` bind-mounts `$SSH_AUTH_SOCK` at `/opt/agentcon/ssh-agent.sock`.
This source is not a PUT.

Required: none beyond `source`.
Optional: `fingerprint` (default is every key currently in the agent).
`fingerprint` is the `SHA256:...` line from `ssh-add -l -E sha256`.

```yaml
credentials:
  github-ssh:
    allow: [agent]
    private_key:
      source: ssh-agent
      fingerprint: SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### provided

The host supplies the value at start.
PUT key is `credential.slot`.

Required: none beyond `source`.

```yaml
credentials:
  deploy:
    allow: [agent]
    private_key:
      source: provided
```

An HTTP service lists in `credentials` the credentials that may be sent to its hosts.
`inject` names one of them in `inject.credential` and says how it is attached.
`inject.git` changes how it is attached to git smart-HTTP requests, and always uses `inject.credential`.
An agent may also send a listed credential's placeholder in `Authorization`, `Private-Token`, the inject header, or a header in `placeholder_headers`.
A placeholder there takes precedence over `inject` in the header `inject` would write.
An SSH service names its one credential in `credential`.

```yaml
profiles:
  default:
    unmatched: tunnel
    http:
      - name: github
        hosts: [github.com, api.github.com]
        credentials: [github-pat]
        inject:
          credential: github-pat
          bearer: true
          git: {basic: {username: x-access-token}}
          # header: PRIVATE-TOKEN
          # value: "{{secret}}"
          # basic: {username: oauth2}
          # query: token
        rules:
          - action: ask
            git: {service: receive-pack, refs: [refs/tags/*]}
            github_repo: [your-org/your-repo]
            prompt: "Push a git tag?"
          - action: allow
            git: {}
            github_repo: [your-org/your-repo]
    ssh:
      - name: github-ssh
        hosts: [github.com, ssh.github.com]
        user: git
        credential: github-ssh
        allow: [git]
        rules:
          - action: ask
            git: {service: receive-pack, refs: [refs/tags/*]}
            github_repo: [your-org/your-repo]
            prompt: "Push a git tag?"
          - action: allow
            git: {}
            github_repo: [your-org/your-repo]
```

A full GitHub overlay is the [GitHub starting point](#github-starting-point).

Through v0.6.0, a service named one credential with `credential:`, and `internal: true` marked a signing key.
Both are now rejected.
Replace `credential: X` with `credentials: [X]` and `inject: {credential: X, ...}`, and `internal: true` with `allow: [internal]`.

### lookup_credential

A rule can name a GitLab project by path while the request URL uses its numeric ID, such as `/api/v4/projects/42/issues`.
The sidecar then looks the ID up with `GET /api/v4/projects/<path>`, sending the service's `lookup_credential` as a bearer token.
It must be listed in the service's `credentials` and must allow `agent`, because agent requests trigger lookups.
A service whose rules name a project by `path` without `id` must set it.

```yaml
      - name: gitlab
        hosts: [gitlab.example.com]
        credentials: [gitlab]
        inject: {credential: gitlab, header: PRIVATE-TOKEN}
        lookup_credential: gitlab
        rules:
          - action: allow
            gitlab_project: {path: mygroup/myproject, subpaths: ["issues/**"]}
```

A lookup only ever uses the service of the profile that matched the request.
Results are cached for an hour per credential, host, and project.

### allow

`allow` lists the kinds of requests that may use a credential:

- `agent`: the agent's own requests and SSH connections.
- `subrequest`: requests a filter makes with [`subrequest()`](bouncer-filters.md#subrequests).
- `internal`: handlers inside the sidecar, such as an [OpenPGP signer](#commit-signing).
  It never combines with another kind, because the secret is used inside the sidecar and never sent.

None of them lets filter code read the secret.
The policy load refuses:

- a credential without `allow`, or with an empty one
- `export_env` without `agent`, since the agent could never use the exported placeholder
- an SSH service's credential without `agent`, since the SSH proxy signs in with the key directly
- a signer's credential that is not `allow: [internal]`
- an `internal` credential in a service's `credentials`

```yaml
credentials:
  signing:
    allow: [internal]
    private_key:
      source: bitwarden
      account: agent
      item: gpg-signing
      path: $.notes
    password:
      source: bitwarden
      account: agent
      item: gpg-signing
      path: $.login.password
```

### Elevated credentials

An elevated credential allows `subrequest` but not `agent`.
It lets a filter look up data that the agent's own token must not read, such as a repo's Actions secrets or classic branch protection.
The agent can never send it, even by naming its placeholder.

A subrequest may use an elevated credential only on a rule that lists it in `subrequest.credentials`.
A rule with a `subrequest` block matches only filter subrequests, and agent requests fall through to later rules.
`subrequest.filters` limits it further, to the filter placements with those ids.
A filter placement gets an `id` in the policy, unique across the whole policy.
Rules never match on a filter's name, because the name comes from its file name or from `defineFilter({name})`, and two filters can share one.

```yaml
credentials:
  github:       {allow: [agent, subrequest], token: {source: keyring}}
  github-audit: {allow: [subrequest], token: {source: keyring}}

profiles:
  default:
    http:
      - name: github
        hosts: [github.com, api.github.com]
        credentials: [github, github-audit]
        inject: {credential: github, bearer: true}
        rules:
          - action: allow                     # the filter's lookup, elevated token
            methods: [GET]
            github_repo: [myorg/myrepo]
            github_subpaths: ["actions/secrets"]
            subrequest:
              filters: [github-ci-safety]     # optional: only this placement
              credentials: [github-audit]
          - action: allow                     # the agent's own access, ordinary token
            methods: [GET]
            github_repo: [myorg/myrepo]
          - action: allow
            git: {}
            github_repo: [myorg/myrepo]
            filters:
              - path: ts/filters/github-ci-safety.ts
                id: github-ci-safety
```

When the agent and a filter use the same endpoint with different tokens, put the subrequest rule first.
The policy file then shows every route an elevated credential can reach.
A redirect hop is matched against the rules again, so a redirect to another route loses the elevated credential.

The policy load refuses a `subrequest` block with neither `filters` nor `credentials`, an empty list in either, an id that no placement has, an id used twice, a `subrequest.credentials` entry that is not elevated or not in the service's `credentials`, an elevated `inject.credential`, and a `subrequest` block on an SSH rule.

A filter that names an elevated credential acts with that credential's authority.
The filter author is responsible for how it is used, the same as for any other filter code.
[Elevated lookups](bouncer-filters.md#elevated-lookups) covers what that means for filter code.

## Commit signing

An agent can sign its own commits and tags with an OpenPGP key that only the sidecar holds.
The signer is a pseudo service.
It is an `http` service like any other, matched by host, with profile, service, and rule filters.
Its last step signs the request body inside the sidecar instead of forwarding it, and nothing is sent to its hosts.

```yaml
credentials:
  signing-work:
    allow: [internal]
    private_key: {source: bitwarden, account: agent, item: gpg-work, path: $.notes}
    password:    {source: bitwarden, account: agent, item: gpg-work, path: $.login.password}
  signing-oss:
    allow: [internal]
    private_key: {source: bitwarden, account: agent, item: gpg-oss, path: $.notes}
    password:    {source: bitwarden, account: agent, item: gpg-oss, path: $.login.password}
profiles:
  default:
    http:
      - name: commit-signing
        hosts: [signer.bouncer.internal]
        signer:
          openpgp:
            keys:
              - {id: 7C44826B7B1878A0, credential: signing-work}
              - {id: C26E02CE599B53FF, credential: signing-oss}
        filters: [ts/filters/signing-repository-scope.ts]
```

Each `id` is a 16-digit long key ID or a full fingerprint.
Git asks for a key with `-u <user.signingkey>`, so per-repository keys chosen by the agent's own git config keep working.
A long key ID matches a fingerprint that ends with it.
Each `credential` must be `allow: [internal]`, must have `private_key` as an armored OpenPGP private key, and may have `password` as its passphrase.
After unlocking, the signer checks that the key, or one of its signing subkeys, has the configured ID.
A subkey ID signs with exactly that subkey, like `gpg -u <subkey>!`.
A primary key ID signs with the newest valid signing subkey, or the primary key when it has none, like `gpg -u <primary>`.
An unlocked key is kept for the credential's `cache` TTL, then evicted.
A config reload evicts every unlocked key.

`gpg --export-secret-keys <id>` exports the whole key, with every subkey, even when `<id>` names one subkey.
Append `!` to export only the primary key and that subkey, which keeps expired and unrelated subkeys out of the credential:

```bash
gpg --armor --export-secret-keys 'C26E02CE599B53FF!'
```

`hosts` must be exact names, and a resolved profile may have only one signer service.
A signer service may not set `credentials`, `lookup_credential`, `inject`, `allow_upgrade`, or `insecure`.

The signer refuses, with no signature:

- anything but `POST /openpgp/sign` over HTTPS
- a request no rule allowed, such as a leftover path under `unmatched: tunnel`
- a `key` it does not hold, without naming the keys it does hold
- a body that is not an unsigned git commit or tag object, up to 1 MiB

So the key can never vouch for arbitrary bytes.
The audit line names the key, the object type, its size, and its SHA-256, never its contents.

The signer does not read claims.
**Without a filter, it signs for every session that reaches it.**
[`signing-repository-scope.ts`](bouncer/reference/ts/filters/signing-repository-scope.ts) signs without a prompt for a repository in the session's `repository` claims, and asks the operator to add any other.

### Agent side

The agent tar includes `/opt/agentcon/bin/git-sign`, a one-line wrapper around `agentcon bouncer git-sign`.
`agentcon run` sets `BOUNCER_SIGNER_URL` to `https://<first host>/openpgp/sign` when the session's profile has a signer service.
It does not change the agent's git config.
Point git at the wrapper wherever the agent's git config lives:

```ini
[gpg]
        format = openpgp
[gpg "openpgp"]
        program = /opt/agentcon/bin/git-sign
```

`git commit -S` and `git tag -s` then send the object, `key`, and `repository` to the signer.
`repository` is `git config agentcon.signing.repository`, or the `origin` remote as `host/path`.
A refusal prints the sidecar's reason, and git aborts with the index unchanged.
`git verify-commit` runs the `gpg` on `PATH`, so verifying needs gpg and the public key in the agent.
`agentcon bouncer git-sign --help` describes each step, and `--dry-run` prints the request without sending it.

## GitHub starting point

[docs/bouncer/github](github) is a starting point, not a product policy.
Copy it into `~/.config/agentcon.d`, then edit `bouncers.yaml` for your repo and Bitwarden items.
It adds a named `github` bouncer, binds it on the `git` context, and ships the three filters that overlay uses.
Keep one `bouncers.yaml`.
A leftover `bouncer.yaml` loses, because later files replace slices.

From a clone of this repository:

```bash
mkdir -p ~/.config/agentcon.d
cp -a docs/bouncer/github/. ~/.config/agentcon.d/
```

From a release-only install:

```bash
mkdir -p ~/.config/agentcon.d
curl --fail --location \
  https://github.com/pastdev/agentcon/archive/refs/heads/master.tar.gz \
  | tar \
      --directory ~/.config/agentcon.d \
      --extract \
      --gzip \
      --strip-components 4 \
      --wildcards \
      '*/docs/bouncer/github'
```

That writes `bouncers.yaml`, `ts/`, and `tests/` next to your agent and context files.
It does not set `agent` or `root`.
If your context is not named `git`, rename that key in `bouncers.yaml`.
Add another repo by appending to each `github_repo` list, not by copying the rules.
After editing, update `tests/` to match and run `agentcon bouncer test --context git`.
[Test](bouncer-filters.md#test) covers the spec format.

`unmatched: tunnel` splices unknown hosts.
github.com and api.github.com are intercepted.
Leftover paths on those hosts go through without the PAT.
A receive-pack of `refs/tags/*` asks, because a tag starts the release workflow.
`git-protect-branches.ts` still only blocks `main` and `master`.
A GraphQL `mergePullRequest` asks first, before the blanket `/graphql` allow.
`mergePullRequest` is omitted from the GraphQL deny list so `require-approval-merge.ts` can still ask if that YAML rule is missing.
REST merge uses the YAML `action: ask` rule.

Writing filters is in [bouncer-filters.md](bouncer-filters.md).

## Sessions

`agentcon run` mints an 8-character hex session slug before it creates Docker objects.
Container and network names are `agentcon-<bounded>-<slug>-<role>`.
`<bounded>` is the project path relative to the context root, made docker-safe, and left-truncated so the full name stays at 63 characters.
`<role>` is `agent`, `bouncer`, or `ext`.

Host discovery files are `~/.local/state/agentcon/running/<slug>.yml`.
`run` prints `agentcon session <slug> project <project>`.

Decisions go to the audit logger, which [Logging](../README.md#logging) describes.

### Audit events

Every audit line has an `event` field.
Hosts can send these lines to log ingestion, so their field names are stable.

| Event | Fields |
| --- | --- |
| `decision` | `session`, `label`, `profile`, `transport`, `service`, `request`, `decision`, `by`, `reason`, `status`, `duration_ms`, `credentials` (names only, when the request carried any), and for a filter's subrequest `subrequest` (`filter`, `id`, `depth`, `parent`) |
| `session_created` | `session`, `label`, `profile`, `claims` (`{}` when none) |
| `claim_added` | `session`, `label`, `claim_type`, `claim_value`, `added_by`, and for an operator addition `filter` and `prompt` |

A [subrequest](bouncer-filters.md#subrequests) logs one `decision` per hop, including each redirect it follows.
Its `parent` is the description of the request that caused it.
One request can carry more than one credential, such as a one-time placeholder in the body and `inject` in a header.
The message names them, as in `[subrequest from github-ci-safety as github-audit]` or `[as github]`.

`added_by` is `seeded` for a claim the session was created with, and `operator` for one added through a `requestClaim()` prompt.
A session created with claims logs `session_created` and then one `claim_added` per claim.

```json
{"level":"info","event":"claim_added","session":"deadbeef","label":"agentcon","claim_type":"repository","claim_value":"gitlab.example.com/group/other","added_by":"operator","filter":"gitlab-issue-scope","prompt":"a1b2c3","message":"CLAIM  [agentcon] repository=gitlab.example.com/group/other (operator)"}
```

## Prompts

The sidecar asks a human through prompts.
Filter `ask()` and rule `action: ask` raise one, filter `requestClaim()` raises one, and so does a Bitwarden vault that needs a master password or verification code.
Each prompt has an id, a kind, a source, and a message.

| Kind | Raised for | Answer |
| --- | --- | --- |
| `confirm` | an `ask` approval | allow or deny, once or for the session |
| `claim` | a [session claim](bouncer-filters.md#session-claims) request | allow once, add the claim for the session, or deny |
| `text` | a verification code | a line of text |
| `secret` | a master password | a value read without echo |

Several places can answer a pending prompt.

- `agentcon run` answers prompts at its terminal while the sidecar starts.
- An interactive `agentcon bouncer serve` shows prompts one at a time.
- `agentcon bouncer prompts` lists them from another terminal, and `agentcon bouncer answer <id>` answers one there.
- `agentcon bouncer approve <id>` and `agentcon bouncer deny <id>` answer a `confirm`, and `--session` remembers the answer.
  They answer a `claim` too, where `approve --session` adds the claim and `deny --session` is refused.
- `agentcon bouncer decline <id>` refuses to answer a prompt of any kind.

A claim prompt shows the requested claim in full.
When its value has a backslash or a non-ASCII character, a `claim (escaped):` line follows with those characters as `\uXXXX` escapes.
That makes a look-alike letter from another script visible, such as a Cyrillic `о` in `grоup`.
`agentcon bouncer prompts` shows only the escaped form.

At a terminal, Enter answers.
An empty `text` or `secret` declines, and so does Ctrl-C.
A declined or expired approval or claim request is a deny.
A declined master password fails that vault's unlock.

A `secret` answer goes only to the code that asked for it.
It is never logged, remembered, or shown in listings, events, or notifications.
Filters and rules raise only `confirm` and `claim` prompts, so a request can never ask the human for a password.

The `prompts` block configures them.

```yaml
prompts:
  timeout: 2m      # unanswered prompts expire after this
  notify: true     # desktop notification for each pending prompt
  terminal: true   # prompt in an interactive `bouncer serve` terminal
  cli: true        # allow answering through the management API
```

`cli: false` stops `agentcon run` and the `agentcon bouncer` commands from answering.
`agentcon run` refuses a policy with `cli: false` when a Bitwarden account it uses has no `password`, because nothing could unlock it.

## Sidecar image

The sidecar runs `registry.access.redhat.com/ubi10/ubi-minimal:10.2` unless `sidecar` names another image.
`sidecar` takes the same `image`, `build`, and `pull_policy` fields as `agents.<name>`, with the same meaning.
A `build` without `image` is tagged `agentcon/bouncer-sidecar`.
`--pull` overrides `sidecar.pull_policy` for one run.

```yaml
sidecar:
  build:
    context: '{{relativeDir "sidecar"}}'
```

The image has to work in your environment, the same as an agent image.
That includes trusting the CAs your network presents and passing your image scans.

The image does not need agentcon.
`run` copies its static binary to `/opt/agentcon` and makes it the entrypoint.
On a Linux host, that binary is the running `agentcon`.
Other hosts need a Linux build that matches the container architecture, such as the `agentcon-linux-arm64` release asset.
The container runs as the host UID with group `0`, not as root, so install trust when the image is built.

### Trusting a TLS inspection CA

On a network that inspects TLS, upstream certificates are signed by an inspection CA.
The stock image does not trust it, so the Bitwarden unlock and every intercepted host fail with `x509: certificate signed by unknown authority`.
Put the CA in the `sidecar.build` context next to this Dockerfile:

```dockerfile
FROM registry.access.redhat.com/ubi10/ubi-minimal:10.2
COPY inspection-ca.pem /etc/pki/ca-trust/source/anchors/
RUN update-ca-trust extract
```

## Sidecar layout

`agentcon run` with a `bouncer` section starts two containers and two networks.
The sidecar is PID 1 running `bouncer serve`.
Secrets are not passed as container environment variables.
After the management API is up, the host PUTs secrets into memory.

The rest of this section is the equivalent Docker commands, for debugging or a custom runner.

### Networks

Create an internal agent network and an external management network.

```bash
docker network create --internal agentcon-github-com-example-agentcon-deadbeef-agent
docker network create agentcon-github-com-example-agentcon-deadbeef-ext
```

Inspect each network for its subnet.
Those CIDRs become `AGENT_NETWORK` and `MANAGEMENT_NETWORK` on the sidecar.

Under [Docker-outside-of-Docker](../README.md#docker-outside-of-docker), `DOOD_NETWORK` takes the place of the external network.
The sidecar then publishes no port, and the management API is at the sidecar's container name on port `8228`.

### Sidecar payload

Pack files at `/opt/agentcon` and copy them into a created, not yet started, container.

Sidecar tar:

- `/opt/agentcon/config.yaml`
- `/opt/agentcon/ts/` from overlay `ts/` trees
- `/opt/agentcon/state/admin-token`
- `/opt/agentcon/bin/agentcon`

Agent tar, copied later:

- `/opt/agentcon/bin/agentcon`
- `/opt/agentcon/ca.pem`
- `/opt/agentcon/ca-bundle.pem`
- `/opt/agentcon/ssh/config`
- `/opt/agentcon/ssh/known_hosts`
- `/opt/agentcon/bin/git-sign`

```bash
docker create \
  --name agentcon-github-com-example-agentcon-deadbeef-bouncer \
  --user 1000:1000 \
  --group-add 0 \
  --network agentcon-github-com-example-agentcon-deadbeef-ext \
  --publish 127.0.0.1:8228:8228 \
  --add-host host.docker.internal:host-gateway \
  --entrypoint /opt/agentcon/bin/agentcon \
  -e AGENT_NETWORK=10.1.0.0/16 \
  -e MANAGEMENT_NETWORK=10.2.0.0/16 \
  -e MANAGEMENT_PORT=8228 \
  registry.access.redhat.com/ubi10/ubi-minimal:10.2 \
  bouncer serve \
    --file /opt/agentcon/config.yaml \
    --state-dir /opt/agentcon/state \
    --log bouncer=info \
    --log audit=info \
    --log-format pretty

docker network connect agentcon-github-com-example-agentcon-deadbeef-agent \
  agentcon-github-com-example-agentcon-deadbeef-bouncer
docker cp sidecar.tar agentcon-github-com-example-agentcon-deadbeef-bouncer:/
docker start agentcon-github-com-example-agentcon-deadbeef-bouncer
```

Use your `sidecar` image in place of the stock image when one is configured.
`serve` is PID 1.
The container exits if serve exits.
Do not pass credential values with `-e`.
When the policy uses `source: ssh-agent`, add `--volume "${SSH_AUTH_SOCK}:/opt/agentcon/ssh-agent.sock"` and `-e SSH_AUTH_SOCK=/opt/agentcon/ssh-agent.sock`.

### Management API

Wait until status answers.

```bash
TOKEN=$(tar -xOf sidecar.tar opt/agentcon/state/admin-token | tr -d '\n')
curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:8228/_bouncer/status
```

For each `source: env` slot, read the named variable on the host.
For each `file`, `keyring`, `command`, or `provided` slot, resolve the secret on the host.
PUT keys are `credential.slot` (for example `github-pat.token` and `deploy.private_key`).
Resolve the `password` of each Bitwarden account a slot uses the same way, keyed `bitwarden.<account>`, or with the env values for `source: env`.
If a `private_key` slot is passphrase-protected, prompt on the host TTY and PUT the unlocked PEM.
Other slots are not parsed as keys.
Fail on the host if any are missing.
PUT the maps after status is up.

```bash
curl -fsS -X PUT \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data "{\"SMOKE_TOKEN\":\"${SMOKE_TOKEN}\"}" \
  http://127.0.0.1:8228/_bouncer/credentials/sources/env

curl -fsS -X PUT \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"deploy.private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\\n..."}' \
  http://127.0.0.1:8228/_bouncer/credentials/provided
```

The daemon stores both maps in memory.
`source: env` lookups use the overlay first, then `os.LookupEnv`.
Lookups for other sources use the provided overlay first, then the configured source.
Bitwarden account passwords follow the same order.
If startup unlock failed, the env PUT starts it again, and status reports not ready until it finishes.

Bitwarden slots fetch the decrypted cipher JSON.
`path` is required.
Use a JSONPath such as `$.notes`, `$.login.password`, `$.sshKey.privateKey`, or `$.fields[?(@.name=='API Key')].value`.

If the policy uses `source: ssh-agent`, require `SSH_AUTH_SOCK` on the host before `docker create`.
Bind-mount it and set `SSH_AUTH_SOCK=/opt/agentcon/ssh-agent.sock` on the sidecar.
Do not copy private keys out of the agent.

Poll status until `ready` is true.
`ready` turns true once the sidecar has unlocked every Bitwarden vault the policy uses.
If `error` is set, startup failed.
While `pending_prompts` is above zero, list the [prompts](#prompts) and answer each one.
Do not send item secrets.
A new sidecar has no remembered Bitwarden device, so the first login often needs a 2FA code or the emailed new-device OTP.

```bash
curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:8228/_bouncer/prompts

curl -fsS -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"value":"..."}' \
  http://127.0.0.1:8228/_bouncer/prompts/PROMPT_ID
```

Answer a `confirm` with `{"allow":true}` or `{"allow":false}`, and add `"remember":true` to apply it for the session.
A `claim` prompt also lists `claim` (`{"type","value"}`) and `session_claims`, the session's claims grouped by type.
Answer it with `{"allow":true,"remember":true}` to add the claim, `{"allow":true}` to allow once, or `{"allow":false}` to deny.
A claim denial is never remembered, so `{"allow":false,"remember":true}` is refused.
`DELETE /_bouncer/prompts/PROMPT_ID` declines.
A password retry and a verification code each arrive as a new prompt.
The message names the method, `authenticator app` for TOTP or `new device email` for the code Bitwarden emails on an unknown device.
Read a code when its prompt appears, not before.
TOTP values expire.

Create a session, then fetch the CA.
`claims` is optional and seeds the session's [claims](bouncer-filters.md#session-claims).
Any invalid claim, or a set over a limit, rejects the whole request with 400 and creates no session.
Claims compare exactly, so the request body must also be valid UTF-8 with no unpaired surrogate escapes and no repeated member names.
`GET /_bouncer/sessions` lists each session with its current claims.
From Go, pass `mgmt.WithClaims` to `CreateSession`.

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"label":"agentcon","claims":{"repository":["gitlab.example.com/group/project"]}}' \
  http://127.0.0.1:8228/_bouncer/sessions

curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:8228/_bouncer/ca
```

### Agent container

Connect the agent only to the internal network.
Point proxy and CA paths at the sidecar IP on that network.
Copy the agent tar, then start.

```bash
PROXY=http://bouncer:SESSION@${SIDECAR_AGENT_IP}:8228
docker create \
  --name agentcon-github-com-example-agentcon-deadbeef-agent \
  --user 1000:1000 \
  --network agentcon-github-com-example-agentcon-deadbeef-agent \
  --env HTTPS_PROXY="${PROXY}" \
  --env https_proxy="${PROXY}" \
  --env HTTP_PROXY="${PROXY}" \
  --env http_proxy="${PROXY}" \
  --env NO_PROXY=localhost,127.0.0.1,::1 \
  --env no_proxy=localhost,127.0.0.1,::1 \
  pastdev.com/agentcon-cursor:latest

docker cp agent.tar agentcon-github-com-example-agentcon-deadbeef-agent:/
docker start -ai agentcon-github-com-example-agentcon-deadbeef-agent
```

`agentcon run` also sets `NODE_USE_ENV_PROXY=1` so Node 24+ honors those proxy vars.
It sets `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `BOUNCER_*`, credential placeholders, and the other session variables.
`GIT_SSH_COMMAND` invokes `/usr/bin/ssh -F /opt/agentcon/ssh/config`.
The SSH config `ProxyCommand` is `agentcon bouncer ssh-connect`.

Extra hosts belong on the sidecar only.
The agent reaches the outside through the proxy.

## Embedding

Go programs that run the sidecar themselves can reuse these steps instead of calling the management API by hand.
Creating the containers stays with the caller.

| Package | Use |
|---|---|
| `pkg/bouncer/host` | `Check`, `CheckPromptable`, `PrepareCredentials`, `WaitReady`, `NotifyPrompts`, `AnswerAtTerminal`, `AgentLayout`, `WriteAgentPayload`, `AgentEnv` |
| `pkg/bouncer/mgmt` | the [management API](#management-api) client |
| `pkg/bouncer/prompt` | pending prompts and answers |
| `pkg/bouncer/envexport` | the agent environment from session values |
| `pkg/bouncer/crederr` | `CommandError` and its operator-only stderr |
| `pkg/bouncertest` | `Run` policy tests and `WriteTAP` |

In order:

1. `host.Check` and `host.CheckPromptable` reject a bad policy before slow setup.
2. `host.PrepareCredentials` resolves host-side values.
   It never changes its inputs and returns nothing on error.
3. Create the sidecar, and bind `Credentials.SSHAuthSock` at `host.SidecarSSHAuthSock` when it is set.
4. `mgmt.New`, then `PutEnv` and `PutProvided` with the prepared maps.
5. `host.WaitReady` answers prompts at a terminal until the sidecar is ready.
6. `CreateSession` and `Trust`, then `host.WriteAgentPayload` and `host.AgentEnv` for the agent container.
7. Run `host.NotifyPrompts` under a context cancelled when the agent exits.

`AgentLayout` paths are Linux paths in the agent container.
`Normalize` fills empty fields from `DefaultAgentLayout` and rejects relative, unclean, overlapping, or hard-to-quote paths.

## Agent tunnels

`run` unions the active agent's `tunnel` list onto each bouncer profile that does not `extends` another profile.
Child profiles inherit that list.

The active agent is `--agent`, then `contexts.<name>.agent`.

If a vendor host is missing, add it on the agent or on the profile:

```yaml
agents:
  cursor:
    tunnel:
      - extra.vendor.example
bouncers:
  github:
    profiles:
      locked-down:
        unmatched: deny
        tunnel:
          - extra.vendor.example
```

Example lists are in [cursor.md](cursor.md) and [claude.md](claude.md).
