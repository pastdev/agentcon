# Bouncer

The [README](../README.md) getting-started path ends with a GitHub overlay you can add after a session already starts.
This page is policy shape, credentials, sessions, and the sidecar layout `agentcon run` implements.

`agentcon bouncer --help` lists flags.
Host commands pick a live session by `--slug`, then `--project`, then cwd.

## Policy

`default_profile` is required.
A session with no profile uses that name.

Each HTTP or SSH service is a host list, an optional credential, inject rules, and an ordered `rules` list.
The first matching rule wins.
`unmatched` applies to hosts that no service claims.
`tunnel` splices those hosts.
`deny` blocks them.
Leftover paths on an intercepted host skip the credential and strip placeholder auth.

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
Identity stays in the YAML.
The sidecar raises a [prompt](#prompts) for the master password, and another for a verification code when the account asks for one.
`agentcon run` answers them at its terminal and starts the agent once every vault is unlocked.
The master password is asked for up to three times.

Required: `email`, `item`, `path`.
Optional: `server` (default bitwarden.com), `folder` (unset), `password_env` (unset, so the sidecar prompts).

The named item must already exist in that account's vault.
`path` must select exactly one string from the decrypted cipher JSON.
Examples: `$.notes`, `$.login.password`, `$.login.username`, `$.sshKey.privateKey`, `$.fields[?(@.name=='API Key')].value`.

```yaml
credentials:
  github-pat:
    token:
      source: bitwarden
      email: you@example.com
      item: pat-github-agent
      path: $.notes
    export_env: [GH_TOKEN, GITHUB_TOKEN]
  gitlab-login:
    username:
      source: bitwarden
      email: you@example.com
      item: GitLab
      path: $.login.username
    password:
      source: bitwarden
      email: you@example.com
      item: GitLab
      path: $.login.password
```

### env

Reads a host environment variable.
`agentcon run` PUTs those names after status is up.

Required: `env`.

```yaml
credentials:
  slack:
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
    token:
      source: command
      command: [gh, auth, token]
    cache: 15m
    export_env: [GH_TOKEN]
```

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
    private_key:
      source: provided
```

A service names a credential, then `inject` says how it is attached:

```yaml
profiles:
  default:
    unmatched: tunnel
    http:
      - name: github
        hosts: [github.com, api.github.com]
        credential: github-pat
        inject:
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

That writes `bouncers.yaml` and `ts/` next to `agents.yaml` and `contexts.yaml`.
It does not set `agent` or `root`.
If your context is not named `git`, rename that key in `bouncers.yaml`.
Add another repo by appending to each `github_repo` list, not by copying the rules.

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

## Prompts

The sidecar asks a human through prompts.
Filter `ask()` and rule `action: ask` raise one, and so does a Bitwarden vault that needs a master password or verification code.
Each prompt has an id, a kind, a source, and a message.

| Kind | Raised for | Answer |
| --- | --- | --- |
| `confirm` | an `ask` approval | allow or deny, once or for the session |
| `text` | a verification code | a line of text |
| `secret` | a master password | a value read without echo |

Several places can answer a pending prompt.

- `agentcon run` answers prompts at its terminal while the sidecar starts.
- An interactive `agentcon bouncer serve` shows prompts one at a time.
- `agentcon bouncer prompts` lists them from another terminal, and `agentcon bouncer answer <id>` answers one there.
- `agentcon bouncer approve <id>` and `agentcon bouncer deny <id>` answer a `confirm`, and `--session` remembers the answer.
- `agentcon bouncer decline <id>` refuses to answer a prompt of any kind.

At a terminal, Enter answers.
An empty `text` or `secret` declines, and so does Ctrl-C.
A declined or expired approval is a deny.
A declined master password fails that vault's unlock.

A `secret` answer goes only to the code that asked for it.
It is never logged, remembered, or shown in listings, events, or notifications.
Filters and rules raise only `confirm` prompts, so a request can never ask the human for a password.

The `prompts` block configures them.

```yaml
prompts:
  timeout: 2m      # unanswered prompts expire after this
  notify: true     # desktop notification for each pending prompt
  terminal: true   # prompt in an interactive `bouncer serve` terminal
  cli: true        # allow answering through the management API
```

`cli: false` stops `agentcon run` and the `agentcon bouncer` commands from answering.
`agentcon run` refuses a policy with `cli: false` when a Bitwarden credential has no `password_env`, because nothing could unlock it.

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
`DELETE /_bouncer/prompts/PROMPT_ID` declines.
A password retry and a verification code each arrive as a new prompt.
The message names the method, `authenticator app` for TOTP or `new device email` for the code Bitwarden emails on an unknown device.
Read a code when its prompt appears, not before.
TOTP values expire.

Create a session, then fetch the CA.

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"label":"agentcon"}' \
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

A Cursor example list is in [cursor.md](cursor.md).
