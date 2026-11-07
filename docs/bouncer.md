# Bouncer

The [README](../README.md) covers enabling bouncer and a minimal GitHub overlay.
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

`github_repo` is a YAML list of `owner/repo`.
`github_subpaths` limits REST paths under that repo.
Git traffic never matches a subpath rule.

TypeScript filters attach to a rule.
They run only after that rule matches.
A filter may `allow`, `deny`, or `ask`.
Put files under `ts/` next to the config.
`agentcon bouncer check` compiles them.

Cursor product hosts are unioned onto root profiles from `pkg/harness/<name>/default.yml`.
`agentcon config` prints that list under `harnesses`.
Setting `harnesses.cursor.tunnel` in your own config replaces the builtin list.

## Credentials

Each credential is a composite of slots (`username`, `password`, `token`, `private_key`, `certificate`).
Each slot is a source plus an optional JSONPath on the source payload.

`source: env` is a map of environment variable names.
`file`, `keyring`, `command`, and `provided` are a map of `credential.slot` keys (for example `github-pat.token`).

Bitwarden stays an unlock, not a key/value dump.
Identity lives in the policy YAML.
The host prompts for the master password and POSTs `/_bouncer/credentials/sources/bitwarden/unlock`.

`source: ssh-agent` is a socket, not a PUT.
Bind-mount `$SSH_AUTH_SOCK` at `/opt/agentcon/ssh-agent.sock` and set that path on the sidecar.

## Sessions

`agentcon run` mints an 8-character hex session slug before it creates Docker objects.
Container and network names are `agentcon-<bounded>-<slug>-<role>`.
`<bounded>` is the project path relative to the context root, made docker-safe, and left-truncated so the full name stays at 63 characters.
`<role>` is `agent`, `bouncer`, or `ext`.

Host discovery files are `~/.local/state/agentcon/running/<slug>.yml`.
`run` prints `agentcon session <slug> project <project>`.

Decisions are appended to the sidecar audit log even when `--quiet` hides them on the TTY.

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
    --quiet

docker network connect agentcon-github-com-example-agentcon-deadbeef-agent \
  agentcon-github-com-example-agentcon-deadbeef-bouncer
docker cp sidecar.tar agentcon-github-com-example-agentcon-deadbeef-bouncer:/
docker start agentcon-github-com-example-agentcon-deadbeef-bouncer
```

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

If status reports `bitwarden_pending`, unlock the vault.
Do not send item secrets.
A new sidecar has no remembered Bitwarden device, so the first login often needs a 2FA code or the emailed new-device OTP.

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"password":"..."}' \
  http://127.0.0.1:8228/_bouncer/credentials/sources/bitwarden/unlock
```

If that responds `409` with `{"error":"need_code","method":"..."}`, prompt for the code and POST again with `password` and `code`.
`method` is `authenticator app` for TOTP, or `new device email` for the code Bitwarden emails on an unknown device.
Ask for the code at submit time, not before `serve` is up.
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
  pastdev.com/agentcon:latest

docker cp agent.tar agentcon-github-com-example-agentcon-deadbeef-agent:/
docker start -ai agentcon-github-com-example-agentcon-deadbeef-agent
```

`agentcon run` also sets `NODE_USE_ENV_PROXY=1` so Node 24+ honors those proxy vars.
It sets `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `BOUNCER_*`, credential placeholders, and the other session variables.
`GIT_SSH_COMMAND` invokes `/usr/bin/ssh -F /opt/agentcon/ssh/config`.
The SSH config `ProxyCommand` is `agentcon bouncer ssh-connect`.

Extra hosts belong on the sidecar only.
The agent reaches the outside through the proxy.

## Harness tunnels

Builtin harness host lists live in `pkg/harness/<name>/default.yml` and load as the first config source.
`run` unions only the active harness list onto each bouncer profile that does not `extends` another profile.
Child profiles inherit that list.

The active harness is `--harness`, then `$HARNESS`, then `contexts.<name>.harness`, then `cursor`.

If a vendor host is missing, add it on the profile:

```yaml
contexts:
  git:
    bouncer:
      profiles:
        locked-down:
          unmatched: deny
          tunnel:
            - extra.vendor.example
```

When the gap belongs in the product, add it to `pkg/harness/<name>/default.yml`.
