# Bouncer run layout

`agentcon run` with a `bouncer` section starts two containers and two networks.
The sidecar is PID 1 running `bouncer serve`.
Secrets are not passed as container environment variables.
After the management API is up, the host PUTs secrets into memory.

`source: env` is a map of environment variable names.
`file`, `keyring`, `command`, and `provided` are a map of credential names.

Bitwarden stays an unlock, not a key/value dump.
Identity lives in the policy YAML.
The host prompts for the master password and POSTs `/_bouncer/credentials/sources/bitwarden/unlock`.

`source: ssh-agent` is a socket, not a PUT.
Bind-mount `$SSH_AUTH_SOCK` at `/opt/agentcon/ssh-agent.sock` and set that path on the sidecar.

## Networks

Create an internal agent network and an external management network.

```bash
docker network create --internal agentcon-ctx-agent
docker network create agentcon-ctx-ext
```

Inspect each network for its subnet.
Those CIDRs become `AGENT_NETWORK` and `MANAGEMENT_NETWORK` on the sidecar.

## Sidecar payload

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
  --name agentcon-ctx-bouncer \
  --user 1000:1000 \
  --group-add 0 \
  --network agentcon-ctx-ext \
  --publish 127.0.0.1:8228:8228 \
  --add-host host.docker.internal:host-gateway \
  --entrypoint /opt/agentcon/bin/agentcon \
  -e AGENT_NETWORK=10.1.0.0/16 \
  -e MANAGEMENT_NETWORK=10.2.0.0/16 \
  -e MANAGEMENT_PORT=8228 \
  pastdev.com/agentcon:latest \
  bouncer serve \
    --file /opt/agentcon/config.yaml \
    --state-dir /opt/agentcon/state \
    --quiet

docker network connect agentcon-ctx-agent agentcon-ctx-bouncer
docker cp sidecar.tar agentcon-ctx-bouncer:/
docker start agentcon-ctx-bouncer
```

`serve` is PID 1.
The container exits if serve exits.
Do not pass credential values with `-e`.
When the policy uses `source: ssh-agent`, add `--volume "${SSH_AUTH_SOCK}:/opt/agentcon/ssh-agent.sock"` and `-e SSH_AUTH_SOCK=/opt/agentcon/ssh-agent.sock`.

## Management API

Wait until status answers.

```bash
TOKEN=$(tar -xOf sidecar.tar opt/agentcon/state/admin-token | tr -d '\n')
curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:8228/_bouncer/status
```

For each `source: env` credential, read the named variable on the host.
For each `file`, `keyring`, `command`, or `provided` credential, resolve the secret on the host.
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
  --data '{"deploy-key":"-----BEGIN OPENSSH PRIVATE KEY-----\\n..."}' \
  http://127.0.0.1:8228/_bouncer/credentials/provided
```

The daemon stores both maps in memory.
`source: env` lookups use the overlay first, then `os.LookupEnv`.
Lookups for other sources use the provided overlay first, then the configured source.

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

## Agent container

Connect the agent only to the internal network.
Point proxy and CA paths at the sidecar IP on that network.
Copy the agent tar, then start.

```bash
PROXY=http://bouncer:SESSION@${SIDECAR_AGENT_IP}:8228
docker create \
  --name agentcon-ctx-agent \
  --user 1000:1000 \
  --network agentcon-ctx-agent \
  --env HTTPS_PROXY="${PROXY}" \
  --env https_proxy="${PROXY}" \
  --env HTTP_PROXY="${PROXY}" \
  --env http_proxy="${PROXY}" \
  --env NO_PROXY=localhost,127.0.0.1,::1 \
  --env no_proxy=localhost,127.0.0.1,::1 \
  pastdev.com/agentcon:latest

docker cp agent.tar agentcon-ctx-agent:/
docker start -ai agentcon-ctx-agent
```

`agentcon run` also sets `NODE_USE_ENV_PROXY=1` so Node 24+ honors those proxy vars.
It sets `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `BOUNCER_*`, credential placeholders, and the other session variables.

Extra hosts belong on the sidecar only.
The agent reaches the outside through the proxy.

## Harness tunnels

Builtin harness host lists live in `pkg/harness/<name>/default.yml` and load as the first config source.
`agentcon config` always prints every embedded harness under `harnesses`.
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

`agentcon config` will still show the builtin list under `harnesses.cursor.tunnel`.
The sidecar policy has both.
When the gap belongs in the product, add it to `pkg/harness/<name>/default.yml`.

Setting `harnesses.cursor.tunnel` in your own agentcon config replaces the builtin list.
That is a replace, not an append.
