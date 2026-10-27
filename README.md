# agentcon

Containerized agent workspace.

The host CLI is `agentcon run`.
Build the image, then configure a context with an `image` and a host `root`.

```bash
docker build --progress plain --tag pastdev.com/agentcon:latest image/base/
```

Config is loaded from `/etc/agentcon.d`, `~/.config/agentcon.d`, and `./agentcon.d`.

```yaml
default_context: git
contexts:
  git:
    image: pastdev.com/agentcon:latest
    root: ~/git
```

`agentcon run` uses `default_context`.
`agentcon run NAME` uses that context.
Cwd must be at or under the selected `root`.
It bind-mounts `root` at `/workspace` and starts the harness.
Harness state is bind-mounted from the host to `/agent`.
The container sets `AGENTCON_HOST_ROOT` to that host `root`.

## Handoff scratch space

Agents write host-side handoff scripts under `.agentcon/` at the project root.
That directory is gitignored.
It is scratch space for the agent.

The agent process cannot use host credentials or Docker.
When a step needs those, the agent writes `.agentcon/<use_case>.handoff.sh`.
You review and run that script.
Results go to `.agentcon/<use_case>.handoff.result`.

## Optional CLI allowlist

`~/.cursor` inside the container is your host `~/.cursor`.
The image does not edit that file.

If you want the agent to read and write `.agentcon/` without approval
prompts, add allow rules in `~/.cursor/cli-config.json`.

```json
{
  "permissions": {
    "allow": [
      "Read(.agentcon/**)",
      "Write(.agentcon/**)",
      "Delete(.agentcon/**)"
    ]
  }
}
```

Restart the agent session after you change that file.
Exact pattern syntax can vary by CLI version.
Keep `approvalMode` as `allowlist` unless you intend a broader grant.
