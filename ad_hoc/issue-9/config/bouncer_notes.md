# GitHub allowlist overlay

This directory is an `agentcon.d` overlay for the `git` context, scoped to `pastdev/agentcon`.
Extract it onto the host config dir:

```bash
tar --directory ad_hoc/issue-9/config --create . \
  | tar --directory ~/.config/agentcon.d --extract
```

That writes `bouncer.yaml`, `bouncer_notes.md`, and `ts/` next to your existing context files.
`bouncer.yaml` only sets `contexts.git.bouncer`.
It does not set `image` or `root`.
If your context is not named `git`, rename that key before extracting.

Credentials come from sidecar `source: bitwarden`, not `rbw` on the host.
`agentcon run` prompts for the vault password (and TOTP if needed) and POSTs unlock.
Each slot is a source plus JSONPath on the decrypted cipher.
The PAT is Secure Note `pat-github-agent`, `path: $.notes`.
The SSH key is item `ssh-github`, `path: $.sshKey.privateKey`.
Both use `agent@pastdev.com`.
`agent-bouncer-smoke-test` is a login item for the smoke binary, not this session.

`unmatched: tunnel` so arbitrary HTTPS (search, docs, packages) is spliced through.
github.com and api.github.com match the GitHub `http` entry, so they are intercepted.
Rules that match still inject the PAT.
Leftover paths on those hosts are forwarded with placeholder auth stripped, not denied.
HTTPS and SSH are separate `http` and `ssh` lists.
They do not share REST rules.
Each copies `git-protect-branches.ts` onto its git allow rule with the same `branches` config.

`github_repo` is always a list of `owner/repo`.
`github_subpaths` are globs under `/repos/owner/repo/` (`""` is the repo itself).
Git does not match a rule that has subpaths.
A second identical repo is another entry in `github_repo`, not a copy of the rules.
`github_repo` without subpaths would allow DELETE, secrets, collaborators, and deploy keys.
This sketch uses subpaths for fetch, PR conversation, and creating an issue.
It does not match GraphQL.
A POST to `/graphql` is allowed so `gh` works.
That rule runs the GraphQL guard and `require-approval-merge.ts`.
`mergePullRequest` is left out of the guard deny list so the merge filter can ask.
REST merge uses the YAML `action: ask` rule, not that filter.
The PAT needs Issues: Read and write for `gh issue create`.
GraphQL `createIssue` is not on the deny list.

SSH is `allow: [git]` only.
No shell, no exec, no forwards.
`host_key` is GitHub's published ed25519 key so the sidecar does not need the host `known_hosts`.
