# GitHub

Letting an agent push to a GitHub repo through Bouncer also lets it run code in that repo's CI.
Bouncer sees the push, but not what CI does with it.
This page lists the settings known to keep CI from handing the agent anything its token cannot already reach.
[Scenarios](#scenarios) shows how each setting can be undone.

## Agent token

Use a fine-grained personal access token limited to the repositories the agent works in.
Grant only these repository permissions:

- Contents: read and write
- Issues: read and write
- Pull requests: read and write
- Metadata: read

Do not grant Workflows.
A token with Workflows can push a new workflow that reads every secret the repo can see.
Do not grant Administration, Secrets, Variables, Environments, or Actions either.

A fine-grained token acts as the user who owns it.
Keep that user off the bypass list of every ruleset the agent must not get past.

## Workflows

A token without Workflows cannot change `.github/workflows/`, but it can change any code those workflows run.
That includes tests, build scripts, and anything a `run:` step calls.

For each workflow that runs on a branch or pull request the agent can push:

- Pass no secret to a step that runs repo code.
  This covers `env:`, `with:`, and arguments that reference `secrets.*`.
  It includes `pull_request_target` and `workflow_run` workflows, as [Trusted workflows that run pushed code](#trusted-workflows-that-run-pushed-code) shows.
- Give `GITHUB_TOKEN` only read permissions.
  Set `permissions: contents: read` at the top of the workflow, and raise it only in jobs that run on refs the agent cannot push, such as release tags.

Set the repository default under Settings, Actions, General, Workflow permissions, to read only.

## Secrets

Repository secrets and organization secrets cannot be limited to branches.
Any workflow in the repo can read them.

- Do not add repository secrets to a repo the agent can push to, unless no workflow passes them to repo code.
- Share organization secrets with selected repositories only, and leave out every repo an agent can push to.
- Put secrets that deployments need in an environment, with deployment branches limited to branches the agent cannot push and required reviewers.

## Branch rules

The `github-branch-rules.ts` filter in [the reference policy](bouncer/reference/bouncers.yaml) asks GitHub which rulesets apply to each pushed branch and denies the push before it leaves Bouncer.
It sees rulesets only, not classic branch protection.
GitHub still enforces both.

## Scenarios

Bouncer cannot check any of these.
It cannot read a fine-grained token's permissions, and it cannot tell what a workflow does with the code the agent pushed.
Each scenario relies on the settings above.

### Trusted workflows that run pushed code

`pull_request_target` and `workflow_run` run the workflow file from the default branch, so the agent cannot edit the workflow that runs.
Both run with secrets.
They are only as safe as the code they run.

A `pull_request_target` workflow that checks out the pull request runs the agent's code:

```yaml
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
        env:
          CODECOV_TOKEN: ${{ secrets.CODECOV_TOKEN }}
```

The agent pushes a branch whose `Makefile` sends `$CODECOV_TOKEN` to a host it controls, then opens a pull request.
The workflow from the default branch runs that `Makefile` with the secret set.
The agent never changed `.github/workflows/`.

A `workflow_run` workflow that uses a pushed run's artifacts has the same problem.
The pushed code decides what the artifact holds.
A follow-up workflow that runs a script from it, or installs dependencies from a manifest in it, runs the agent's code with the follow-up's secrets.

### A secret or permission added later

These settings live in GitHub, not in Bouncer.
A change made for another reason can expose a secret to the agent's next push, and nothing warns anyone.

#### An organization secret shared with all repositories

Someone adds `NPM_TOKEN` to the organization to publish from another repo and leaves its visibility at all repositories.
It is now one `${{ secrets.NPM_TOKEN }}` away from any job in the agent's repo.

#### A workflow step that gains a secret

Someone adds code scanning to a test job.

```yaml
- run: go test ./... && sonar-scanner
  env:
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

On the agent's next push, `go test` runs the agent's test code with `SONAR_TOKEN` set.

#### A changed default

Someone sets Workflow permissions to read and write.
Every workflow without its own `permissions:` block now gets a `GITHUB_TOKEN` that can push, from CI, where Bouncer does not see it.

#### Review after changes

Review the settings on this page whenever a repo's workflows, secrets, or organization sharing change.
