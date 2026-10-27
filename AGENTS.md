# AGENTS

Guidance for automated agents working in this repository.
Humans should be able to review this file as ordinary project documentation.

## Project

This repository builds and runs a containerized agent workspace (`agentcon`).
The host launches the image with `agentcon run`.
The image entrypoint prepares a writable home for an arbitrary container UID.
It links harness state onto a bind mount under `/agent`.
It then starts the selected harness.

Treat `/workspace` as the mounted host workspace tree.
The container sets `AGENTCON_HOST_ROOT` to the host path of that bind.
Prefer changing files under this project's root unless the user asks otherwise.

Do not change this repository without explicit approval of the proposed diff.
That includes creating, editing, or deleting `AGENTS.md`.

## Shared

### Development process

Start with a conversation that captures the bug or feature requirements.
After a brief discussion, create an issue on the remote repository.

Create a local `ad_hoc/issue-<num>/` folder only when needed.
That folder may hold `<use_case>.plan.md` and short-lived notes or prototypes.
Choose a short `<use_case>` that names the feature or bug fix.
Use `notes.md` for context that does not belong in the README.

Continue discussion until the design and process for the change are settled.
For significant work, use `<use_case>.plan.md` to capture clear guidance.
Resolve open questions before treating a plan as complete.
Do not leave unanswered questions in `<use_case>.plan.md`.

Treat questions as inquiry, not as a cue to start work.
That includes a statement ending in `..., right?` or similar.
Think about the claim.
Give pushback when it is wrong.
Propose a next step only after we agree.

Default to proposing changes and waiting for approval before applying them.
The user may grant permission to implement a full feature at once.

After implementation, ensure tests, lint, and compile succeed.
Run smoke checks that verify end-to-end behavior when practical.
Then use the handoff process for merge requests or other elevated actions.

After merge, when asked to close out the conversation, remove ephemeral files.
That includes `ad_hoc/` content created for the work.
It also includes leftover handoff scripts, test artifacts, and local branches.
Then propose `AGENTS.md` updates from issues found during this work.

### Go layout

Code under `cmd/**` is for commands only.
Commands may only process user input and format user output.
They may call services under `pkg/**`.
They must not hold domain logic that belongs in `pkg/**`.

Do not import `pkg/config` from other packages under `pkg/**`.
Config objects stay in `pkg/config`.
That package is a factory.
It maps loaded config into the types each service package already owns.
A service package receives only the values it needs at that boundary.

### Bash

Follow the Google Shell Style Guide.
Use `function <name> {` instead of `<name>() {`.

### Go style

Do not use `if err := <thing>; err != nil` unless `<thing>` is only validation.
Keep real actions on their own line so later readers can see them.

### Handoff process

The agent runs in a container without credentials or elevated host access.
Actions that need credentials or elevated access require a handoff script.
Examples include `git push`, merge request creation, and Docker on the host.
When a handoff script must name a host path, use `AGENTCON_HOST_ROOT` with the path under `/workspace`.

Keep handoff artifacts under `.agentcon/` at the project root.
That directory must be listed in `.gitignore`.
Write the script as `.agentcon/<use_case>.handoff.sh`.
Choose a `<use_case>` that describes the goal.
Ask the user to review and run the script.
Do not run credentialed or elevated host actions yourself.

The script must write results only through an intentional `write_result` helper.
Register that helper with `trap` on `EXIT` so results are always written.
Do not redirect the full script transcript into the result file.
Put only the fields needed for the next agent step into the result file.
Prefer streaming long-running command output to the terminal as it runs.
A typical pattern is piping through `tee` for the user display only.

After the user runs the script, they will say when results are ready to read.
Do not put passwords, keys, tokens, or other secrets in the result file.
Do not exfiltrate secrets by any other means.
Remove handoff scripts and result files when the use case is finished.

### Maintaining this file

Keep harness and model product names out of this file when possible.
Prefer rules that remain valid across agent products.

Propose changes to `AGENTS.md` before applying them.
Grow this file only when a recurring rule would otherwise be restated in chat.

### Markdown

Wrap lines at sentence boundaries.
Put each sentence on its own line.

Do not use emdashes.

Do not use semicolons to join English clauses.
Prefer two sentences.
When a list is not involved, rephrase with commas or conjunctions.
