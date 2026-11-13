# Public Bouncer host APIs for external lifecycle managers

Issue: https://github.com/pastdev/agentcon/issues/32
Status: Implementation requirements, this document does not implement the API extraction.

## Context

Expose Bouncer's host-side operations as public Go services that can manage the published executable independently of `agentcon run`.
Support HTTP, HTTPS, SSH, and embedded TypeScript filters with the existing behavior.
Keep configuration code and the executable compatible by publishing both under the same module/release version.
The published executable remains the sidecar entry point.

Preserve Bouncer configuration behavior when a caller loads the same policy under a different enclosing configuration node.
This includes ordered overlays, map merging, slice replacement, directory templates, profiles, filter assets, test specs, and materialization.

Public configuration and materialization APIs already support loading policy from another Go module.
The remaining requirements concern reusable host operations, test-command integration, and release artifacts.
The inspected baseline is agentcon `v0.2.0` at commit `319810a6bbfa2902fde0035260804fd37998b041`.

## Design history

- Running `agentcon run` would adopt agentcon's whole agent and container lifecycle.
  Expose reusable host operations so callers can compose their own lifecycle.
- Copying internal helpers into other applications would create independent credential, prompt, and environment behavior.
  Expose one shared implementation.
- Moving the daemon out of `internal` is unnecessary.
  The published executable remains the sidecar entry point.
- Rebuilding the sidecar executable from the module source duplicates upstream release work.
  Consume the matching published release binary instead.
- Invoking `agentcon bouncer test` with a different root configuration cannot work unchanged.
  That command loads agentcon contexts and rejects standalone `--file` input.
  Expose reusable runner and output services for native consumer commands.

## Existing public configuration APIs

Retain the behavior of `pkg/bouncer/config`, `pkg/config.BouncerSpec`, `Config.MaterializeBouncer`, `Config.BouncerTests`, and `pkg/bouncertest`.
An external consumer can map its selected Bouncer entry to these factories without adopting agentcon's complete agent/context model.
If a smaller configuration factory is extracted, make agentcon use it too and preserve these behaviors.

Keep source-directory provenance available through the ordered configloader sources.
Explicit configuration files contribute their parent directories, and directory sources contribute their directories as they do today.
Keep TypeScript overlay selection and path rewriting shared, including relative imports and supported package dependencies.
Keep test-directory configuration host-side rather than including it in the daemon policy.

## Required public host operations

Provide public entry points for the following operations independently of `agentcon run`.
Exact exported names and package boundaries are implementation choices.
Public argument and response types must be usable and nameable from a different Go module without importing an `internal` path.
Keep the CLI thin and make agentcon itself use the same shared services.
Keep root configuration objects in the configuration factory rather than importing `pkg/config` into service packages.

### Credential preparation

Accept materialized policy, optional environment overrides, provided credential slots, and terminal input/output.
Return host-resolved source values and the required sidecar-only SSH-agent socket mapping.
Preserve all sources, slot names, JSONPath selection, encrypted-key handling, cache behavior, promptability validation, and existing platform restrictions.
Keep credential values in memory and out of container arguments, container environment, image layers, policy files, diagnostics, and agent-visible payloads.

Share the implementations currently located in:

- `pkg/run/env.go`, including `hostEnvCreds`.
- `pkg/run/creds.go`, including `hostProvidedCreds` and `hostSSHAuthSock`.
- `pkg/run/sshkey.go`, including encrypted private-key preparation.
- `pkg/run/prompts.go`, including `checkPromptable`.

Sidecar Bitwarden unlock and verification prompts must retain their existing behavior.
Do not force consumers to replace native Bouncer credentials with a separate credential system.

### Management client and human prompts

Expose the typed client currently in `internal/bouncer/mgmt`, or a public facade that delegates to it.
Support status, public trust retrieval, session creation/listing/revocation, environment/provided credential updates, reload, prompt listing, prompt answers, and prompt decline.
Expose the relevant session, trust, status, and prompt types publicly.
Moving only the client package is insufficient if its public signatures still require internal types.

Expose the readiness and startup-prompt loop currently used by `pkg/run/prompts.go:waitReady`.
Expose terminal answering behavior from `internal/bouncer/app/answer.go:AnswerAtTerminal`.
Allow consumers to supply their own command names in human-facing hints while preserving secret input, approval scope, timeout, expiry, and decline semantics.
Honor cancellation and retain useful operation errors without exposing secrets.

### Agent payload and environment

Expose the agent payload writer currently implemented by `pkg/run/sidecar.go:writeAgentPayload`.
It must retain SSH configuration, strict host verification, public CA and combined trust bundles, ownership, modes, and installation of the matching executable as the SSH connection helper.
Allow the caller to supply the executable obtained from the sidecar image or published release, without compiling another helper.

Expose the environment builder currently in `internal/bouncer/envexport` through a public service.
Accept caller-selected agent-facing addresses and payload paths.
Preserve proxy variable casing, Node proxy support, combined CA bundles, credential placeholders, SSH command configuration, and Bouncer session variables.

### Policy compilation

Expose the policy compilation service currently implemented by `internal/bouncer/app/check.go:Check`.
External lifecycle managers need to validate policy and compile filters before changing a running sidecar.
Preserve upstream validation and compilation diagnostics.

## Reusable policy-test command services

Expose the services needed to run the same policy tests from a caller's own command and configuration loader.
The command should be able to follow this sequence:

1. Load the consumer configuration with the shared source and overlay behavior.
2. Select the Bouncer spec and its test directory.
3. Materialize the same policy and TypeScript tree using the upstream factories.
4. Run the existing upstream policy/filter test runner in a temporary layout.
5. Print the shared TAP report and return failure when loading, running, formatting, or test assertions fail.
6. Remove the temporary layout on success and failure.

`pkg/bouncertest.Suite` and `pkg/bouncertest.Run` already cover runner invocation independently of agentcon's root config.
Retain that public entry point and its offline behavior.
Expose the result types referenced by `SpecReport.Results`, which currently come from `internal/bouncer/testrunner`.
Make callers able to construct, inspect, and test reports without naming internal types.

Move the TAP implementation from `cmd/agentcon/bouncer/tap.go` into a public report service, for example `pkg/bouncertest.WriteTAP(io.Writer, Report)`.
Make `agentcon bouncer test` call that same service.
Preserve TAP 14 output, ordering, YAML diagnostics, step names, filter logs, failed-spec reporting, and writer error handling.
Keep pass/fail status available independently of output formatting so each CLI controls its own exit status without parsing text.
No alternative test-spec syntax or duplicated TAP implementation should be required by a caller.

## Release artifacts

Publish native Linux amd64 and Linux arm64 executables under unambiguous asset names.
Select the sidecar's Linux architecture independently of the host operating system.
The current `v0.2.0` release's `agentcon-linux` executable is amd64 only.
Keep legacy filenames as compatibility aliases if needed.

Provide checksums or document how consumers should use GitHub's SHA-256 asset digests for verified downloads.
Publish the reusable Go APIs and supported executables under the same release tag.
The consumer's selected Go module version will identify the executable download and sidecar image version.
No particular next version number is prescribed.

## Out of scope

- Implementing an application's lifecycle or CLI inside agentcon.
- Changing the existing policy language, test specs, credential model, or filter execution behavior.
- Embedding the Bouncer daemon in an external application's executable.
- A second host credential resolver or test-report formatter in the consumer.
- Making arbitrary application configuration trees directly readable by the agentcon CLI.
- Publishing a release as part of this requirements-only PR.

## Verification and acceptance

- An external Go module imports the public APIs without importing `internal` paths.
- Agentcon and the external consumer use the same materialization, credentials, readiness, payload, environment, compilation, and test-report implementations.
- Existing agentcon behavior and tests remain intact after extraction.
- Shared fixtures retain overlay precedence, map merging, slice replacement, relative directory templates, relative TypeScript imports, profile inheritance, and exclusion of tests from daemon policy.
- Credential and prompt tests cover missing/invalid sources, encrypted keys, cancellation, malformed API responses, expiry, decline, and absence of secrets in logs and results.
- External test-runner coverage includes passing cases, assertion failures, malformed specs, compile errors, temporary-directory cleanup, and missing test directories without credentials, Docker, or network access.
- Shared TAP tests cover the current passing/failing output, failed spec loads, YAML diagnostics, and writer failures.
- The agentcon CLI uses the shared TAP formatter and retains its existing test exit behavior.
- Native Linux amd64 and arm64 release binaries have matching versions and verifiable digests.

Run upstream tests, lint, build, and practical smoke checks for the implementation PR that follows these requirements.
This requirements-only PR changes documentation and does not claim that the new APIs or release assets already exist.
