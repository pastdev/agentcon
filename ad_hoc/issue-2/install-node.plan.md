# Plan: Install Node.js in the base image (issue 2)

Issue: https://github.com/pastdev/agentcon/issues/2

## Goal

Install a pinned Node.js toolchain in the `agentcon` base image the same way Go is installed.
Agents should have `node`, `npm`, and `npx` on `PATH` after the entrypoint sources `/etc/profile`.

## Non-goals

Do not install `nvm`, `fnm`, or another version manager.
Do not enable Corepack or add Yarn or pnpm.
Do not change `agent_exec.sh` or harness startup beyond the new image layer.

## Decisions

- Official Node.js Linux tarball, not a distro package
- Version: `24.21.0` LTS
- Architectures: `x86_64` (`linux-x64`) and `aarch64` (`linux-arm64`)
- Archive: `.tar.gz` so the image does not need `xz`
- Checksums from `https://nodejs.org/dist/v24.21.0/SHASUMS256.txt`
  - `linux-x64`: `6e1db87ef58b8819e5d5402eff1536491b18edd8eb7bee5ef7897876e88dc5ff`
  - `linux-arm64`: `724282c3b43aec998aa9527380465b45d229e021b58035f5f4f63095eabfe5d5`
- Fetch through `lib/cache.sh` and the existing BuildKit cache mount
- Extract to `/usr/local/node` with `--strip-components=1`
- Write `/etc/profile.d/node.sh` to prepend `/usr/local/node/bin` to `PATH`
- Call `install_go.sh`, `install_golangci_lint.sh`, and `install_node.sh` from one cache-mounted `RUN`
- Keep install scripts separate so each toolchain stays its own file
- Do not add a `RUN` per language
- `COPY contrib/ /` already invalidates later install steps when any script changes
- BuildKit cache under `/var/cache/agentcon` is what avoids re-downloading tarballs
- Land this change in the initial `master` commit with the Go CLI skeleton
- Do not open a merge request for this issue yet

## Layout

```text
ad_hoc/issue-2/install-node.plan.md
image/base/Dockerfile
image/base/contrib/usr/local/share/agentcon/scripts/install_node.sh
```

## Acceptance checks

- Image build runs `install_node.sh` successfully
- A container that sources `/etc/profile` has `node`, `npm`, and `npx` on `PATH`
- `node --version` prints `v24.21.0`

## Implementation sequence

1. Add `install_node.sh` beside `install_go.sh`
2. Fold all toolchain installs into one cache-mounted Dockerfile `RUN`
3. Write this plan
4. Rebuild the image on the host and smoke-check `node --version`
5. Push `master` with the skeleton and this change together
