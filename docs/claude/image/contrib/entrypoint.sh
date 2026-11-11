#!/bin/bash

set -euo pipefail

readonly AGENT_USER="${USER:-agent}"
readonly HOME="/home/${AGENT_USER}"
readonly CLAUDE_STATE="${CLAUDE_STATE:-/agent/claude}"
readonly CLAUDE_INSTALL="${CLAUDE_INSTALL:-/agent/claude-install}"
readonly XTRACE_LOG="${AGENTCON_XTRACE_LOG:-${CLAUDE_INSTALL}/entrypoint.xtrace}"

export HOME
# Claude keeps its settings, credentials, sessions, and .claude.json here.
export CLAUDE_CONFIG_DIR="${CLAUDE_STATE}"

function setup_user {
  printf '%s:%s:%s:%s:%s:%s:%s\n' \
    "${AGENT_USER}" \
    "x" \
    "$(id -u)" \
    "$(id -g)" \
    "Agent user" \
    "${HOME}" \
    "/bin/bash" \
    >> /etc/passwd
}

function source_profiles {
  if [[ -f /etc/profile ]]; then
    set +eu
    # shellcheck disable=SC1091
    source /etc/profile
    set -eu
  fi
}

# latest_claude prints the newest installed version. Versions are files
# named by version, so they sort by version, not by string.
function latest_claude {
  local versions_dir="${HOME}/.local/share/claude/versions"
  if [[ ! -d "${versions_dir}" ]]; then
    return 1
  fi
  local latest
  latest="$(find "${versions_dir}" -mindepth 1 -maxdepth 1 -type f -executable -printf '%f\n' \
    | sort --version-sort \
    | tail --lines 1)"
  if [[ -z "${latest}" ]]; then
    return 1
  fi
  printf '%s\n' "${versions_dir}/${latest}"
}

function link_claude_bin {
  local version
  version="$(latest_claude)" || return 0
  ln --symbolic --force "${version}" "${HOME}/.local/bin/claude"
}

function link_claude_state {
  mkdir --parents \
    "${HOME}" \
    "${HOME}/.local/bin" \
    "${HOME}/.local/share" \
    "${CLAUDE_STATE}" \
    "${CLAUDE_INSTALL}/share"
  # The native installer unpacks into ~/.local/share/claude and links
  # claude into ~/.local/bin. Persist only that share tree, on its own
  # bind, so Linux binaries stay out of the shared state directory.
  ln --symbolic --force --no-target-directory \
    "${CLAUDE_INSTALL}/share" \
    "${HOME}/.local/share/claude"
  link_claude_bin
}

function install_claude {
  export PATH="${HOME}/.local/bin:${PATH}"
  if [[ -x "${HOME}/.local/bin/claude" ]]; then
    return 0
  fi
  # The installer is quiet until its download finishes.
  printf 'Installing Claude Code into %s. This can take a few minutes on first start.\n' \
    "${CLAUDE_INSTALL}" >&2
  curl -fsSL https://claude.ai/install.sh | bash
}

function main {
  if [[ "${AGENTCON_XTRACE:-}" == "1" ]]; then
    mkdir --parents "$(dirname "${XTRACE_LOG}")"
    exec {BASH_XTRACEFD}>"${XTRACE_LOG}"
    set -x
  fi
  setup_user
  source_profiles
  link_claude_state
  install_claude
  exec claude "$@"
}

main "$@"
