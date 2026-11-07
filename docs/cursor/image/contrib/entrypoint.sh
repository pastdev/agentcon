#!/bin/bash

set -euo pipefail

readonly AGENT_USER="${USER:-agent}"
readonly HOME="/home/${AGENT_USER}"
readonly CURSOR_STATE="${CURSOR_STATE:-/agent/cursor}"
readonly CURSOR_CONFIG="${CURSOR_CONFIG:-/agent/cursor-config}"
readonly XTRACE_LOG="${AGENTCON_XTRACE_LOG:-${CURSOR_STATE}/entrypoint.xtrace}"

export HOME
export AGENT_CLI_CREDENTIAL_STORE="${AGENT_CLI_CREDENTIAL_STORE:-file}"

if [[ "${AGENTCON_XTRACE:-}" == "1" ]]; then
  mkdir --parents "$(dirname "${XTRACE_LOG}")"
  exec {BASH_XTRACEFD}>"${XTRACE_LOG}"
  set -x
fi

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

function latest_cursor_agent {
  local candidate dir versions_dir
  versions_dir="${HOME}/.local/share/cursor-agent/versions"
  if [[ ! -d "${versions_dir}" ]]; then
    return 1
  fi
  candidate=""
  for dir in "${versions_dir}"/*; do
    if [[ ! -x "${dir}/cursor-agent" ]]; then
      continue
    fi
    if [[ -z "${candidate}" || "${dir}" > "${candidate}" ]]; then
      candidate="${dir}"
    fi
  done
  if [[ -z "${candidate}" ]]; then
    return 1
  fi
  printf '%s\n' "${candidate}"
}

function link_cursor_agent_bin {
  local version_dir
  version_dir="$(latest_cursor_agent)" || return 0
  ln --symbolic --force \
    "${version_dir}/cursor-agent" \
    "${HOME}/.local/bin/agent"
}

function link_cursor_state {
  mkdir --parents \
    "${HOME}" \
    "${HOME}/.config" \
    "${HOME}/.local/bin" \
    "${HOME}/.local/share" \
    "${CURSOR_STATE}/local/share/cursor-agent" \
    "${CURSOR_CONFIG}"
  ln --symbolic --force "${CURSOR_STATE}" "${HOME}/.cursor"
  ln --symbolic --force "${CURSOR_CONFIG}" "${HOME}/.config/cursor"
  # cursor.com/install unpacks into ~/.local/share/cursor-agent
  # and symlinks agent into ~/.local/bin.
  # Persist only that share tree so the rest of ~/.local stays in the container.
  ln --symbolic --force \
    "${CURSOR_STATE}/local/share/cursor-agent" \
    "${HOME}/.local/share/cursor-agent"
  link_cursor_agent_bin
}

function install_cursor {
  export PATH="${HOME}/.local/bin:${PATH}"
  if [[ -x "${HOME}/.local/bin/agent" ]]; then
    return 0
  fi
  curl https://cursor.com/install -fsS | bash
}

setup_user
source_profiles
link_cursor_state
install_cursor
exec agent "$@"
