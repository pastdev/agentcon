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

function link_cursor_state {
  mkdir --parents \
    "${HOME}" \
    "${HOME}/.config" \
    "${CURSOR_STATE}/local" \
    "${CURSOR_CONFIG}"
  ln --symbolic --force "${CURSOR_STATE}" "${HOME}/.cursor"
  ln --symbolic --force "${CURSOR_CONFIG}" "${HOME}/.config/cursor"
  ln --symbolic --force "${CURSOR_STATE}/local" "${HOME}/.local"
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
