#!/bin/bash

set -euo pipefail

readonly HARNESS="${HARNESS:-cursor}"
readonly AGENT_USER="${USER:-agent}"

readonly AGENT_DATA="${AGENT_DATA:-"/agent/${HARNESS}"}"
readonly HOME="/home/${AGENT_USER}"
readonly XTRACE_LOG="${AGENTCON_XTRACE_LOG:-${AGENT_DATA}/entrypoint.xtrace}"

export HOME
export AGENT_CLI_CREDENTIAL_STORE="${AGENT_CLI_CREDENTIAL_STORE:-file}"

if [[ "${AGENTCON_XTRACE:-}" == "1" ]]; then
  mkdir --parents "$(dirname "${XTRACE_LOG}")"
  exec {BASH_XTRACEFD}>"${XTRACE_LOG}"
  set -x
fi

function error_exit {
  echo "${1}" >&2
  exit "${2:-1}"
}

function link_harness_state {
  mkdir --parents "${HOME}" "${HOME}/.config" "${AGENT_DATA}/local"
  ln --symbolic --force "${AGENT_DATA}" "${HOME}/.cursor"
  ln --symbolic --force "${AGENT_DATA}" "${HOME}/.config/cursor"
  ln --symbolic --force "${AGENT_DATA}/local" "${HOME}/.local"
}

function install_cursor {
  export PATH="${HOME}/.local/bin:${PATH}"
  if [[ -x "${HOME}/.local/bin/agent" ]]; then
    return 0
  fi
  curl https://cursor.com/install -fsS | bash
}

function run_cursor {
  local args=("$@")

  # Chats live under ~/.cursor. Linux CLI auth lives under ~/.config/cursor.
  # Both point at the host harness bind so login and --resume survive new containers.
  # https://forum.cursor.com/t/where-are-cursor-chats-stored/77295
  link_harness_state
  install_cursor
  exec agent "${args[@]}"
}

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

function main {
  setup_user
  source_profiles
  case "${HARNESS}" in
    cursor)
      run_cursor "$@"
      ;;
    *)
      error_exit "unsupported harness ${HARNESS}"
      ;;
  esac
}

main "$@"
