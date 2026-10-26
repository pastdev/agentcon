#!/bin/bash

set -xeuo pipefail

readonly HARNESS="${HARNESS:-cursor}"
readonly USER="${USER:-agent}"

readonly AGENT_DATA="${AGENT_DATA:-"/agent/${HARNESS}"}"
readonly HOME="/home/${USER}"

function error_exit {
  echo "${1}" >&2
  exit "${2:-1}"
}

function run_cursor {
  local args=("$@")

  # Cursor stores memory under ~/.cursor. Bind-mount that path.
  # https://forum.cursor.com/t/where-are-cursor-chats-stored/77295
  mkdir --parents "${HOME}"
  ln --symbolic "${AGENT_DATA}" "${HOME}/.cursor"

  curl https://cursor.com/install -fsS | bash
  export PATH="${HOME}/.local/bin:${PATH}"
  exec agent "${args[@]}"
}

function setup_user {
  printf '%s:%s:%s:%s:%s:%s:%s' \
    "${USER}" \
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
