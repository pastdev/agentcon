#!/usr/bin/env bash
#
# Smoke test for issue 25: the Claude Code example agent under agentcon run.
#
# Kept for the record. It ran as .agentcon/claude-smoke.handoff.sh, next to
# agentcon binaries cross-compiled from this branch into
# .agentcon/bin/agentcon-linux-<arch>. Copy it back there to rerun.
#
# 2026-11-11, from a Docker-outside-of-Docker container on a TLS-inspecting
# network with the inspection CA in SMOKE_CA_FILE:
#   first:  passed. Claude Code 2.1.322 installed into the install bind, login
#           and a prompt worked, and .claude.json landed in the state bind.
#           The bouncer tunneled api.anthropic.com, claude.ai,
#           downloads.claude.ai, platform.claude.com, mcp-proxy.anthropic.com,
#           raw.githubusercontent.com, and http-intake.logs.us5.datadoghq.com,
#           and denied nothing. The binds and an empty probe mount over a
#           root-owned image path stayed owned by the user.
#   second: the install and login were reused and a prompt worked. Two smoke
#           bugs, fixed below, lost its sidecar log and its answers: the
#           watcher waited 30 seconds before looking, longer than the session,
#           and a newline left by the session answered the first question.
# Before the volume NoCopy fix, the first run made both empty binds
# root-owned. agentcon run's own image build stalled about half the time on
# Docker Desktop, so the images are prebuilt (issue 26).
#
# Run it from the Docker-outside-of-Docker container that ran the earlier
# smokes, from any directory, once per phase:
#   SMOKE_PHASE=first  bash .agentcon/claude-smoke.handoff.sh
#   SMOKE_PHASE=second bash .agentcon/claude-smoke.handoff.sh
#
# Both phases deny every host (unmatched: deny) except the agents.claude
# tunnel list in docs/claude.md, and log decisions at --log audit=debug.
# first:  Claude Code installs on first start. Log in, send one short prompt
#         such as "say hi", then /exit.
# second: Claude Code should start without reinstalling and without asking
#         you to log in. Send one short prompt, then /exit.
# Any denied host is reported.
#
# Claude's state and install use dedicated directories under
# .agentcon/claude-smoke, not your ~/.claude. A second phase that passes
# deletes them, including the login, unless SMOKE_KEEP=1. Nothing secret is
# written to the result file: it only records whether files exist.
#
# Both images are built first with docker buildx build and named in the
# config with pull_policy: never, because agentcon run's own build can stall
# on Docker Desktop (issue 26).
#
# It uses agentcon binaries cross-compiled from this branch into
# .agentcon/bin/agentcon-linux-<arch>. SMOKE_CA_FILE names an optional CA
# file (PEM), such as a TLS inspection CA, built into the sidecar image.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE
REPO="$(cd "${HERE}/.." && pwd)"
readonly REPO
readonly RESULT="${HERE}/claude-smoke.handoff.result"
readonly SMOKE_DIR="${HERE}/claude-smoke"
readonly DOC="${REPO}/docs/claude.md"
readonly AGENT_IMAGE="agentcon/claude-smoke:latest"
readonly SIDECAR_IMAGE="agentcon/claude-smoke-sidecar:latest"
readonly PHASE="${SMOKE_PHASE:-}"

STEP="start"
STATUS="failed"
MESSAGE=""
HOST_PLATFORM=""
DOOD_SEEN=""
CA_FILE=""
SLUG=""
RUN_RC=""
VERSIONS_BEFORE=""
VERSIONS_AFTER=""
CREDENTIALS=""
CLAUDE_JSON=""
TUNNEL_LIST=""
PROBE=""
OWNERS=""
SIDECAR_LINES=""
TUNNELED=""
DENIED=""
LOGIN_ASKED=""
PROMPT_DONE=""
WORK=""
WATCHER_PID=""

function flat {
  local value="${1:-}"
  value="${value//$'\r'/}"
  printf '%s' "${value//$'\n'/ | }"
}

function write_result {
  local code=$?
  if [[ -n "${WATCHER_PID}" ]]; then
    kill "${WATCHER_PID}" 2>/dev/null || true
  fi
  if [[ "${STATUS}" != "success" && -z "${MESSAGE}" ]]; then
    MESSAGE="exited with code ${code} during ${STEP}"
  fi
  {
    printf 'status=%s\n' "${STATUS}"
    printf 'step=%s\n' "${STEP}"
    printf 'message=%s\n' "$(flat "${MESSAGE}")"
    printf 'phase=%s\n' "${PHASE}"
    printf 'host=%s\n' "${HOST_PLATFORM}"
    printf 'dood=%s\n' "${DOOD_SEEN}"
    printf 'sidecar_ca=%s\n' "${CA_FILE:+set}"
    printf 'slug=%s\n' "${SLUG}"
    printf 'run_exit=%s\n' "${RUN_RC}"
    printf 'versions_before=%s\n' "$(flat "${VERSIONS_BEFORE}")"
    printf 'versions_after=%s\n' "$(flat "${VERSIONS_AFTER}")"
    printf 'credentials_file=%s\n' "${CREDENTIALS}"
    printf 'claude_json_in_state=%s\n' "${CLAUDE_JSON}"
    printf 'tunnel_list=%s\n' "$(flat "${TUNNEL_LIST}")"
    printf 'probe_mount=%s\n' "${PROBE}"
    printf 'bind_owners=%s\n' "${OWNERS}"
    printf 'sidecar_log_lines=%s\n' "${SIDECAR_LINES}"
    printf 'tunneled_hosts=%s\n' "$(flat "${TUNNELED}")"
    printf 'denied_hosts=%s\n' "$(flat "${DENIED}")"
    printf 'login_asked=%s\n' "${LOGIN_ASKED}"
    printf 'prompt_completed=%s\n' "${PROMPT_DONE}"
  } > "${RESULT}"
  if [[ -n "${WORK}" ]]; then
    rm -rf "${WORK:?}"
  fi
  # Only a passing second phase removes the install and login, so a failed
  # or interrupted one can be rerun.
  if [[ "${PHASE}" == "second" && "${STATUS}" == "success" && "${SMOKE_KEEP:-}" != "1" ]]; then
    rm -rf "${SMOKE_DIR:?}"
  fi
  printf '\nResult written to %s\n' "${RESULT}"
}
trap write_result EXIT

function preflight {
  case "${PHASE}" in
    first | second) ;;
    *)
      MESSAGE="set SMOKE_PHASE to first or second"
      exit 1
      ;;
  esac
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64 | amd64) arch="amd64" ;;
    aarch64 | arm64) arch="arm64" ;;
  esac
  HOST_PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')/${arch}"
  BIN="${HERE}/bin/agentcon-linux-${arch}"
  if [[ "${HOST_PLATFORM}" != linux/* || ! -x "${BIN}" ]]; then
    MESSAGE="need Linux and ${BIN}"
    exit 1
  fi
  if ! command -v docker > /dev/null; then
    MESSAGE="docker not found"
    exit 1
  fi
  if [[ -n "${DOOD_NETWORK:-}" ]] || env | grep -q '^DOOD_MOUNT_'; then
    DOOD_SEEN="set"
  fi
  if [[ "${PHASE}" == "second" && ! -d "${SMOKE_DIR}/install/share/versions" ]]; then
    MESSAGE="run SMOKE_PHASE=first before second: no install in ${SMOKE_DIR}"
    exit 1
  fi
  TUNNEL_LIST="$(tunnel_list)"
  if [[ -z "${TUNNEL_LIST}" ]]; then
    MESSAGE="no agents.claude tunnel list found in ${DOC}"
    exit 1
  fi
  CA_FILE="${SMOKE_CA_FILE:-}"
  CA_FILE="${CA_FILE/#\~/${HOME}}"
  if [[ -n "${CA_FILE}" && ! -r "${CA_FILE}" ]]; then
    MESSAGE="cannot read CA file ${CA_FILE}"
    exit 1
  fi
}

# sidecar_context writes a build context for a sidecar image that trusts
# $CA_FILE and prints its path.
function sidecar_context {
  local dir="${WORK}/sidecar"
  mkdir -p "${dir}"
  cp "${CA_FILE}" "${dir}/smoke-ca.pem"
  cat > "${dir}/Dockerfile" << 'EOF_DOCKERFILE'
FROM registry.access.redhat.com/ubi10/ubi-minimal:10.2
COPY smoke-ca.pem /etc/pki/ca-trust/source/anchors/
RUN update-ca-trust extract
EOF_DOCKERFILE
  printf '%s\n' "${dir}"
}

# build_images builds the agent image, and the sidecar image when there is a
# CA file, with docker buildx build. agentcon run's own build can stall on
# Docker Desktop (issue 26), and how the image is built is not what this
# smoke tests, so the config names these tags with pull_policy: never.
function build_images {
  docker buildx build --load --tag "${AGENT_IMAGE}" "$(agent_context)"
  if [[ -n "${CA_FILE}" ]]; then
    docker buildx build --load --tag "${SIDECAR_IMAGE}" "$(sidecar_context)"
  fi
}

# tunnel_list prints the tunnel hosts of the agent entry in docs/claude.md,
# one per line, so the smoke tests the documented list.
function tunnel_list {
  sed -n '/^    tunnel:$/,/^```$/p' "${DOC}" \
    | sed -n -E 's/^      - "?([^"]+)"?$/\1/p'
}

# agent_context prints a build context for the agent image: a copy of
# docs/claude/image under $WORK. With a CA file, the copy trusts it before
# anything is downloaded, as a user on a TLS-inspecting network would do.
function agent_context {
  local dir="${WORK}/agent-image"
  cp -a "${REPO}/docs/claude/image" "${dir}"
  if [[ -n "${CA_FILE}" ]]; then
    cp "${CA_FILE}" "${dir}/smoke-ca.pem"
    sed -i '/^FROM /a\
COPY smoke-ca.pem /etc/pki/ca-trust/source/anchors/\
RUN update-ca-trust extract' "${dir}/Dockerfile"
  fi
  printf '%s\n' "${dir}"
}

function write_config {
  local root="$1"
  {
    printf 'default_context: smoke\n'
    printf 'agents:\n  claude:\n    image: %s\n    pull_policy: never\n' "${AGENT_IMAGE}"
    printf '    mounts:\n'
    printf '      - source: %s/state\n        target: /agent/claude\n' "${SMOKE_DIR}"
    printf '      - source: %s/install\n        target: /agent/claude-install\n' "${SMOKE_DIR}"
    # An empty directory over a populated root-owned image path. Docker
    # would copy that path's files, owner, and mode into it unless agentcon
    # asks for no copy.
    printf '      - source: %s/probe\n        target: /usr/local/share/agentcon\n' "${WORK}"
    printf '    tunnel:\n'
    printf '%s\n' "${TUNNEL_LIST}" | sed 's/^\(.*\)$/      - "\1"/'
    printf 'bouncers:\n  smoke:\n    default_profile: smoke\n'
    printf '    profiles:\n      smoke:\n        unmatched: deny\n'
    printf 'contexts:\n  smoke:\n    agent: claude\n    bouncer: smoke\n    root: %s\n' "${root}"
    if [[ -n "${CA_FILE}" ]]; then
      printf 'sidecar:\n  image: %s\n  pull_policy: never\n' "${SIDECAR_IMAGE}"
    fi
  } > "${WORK}/xdg/agentcon.d/smoke.yaml"
}

# watch_sidecar streams the log of this run's sidecar into $1 until agentcon
# run removes it. It finds the sidecar by this run's slug, so a container
# left from an earlier run is never picked up.
function watch_sidecar {
  local log="$1" id=""
  local deadline=$((SECONDS + 900))
  while [[ -z "${id}" ]] && ((SECONDS < deadline)); do
    # A stalled Docker call must not stop the polling.
    id="$(timeout 10 docker ps --all --quiet --filter "label=agentcon.slug=${SLUG}" --filter label=agentcon.role=bouncer | head -n 1 || true)"
    sleep 2
  done
  if [[ -z "${id}" ]]; then
    return
  fi
  # Following a container that is not running yet returns at once with
  # nothing, so wait for the sidecar to start.
  local status=""
  while [[ "${status}" != "running" ]] && ((SECONDS < deadline)); do
    status="$(timeout 10 docker inspect --format '{{.State.Status}}' "${id}" 2>/dev/null || true)"
    if [[ -z "${status}" || "${status}" == "exited" || "${status}" == "dead" ]]; then
      break
    fi
    sleep 1
  done
  docker logs --follow "${id}" > "${log}" 2>&1 || true
}

# hosts_for prints the unique hosts of audit lines with decision $2 in log $1.
function hosts_for {
  grep -E "\blog=audit\b" "$1" \
    | grep -E "\bdecision=$2\b" \
    | sed -n -E 's/.*request="(CONNECT ([^:"]+)|[A-Z]+ https?:\/\/([^/:"]+)).*/\2\3/p' \
    | sort -u
}

# versions prints the installed versions, or nothing before the first install.
function versions {
  local dir="${SMOKE_DIR}/install/share/versions"
  if [[ ! -d "${dir}" ]]; then
    return 0
  fi
  find "${dir}" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' \
    | sort --version-sort \
    | tr '\n' ' '
}

function ask {
  local answer discard
  # Drop input the session left behind, so it does not answer for the user.
  while read -r -t 0.1 discard; do
    : "${discard}"
  done
  read -r -p "$1 [y/n] " answer
  printf '%s' "${answer}"
}

function run_phase {
  local root="${WORK}/root" log="${WORK}/sidecar.log"
  STEP="setup"
  mkdir -p "${WORK}/xdg/agentcon.d" "${root}/project" "${SMOKE_DIR}/state" "${SMOKE_DIR}/install" "${WORK}/probe"
  STEP="build images"
  build_images
  STEP="setup"
  write_config "${root}"
  export XDG_CONFIG_HOME="${WORK}/xdg"
  cd "${root}/project"
  VERSIONS_BEFORE="$(versions)"

  STEP="watcher"
  watch_sidecar "${log}" &
  WATCHER_PID=$!

  STEP="agentcon run"
  if [[ "${PHASE}" == "first" ]]; then
    printf '\nStarting Claude Code. Log in, send a short prompt such as "say hi", then /exit.\n\n'
  else
    printf '\nStarting Claude Code. It should not ask you to log in. Send a short prompt, then /exit.\n\n'
  fi
  local rc=0
  "${BIN}" --log audit=debug run --slug "${SLUG}" || rc=$?
  RUN_RC="${rc}"

  STEP="wait for sidecar removal"
  local waited=0
  while kill -0 "${WATCHER_PID}" 2>/dev/null && ((waited < 20)); do
    sleep 1
    waited=$((waited + 1))
  done
  kill "${WATCHER_PID}" 2>/dev/null || true
  WATCHER_PID=""

  STEP="inspect"
  VERSIONS_AFTER="$(versions)"
  CREDENTIALS="$([[ -f "${SMOKE_DIR}/state/.credentials.json" ]] && echo present || echo missing)"
  CLAUDE_JSON="$([[ -f "${SMOKE_DIR}/state/.claude.json" ]] && echo present || echo missing)"
  PROBE="$(stat -c '%U:%G %a' "${WORK}/probe") entries=$(find "${WORK}/probe" -mindepth 1 | wc -l)"
  OWNERS="$(stat -c '%U:%G' "${SMOKE_DIR}/state" "${SMOKE_DIR}/install" | sort -u | tr '\n' ' ')"
  SIDECAR_LINES=0
  if [[ -f "${log}" ]]; then
    SIDECAR_LINES="$(wc -l < "${log}")"
  fi
  TUNNELED="$(hosts_for "${log}" tunnel || true)"
  DENIED="$(hosts_for "${log}" deny || true)"

  STEP="observations"
  LOGIN_ASKED="$(ask $'\nDid Claude Code ask you to log in?')"
  PROMPT_DONE="$(ask "Did your prompt get an answer?")"
}

function main {
  STEP="preflight"
  preflight
  printf 'Phase %s, host %s, binary %s, dood %s\n' "${PHASE}" "${HOST_PLATFORM}" "${BIN}" "${DOOD_SEEN:-unset}"
  # Inside the repo, which sits on a DOOD_MOUNT_* volume, so agentcon run
  # can translate the binds into volume mounts.
  WORK="$(mktemp -d "${HERE}/work.XXXXXX")"
  SLUG="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  run_phase
  STEP="done"
  if [[ "${PHASE}" == "first" ]]; then
    if [[ "${RUN_RC}" == "0" && -n "${VERSIONS_AFTER// /}" &&
      "${SIDECAR_LINES}" -gt 0 && -n "${TUNNELED}" && -z "${DENIED}" &&
      "${PROBE}" == "$(id -un):$(id -gn) 755 entries=0" && "${OWNERS}" == "$(id -un):$(id -gn) " &&
      "${PROMPT_DONE}" == "y" ]]; then
      STATUS="success"
      MESSAGE="first passed"
    else
      MESSAGE="first did not match: expected run_exit=0, an installed version, a captured sidecar log with tunneled and no denied hosts, an untouched probe mount, binds owned by you, prompt_completed=y"
    fi
  else
    if [[ "${RUN_RC}" == "0" && -n "${VERSIONS_BEFORE// /}" && "${VERSIONS_BEFORE}" == "${VERSIONS_AFTER}" &&
      "${SIDECAR_LINES}" -gt 0 && -n "${TUNNELED}" && -z "${DENIED}" &&
      "${PROBE}" == "$(id -un):$(id -gn) 755 entries=0" &&
      "${LOGIN_ASKED}" == "n" && "${PROMPT_DONE}" == "y" ]]; then
      STATUS="success"
      MESSAGE="second passed"
    else
      MESSAGE="second did not match: expected run_exit=0, the same installed version before and after, a captured sidecar log with tunneled and no denied hosts, an untouched probe mount, login_asked=n, prompt_completed=y"
    fi
  fi
}

main "$@"
