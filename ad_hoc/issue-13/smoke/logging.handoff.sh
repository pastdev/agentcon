#!/usr/bin/env bash
#
# Smoke test for issue 13: agentcon run with a bouncer, logging the sidecar
# at --log bouncer=debug --log audit=debug.
#
# Kept for the record. It ran as .agentcon/logging-smoke.handoff.sh, next to
# agentcon binaries cross-compiled from this branch into
# .agentcon/bin/agentcon-linux-<arch>. Copy it back there to rerun.
#
# 2026-11-10, from a Docker-outside-of-Docker container on a TLS-inspecting
# network with the inspection CA in SMOKE_CA_FILE: passed. Allow 200 at INF,
# deny 403 at WRN, tunnel 200 at DBG, all with log=audit. The sidecar got
# the forwarded --log and --log-format flags, and neither the sidecar log
# nor the redirected run stderr was colored. A first attempt polled
# docker logs once a second and lost the decisions to sidecar removal, so
# the watcher follows the log instead.
#
# Run it from the Docker-outside-of-Docker container that ran the issue 19
# smoke (DOOD_NETWORK and DOOD_MOUNT_* set), from any directory:
#   bash .agentcon/logging-smoke.handoff.sh
#
# It uses agentcon binaries cross-compiled from this branch into
# .agentcon/bin/agentcon-linux-<arch>. It asks for an optional CA file (PEM)
# to build into the sidecar image, such as a TLS inspection CA.
# SMOKE_CA_FILE skips that question.
#
# The mock agent makes three requests through the bouncer:
#   GET https://api.github.com/zen      allowed by a rule   (audit info)
#   GET https://api.github.com/octocat  denied by default   (audit warn)
#   GET https://example.com/            tunneled            (audit debug)
#
# The sidecar's container log is copied to .agentcon/logging-smoke.sidecar.log
# and the stderr of agentcon run to .agentcon/logging-smoke.run.log. Neither
# holds secrets: the policy has no credentials. Temporary config and the work
# directory are deleted on exit. Your ~/.config/agentcon.d is not used.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE
REPO="$(cd "${HERE}/.." && pwd)"
readonly REPO
readonly RESULT="${HERE}/logging-smoke.handoff.result"
readonly SIDECAR_LOG="${HERE}/logging-smoke.sidecar.log"
readonly RUN_LOG="${HERE}/logging-smoke.run.log"

STEP="start"
STATUS="failed"
MESSAGE=""
HOST_PLATFORM=""
DOOD_SEEN=""
CA_FILE=""
SLUG=""
RUN_RC=""
ALLOW_CODE=""
DENY_CODE=""
TUNNEL_CODE=""
CURL_ERRORS=""
SIDECAR_ARGS=""
AUDIT_LINES=""
AUDIT_ALLOW=""
AUDIT_DENY=""
AUDIT_TUNNEL=""
BOUNCER_LISTENING=""
BOUNCER_DEBUG=""
SIDECAR_COLOR=""
RUN_CLI_LINES=""
RUN_COLOR=""
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
    printf 'host=%s\n' "${HOST_PLATFORM}"
    printf 'dood=%s\n' "${DOOD_SEEN}"
    printf 'sidecar_ca=%s\n' "${CA_FILE:+set}"
    printf 'slug=%s\n' "${SLUG}"
    printf 'run_exit=%s\n' "${RUN_RC}"
    printf 'allow_code=%s\n' "${ALLOW_CODE}"
    printf 'deny_code=%s\n' "${DENY_CODE}"
    printf 'tunnel_code=%s\n' "${TUNNEL_CODE}"
    printf 'curl_errors=%s\n' "$(flat "${CURL_ERRORS}")"
    printf 'sidecar_args=%s\n' "$(flat "${SIDECAR_ARGS}")"
    printf 'audit_lines=%s\n' "${AUDIT_LINES}"
    printf 'audit_allow=%s\n' "${AUDIT_ALLOW}"
    printf 'audit_deny=%s\n' "${AUDIT_DENY}"
    printf 'audit_tunnel=%s\n' "${AUDIT_TUNNEL}"
    printf 'bouncer_listening=%s\n' "${BOUNCER_LISTENING}"
    printf 'bouncer_debug_lines=%s\n' "${BOUNCER_DEBUG}"
    printf 'sidecar_color=%s\n' "${SIDECAR_COLOR}"
    printf 'run_cli_lines=%s\n' "${RUN_CLI_LINES}"
    printf 'run_color=%s\n' "${RUN_COLOR}"
    printf 'sidecar_log=%s\n' "${SIDECAR_LOG}"
    printf 'run_log=%s\n' "${RUN_LOG}"
  } > "${RESULT}"
  if [[ -n "${WORK}" ]]; then
    rm -rf "${WORK:?}"
  fi
  printf '\nResult written to %s\n' "${RESULT}"
}
trap write_result EXIT

function pick_binary {
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
}

function ask_ca {
  CA_FILE="${SMOKE_CA_FILE-}"
  if [[ -z "${SMOKE_CA_FILE+set}" ]]; then
    read -r -e -p "CA file (PEM) to build into the sidecar image (empty for none): " CA_FILE
  fi
  CA_FILE="${CA_FILE/#\~/${HOME}}"
  if [[ -n "${CA_FILE}" && ! -r "${CA_FILE}" ]]; then
    MESSAGE="cannot read CA file ${CA_FILE}"
    exit 1
  fi
}

# sidecar_build prints a sidecar.build config for $CA_FILE, after writing its
# build context under $WORK. It prints nothing without a CA file.
function sidecar_build {
  if [[ -z "${CA_FILE}" ]]; then
    return
  fi
  local dir="${WORK}/sidecar"
  mkdir -p "${dir}"
  cp "${CA_FILE}" "${dir}/smoke-ca.pem"
  cat > "${dir}/Dockerfile" << 'EOF_DOCKERFILE'
FROM registry.access.redhat.com/ubi10/ubi-minimal:10.2
COPY smoke-ca.pem /etc/pki/ca-trust/source/anchors/
RUN update-ca-trust extract
EOF_DOCKERFILE
  printf 'sidecar:\n  build:\n    context: %s\n' "${dir}"
}

function write_config {
  local root="$1"
  {
    printf 'default_context: smoke\n'
    printf 'agents:\n  mock:\n    image: agentcon/mock-smoke:latest\n'
    printf '    build:\n      context: %s/docs/workspace\n' "${REPO}"
    cat << 'EOF_POLICY'
bouncers:
  smoke:
    default_profile: smoke
    profiles:
      smoke:
        unmatched: tunnel
        http:
          - name: github
            hosts: [api.github.com]
            default: deny
            rules:
              - action: allow
                methods: [GET]
                path: /zen
EOF_POLICY
    printf 'contexts:\n  smoke:\n    agent: mock\n    bouncer: smoke\n    root: %s\n' "${root}"
    sidecar_build
  } > "${WORK}/xdg/agentcon.d/smoke.yaml"
}

# watch_sidecar streams the log of this run's sidecar into $SIDECAR_LOG until
# agentcon run removes it. It finds the sidecar by this run's slug, so a
# container left from an earlier run is never picked up.
function watch_sidecar {
  local id=""
  local deadline=$((SECONDS + 600))
  while [[ -z "${id}" ]] && ((SECONDS < deadline)); do
    id="$(docker ps --all --quiet --filter "label=agentcon.slug=${SLUG}" --filter label=agentcon.role=bouncer | head -n 1)"
    sleep 0.5
  done
  if [[ -z "${id}" ]]; then
    return
  fi
  docker inspect --format '{{join .Args " "}}' "${id}" > "${WORK}/sidecar-args" 2>/dev/null || true
  # Follow rather than poll, so lines written just before removal are kept.
  docker logs --follow "${id}" > "${SIDECAR_LOG}" 2>&1 || true
}

function run_smoke {
  local root="${WORK}/root"
  mkdir -p "${WORK}/xdg/agentcon.d" "${root}/project"
  write_config "${root}"
  export XDG_CONFIG_HOME="${WORK}/xdg"
  cd "${root}/project"
  : > "${SIDECAR_LOG}"

  STEP="watcher"
  watch_sidecar &
  WATCHER_PID=$!

  STEP="agentcon run"
  local requests
  # Expanded by bash inside the agent container, not here.
  # shellcheck disable=SC2016
  requests='for pair in allow=https://api.github.com/zen deny=https://api.github.com/octocat tunnel=https://example.com/; do
    code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 60 "${pair#*=}" 2> curl-error.txt || true)
    echo "${pair%%=*}=${code:-none}" >> smoke-codes.txt
    echo "${pair%%=*}=$(tr "\n" " " < curl-error.txt)" >> smoke-errors.txt
  done'
  local rc=0
  "${BIN}" --log bouncer=debug --log audit=debug run --slug "${SLUG}" -- bash -c "${requests}" \
    2> >(tee "${RUN_LOG}" >&2) || rc=$?
  RUN_RC="${rc}"

  STEP="wait for sidecar removal"
  local waited=0
  while kill -0 "${WATCHER_PID}" 2>/dev/null && ((waited < 20)); do
    sleep 1
    waited=$((waited + 1))
  done
  kill "${WATCHER_PID}" 2>/dev/null || true
  WATCHER_PID=""

  if [[ -f smoke-codes.txt ]]; then
    ALLOW_CODE="$(sed -n 's/^allow=//p' smoke-codes.txt)"
    DENY_CODE="$(sed -n 's/^deny=//p' smoke-codes.txt)"
    TUNNEL_CODE="$(sed -n 's/^tunnel=//p' smoke-codes.txt)"
  fi
  if [[ -f smoke-errors.txt ]]; then
    CURL_ERRORS="$(grep -v '=$' smoke-errors.txt || true)"
  fi
  SIDECAR_ARGS="$(cat "${WORK}/sidecar-args" 2>/dev/null || true)"
}

# count prints how many lines of file $1 match every extended regex after it.
function count {
  local lines pattern
  lines="$(cat "$1" 2>/dev/null || true)"
  shift
  for pattern in "$@"; do
    lines="$(grep -E -- "${pattern}" <<< "${lines}" || true)"
  done
  if [[ -z "${lines}" ]]; then
    echo 0
    return
  fi
  grep -c '' <<< "${lines}"
}

function check_logs {
  AUDIT_LINES="$(count "${SIDECAR_LOG}" '\blog=audit\b')"
  AUDIT_ALLOW="$(count "${SIDECAR_LOG}" '^[^ ]+ INF ' '\blog=audit\b' '\bdecision=allow\b' 'api\.github\.com/zen')"
  AUDIT_DENY="$(count "${SIDECAR_LOG}" '^[^ ]+ WRN ' '\blog=audit\b' '\bdecision=deny\b' 'api\.github\.com/octocat')"
  AUDIT_TUNNEL="$(count "${SIDECAR_LOG}" '^[^ ]+ DBG ' '\blog=audit\b' '\bdecision=tunnel\b' 'example\.com')"
  BOUNCER_LISTENING="$(count "${SIDECAR_LOG}" '\blog=bouncer\b' '\bcomponent=daemon\b' ' listening ')"
  BOUNCER_DEBUG="$(count "${SIDECAR_LOG}" '^[^ ]+ DBG ' '\blog=bouncer\b')"
  SIDECAR_COLOR="$(count "${SIDECAR_LOG}" $'\x1b\\[')"
  RUN_CLI_LINES="$(count "${RUN_LOG}" '\blog=cli\b')"
  RUN_COLOR="$(count "${RUN_LOG}" $'\x1b\\[[0-9;]*m[^ ]*=')"
}

function main {
  STEP="pick binary"
  pick_binary
  printf 'Host %s, binary %s, dood %s\n' "${HOST_PLATFORM}" "${BIN}" "${DOOD_SEEN:-unset}"
  STEP="ca"
  ask_ca
  # Inside the repo, which sits on a DOOD_MOUNT_* volume, so agentcon run
  # can translate the context root into a volume mount.
  WORK="$(mktemp -d "${HERE}/work.XXXXXX")"
  SLUG="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  run_smoke
  STEP="check logs"
  check_logs
  STEP="done"
  local want="--log bouncer=debug --log audit=debug --log-format pretty"
  if [[ "${RUN_RC}" == "0" && "${ALLOW_CODE}" == "200" && "${DENY_CODE}" == "403" &&
    "${TUNNEL_CODE}" =~ ^[23][0-9][0-9]$ && "${SIDECAR_ARGS}" == *"${want}"* &&
    "${AUDIT_ALLOW}" -ge 1 && "${AUDIT_DENY}" -ge 1 && "${AUDIT_TUNNEL}" -ge 1 &&
    "${BOUNCER_LISTENING}" -ge 1 && "${SIDECAR_COLOR}" == "0" &&
    "${RUN_CLI_LINES}" -ge 1 && "${RUN_COLOR}" == "0" ]]; then
    STATUS="success"
    MESSAGE="smoke passed"
  else
    MESSAGE="smoke did not match: expected run_exit=0 allow_code=200 deny_code=403 tunnel_code=2xx/3xx, sidecar_args with '${want}', audit_allow/deny/tunnel>=1, bouncer_listening>=1, sidecar_color=0, run_cli_lines>=1, run_color=0"
  fi
}

main "$@"
