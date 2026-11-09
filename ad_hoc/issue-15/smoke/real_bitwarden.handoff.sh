#!/usr/bin/env bash
#
# Smoke test for issue 15: Bitwarden unlock and approvals through prompts.
#
# Kept for the record. It ran as .agentcon/bitwarden-prompt-smoke.handoff.sh,
# next to agentcon binaries cross-compiled from this branch into
# .agentcon/bin/agentcon-<os>-<arch>. Copy it back there to rerun.
#
# 2026-11-09, against a real Bitwarden account:
#   serve mode passed: ready=true, retry prompt seen, password hidden,
#   approved request 200, CLI-denied request 403.
#   run mode was blocked by two agentcon run problems that predate issue 15:
#   the sidecar image is never pulled, and run inside a Docker-outside-of-
#   Docker container (condev) cannot reach the sidecar's published port.
#
# Run it on the host from any directory:
#   bash .agentcon/bitwarden-prompt-smoke.handoff.sh
#
# It asks for your Bitwarden email (and self-hosted server, if any), then:
#   run mode   (Linux amd64 with docker): `agentcon run` with the mock agent.
#              Unlock at the run terminal. The agent makes two requests that
#              need approval. This script approves the first and denies the
#              second through the CLI.
#   serve mode (anything else, or SMOKE_MODE=serve): an interactive
#              `agentcon bouncer serve`. Unlock at its terminal and answer the
#              first approval there with y. This script denies the second
#              through the CLI.
#
# Type a WRONG master password first, then the right one, to see the retry.
# Nothing secret is written to the result file. All temporary config and
# state, including the Bitwarden refresh token, is deleted on exit. Your
# ~/.config/agentcon.d is not used.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE
REPO="$(cd "${HERE}/.." && pwd)"
readonly REPO
readonly RESULT="${HERE}/bitwarden-prompt-smoke.handoff.result"
readonly SIDECAR_LOG="${HERE}/bitwarden-prompt-smoke.sidecar.log"
readonly PROMPT_TEXT="Smoke: let this request read api.github.com/zen?"

STEP="start"
STATUS="failed"
MESSAGE=""
MODE=""
HOST_PLATFORM=""
READY=""
STARTUP_ERROR=""
APPROVED_CODE=""
DENIED_CODE=""
RETRY_SEEN=""
PASSWORD_HIDDEN=""
WORK=""
APPROVER_PID=""
WATCHER_PID=""

function flat {
  local value="${1:-}"
  value="${value//$'\r'/}"
  printf '%s' "${value//$'\n'/ | }"
}

function write_result {
  local code=$?
  if [[ -n "${APPROVER_PID}" ]]; then
    kill "${APPROVER_PID}" 2>/dev/null || true
  fi
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
    printf 'mode=%s\n' "${MODE}"
    printf 'host=%s\n' "${HOST_PLATFORM}"
    printf 'ready=%s\n' "${READY}"
    printf 'startup_error=%s\n' "$(flat "${STARTUP_ERROR}")"
    printf 'approved_request_code=%s\n' "${APPROVED_CODE}"
    printf 'denied_request_code=%s\n' "${DENIED_CODE}"
    printf 'retry_prompt_seen=%s\n' "${RETRY_SEEN}"
    printf 'password_not_echoed=%s\n' "${PASSWORD_HIDDEN}"
    if [[ -s "${SIDECAR_LOG}" ]]; then
      printf 'sidecar_log=%s\n' "${SIDECAR_LOG}"
    fi
  } > "${RESULT}"
  if [[ -n "${WORK}" ]]; then
    rm -rf "${WORK:?}"
  fi
  printf '\nResult written to %s\n' "${RESULT}"
}
trap write_result EXIT

function pick_binary {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "${arch}" in
    x86_64 | amd64) arch="amd64" ;;
    aarch64 | arm64) arch="arm64" ;;
  esac
  HOST_PLATFORM="${os}/${arch}"
  BIN="${HERE}/bin/agentcon-${os}-${arch}"
  if [[ ! -x "${BIN}" ]]; then
    MESSAGE="no prebuilt agentcon for ${HOST_PLATFORM} in ${HERE}/bin"
    exit 1
  fi
  if [[ -n "${SMOKE_MODE:-}" ]]; then
    MODE="${SMOKE_MODE}"
  elif [[ "${HOST_PLATFORM}" == "linux/amd64" ]] && command -v docker > /dev/null; then
    MODE="run"
  else
    MODE="serve"
  fi
}

function ask_account {
  read -r -p "Bitwarden email: " BW_EMAIL
  read -r -p "Self-hosted Bitwarden server URL (empty for bitwarden.com): " BW_SERVER
  if [[ -z "${BW_EMAIL}" ]]; then
    MESSAGE="no email given"
    exit 1
  fi
}

# policy prints the bouncer policy, indented by $1 spaces.
function policy {
  local pad
  pad="$(printf '%*s' "$1" '')"
  sed "s/^/${pad}/" <<EOF
default_profile: smoke
prompts: {timeout: 2m, notify: false}
credentials:
  bw:
    token:
      source: bitwarden
      email: ${BW_EMAIL}
${BW_SERVER:+      server: ${BW_SERVER}}
      item: agentcon-smoke-unused
      path: \$.notes
profiles:
  smoke:
    unmatched: deny
    http:
      - name: zen
        hosts: [api.github.com]
        default: deny
        rules:
          - action: ask
            methods: [GET]
            path: /zen
            prompt: "${PROMPT_TEXT}"
EOF
}

# watch_sidecar follows the bouncer sidecar's logs into $SIDECAR_LOG and
# records its state, since agentcon run removes the sidecar when it fails.
function watch_sidecar {
  local id="" state
  : > "${SIDECAR_LOG}"
  local deadline=$((SECONDS + 300))
  while [[ -z "${id}" ]] && ((SECONDS < deadline)); do
    id="$(docker ps --all --quiet --filter label=agentcon.role=bouncer --filter label=agentcon.context=smoke | head -n 1)"
    sleep 0.5
  done
  if [[ -z "${id}" ]]; then
    echo "no sidecar container seen" >> "${SIDECAR_LOG}"
    return
  fi
  echo "sidecar ${id}" >> "${SIDECAR_LOG}"
  while docker inspect "${id}" > /dev/null 2>&1; do
    state="$(docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}}' "${id}" 2>/dev/null || true)"
    if [[ -n "${state}" ]]; then
      printf '%s\n' "${state}" > "${SIDECAR_LOG}.state"
    fi
    # Keep the last capture that worked; removal makes later ones fail.
    if docker logs "${id}" > "${SIDECAR_LOG}.tmp" 2>&1; then
      mv "${SIDECAR_LOG}.tmp" "${SIDECAR_LOG}.out"
    fi
    sleep 1
  done
  {
    echo "--- last state"
    cat "${SIDECAR_LOG}.state" 2>/dev/null || true
    echo "--- logs"
    cat "${SIDECAR_LOG}.out" 2>/dev/null || true
  } >> "${SIDECAR_LOG}"
  rm -f "${SIDECAR_LOG}.state" "${SIDECAR_LOG}.out" "${SIDECAR_LOG}.tmp"
}

# approve_and_deny answers the first two confirm prompts it sees: approve,
# then deny. It runs in the background and logs to $1.
function approve_and_deny {
  local log="$1"
  shift
  local handled=0 id kind
  local -a seen=()
  local deadline=$((SECONDS + 600))
  while ((handled < 2 && SECONDS < deadline)); do
    while read -r id kind _; do
      if [[ "${kind}" != "confirm" || " ${seen[*]-} " == *" ${id} "* ]]; then
        continue
      fi
      seen+=("${id}")
      if ((handled == 0)); then
        "$@" approve "${id}" >> "${log}" 2>&1 && handled=1
      else
        "$@" deny "${id}" >> "${log}" 2>&1 && handled=2
      fi
    done < <("$@" prompts 2>> "${log}" | tail -n +2)
    sleep 1
  done
}

function run_mode {
  local root="${WORK}/root"
  mkdir -p "${WORK}/xdg/agentcon.d" "${root}/project"
  {
    printf 'default_context: smoke\n'
    printf 'agents:\n  mock:\n    image: agentcon/mock-smoke:latest\n'
    printf '    build:\n      context: %s/docs/workspace\n' "${REPO}"
    printf 'bouncers:\n  smoke:\n'
    policy 4
    printf 'contexts:\n  smoke:\n    agent: mock\n    bouncer: smoke\n    root: %s\n' "${root}"
  } > "${WORK}/xdg/agentcon.d/smoke.yaml"
  export XDG_CONFIG_HOME="${WORK}/xdg"
  cd "${root}/project"

  STEP="approver"
  approve_and_deny "${WORK}/approver.log" "${BIN}" bouncer &
  APPROVER_PID=$!
  watch_sidecar &
  WATCHER_PID=$!

  STEP="agentcon run"
  printf '\nStarting agentcon run. Type a WRONG master password first, then the right one.\n\n'
  local requests
  # Expanded by bash inside the agent container, not here.
  # shellcheck disable=SC2016
  requests='for i in 1 2; do
    code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 150 https://api.github.com/zen 2>/dev/null || true)
    echo "request${i}=${code:-none}" >> smoke-codes.txt
  done'
  local rc=0
  "${BIN}" run -- bash -c "${requests}" || rc=$?
  # Let the watcher see the sidecar removed and write its final state, but
  # do not wait for a sidecar that was never created.
  local waited=0
  while kill -0 "${WATCHER_PID}" 2>/dev/null && ((waited < 15)); do
    sleep 1
    waited=$((waited + 1))
  done
  kill "${WATCHER_PID}" 2>/dev/null || true
  WATCHER_PID=""
  READY="$([[ -f smoke-codes.txt ]] && echo true || echo false)"
  if [[ -f smoke-codes.txt ]]; then
    APPROVED_CODE="$(sed -n 's/^request1=//p' smoke-codes.txt)"
    DENIED_CODE="$(sed -n 's/^request2=//p' smoke-codes.txt)"
  fi
  if ((rc != 0)); then
    STARTUP_ERROR="agentcon run exited ${rc}"
  fi
}

function serve_mode {
  local state="${WORK}/state" config="${WORK}/bouncer.yaml"
  local port="${SMOKE_PORT:-18228}"
  {
    printf 'listen: 127.0.0.1:%s\nssh_listen: 127.0.0.1:%s\nanonymous_profile: smoke\n' "${port}" "$((port + 1))"
    policy 0
  } > "${config}"
  local -a cli=("${BIN}" bouncer --file "${config}" --state-dir "${state}")

  STEP="tester"
  serve_tester "${state}" "${port}" "${cli[@]}" &
  APPROVER_PID=$!

  STEP="agentcon bouncer serve"
  printf '\nStarting bouncer serve. Type a WRONG master password first, then the right one.\n'
  printf 'Answer the FIRST approval with y. Leave the second one, the script denies it.\n\n'
  "${cli[@]}" serve || true
  wait "${APPROVER_PID}" || true
  APPROVER_PID=""
WATCHER_PID=""
  READY="$(cat "${WORK}/ready" 2>/dev/null || echo false)"
  STARTUP_ERROR="$(cat "${WORK}/startup_error" 2>/dev/null || true)"
  APPROVED_CODE="$(cat "${WORK}/request1" 2>/dev/null || true)"
  DENIED_CODE="$(cat "${WORK}/request2" 2>/dev/null || true)"
}

# serve_tester waits for serve to be ready, makes the two requests, denies
# the second through the CLI, then stops serve.
function serve_tester {
  local state="$1" port="$2"
  shift 2
  local base="http://127.0.0.1:${port}/_bouncer/status" status=""
  local deadline=$((SECONDS + 600))
  while ((SECONDS < deadline)); do
    if [[ -f "${state}/admin-token" ]]; then
      status="$(curl -fsS -H "Authorization: Bearer $(tr -d '\n' < "${state}/admin-token")" "${base}" 2>/dev/null || true)"
      if [[ "${status}" == *'"ready":true'* ]]; then
        echo true > "${WORK}/ready"
        break
      fi
      if grep -q '"error":"[^"]' <<< "${status}"; then
        echo false > "${WORK}/ready"
        # shellcheck disable=SC2001
        sed 's/.*"error":"\([^"]*\)".*/\1/' <<< "${status}" > "${WORK}/startup_error"
        pkill -INT -f -- "--state-dir ${state}" || true
        return
      fi
    fi
    sleep 1
  done
  local -a proxy=(curl -sS -o /dev/null -w "%{http_code}" --max-time 150
    --proxy "http://127.0.0.1:${port}" --cacert "${state}/ca.pem" https://api.github.com/zen)
  "${proxy[@]}" > "${WORK}/request1" 2>/dev/null || true
  "${proxy[@]}" > "${WORK}/request2" 2>/dev/null &
  local second=$!
  local id kind handled=""
  while [[ -z "${handled}" ]] && kill -0 "${second}" 2>/dev/null; do
    while read -r id kind _; do
      if [[ "${kind}" == "confirm" ]]; then
        "$@" deny "${id}" > /dev/null 2>&1 && handled=1
      fi
    done < <("$@" prompts 2>/dev/null | tail -n +2)
    sleep 1
  done
  wait "${second}" || true
  sleep 1
  pkill -INT -f -- "--state-dir ${state}" || true
}

function ask_observations {
  local answer
  read -r -p $'\nDid a wrong master password lead to a retry prompt ("attempt 2 of 3")? [y/n] ' answer
  RETRY_SEEN="${answer}"
  read -r -p "Was the master password hidden while you typed it? [y/n] " answer
  PASSWORD_HIDDEN="${answer}"
}

function main {
  STEP="pick binary"
  pick_binary
  printf 'Host %s, mode %s, binary %s\n' "${HOST_PLATFORM}" "${MODE}" "${BIN}"
  STEP="account"
  ask_account
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/agentcon-smoke.XXXXXX")"
  case "${MODE}" in
    run) run_mode ;;
    serve) serve_mode ;;
    *)
      MESSAGE="unknown SMOKE_MODE ${MODE}"
      exit 1
      ;;
  esac
  STEP="observations"
  ask_observations
  STEP="done"
  if [[ "${READY}" == "true" && "${APPROVED_CODE}" == "200" && "${DENIED_CODE}" == "403" &&
    "${RETRY_SEEN}" == "y" && "${PASSWORD_HIDDEN}" == "y" ]]; then
    STATUS="success"
    MESSAGE="smoke passed"
  else
    MESSAGE="smoke did not match: expected ready=true approved_request_code=200 denied_request_code=403 retry_prompt_seen=y password_not_echoed=y"
  fi
}

main "$@"
