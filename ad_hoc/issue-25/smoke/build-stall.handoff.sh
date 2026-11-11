#!/usr/bin/env bash
#
# Reproduce the "load remote build context" stall without agentcon.
#
# Kept for the record and for issue 26. It ran as
# .agentcon/build-stall.handoff.sh. Copy it back there to rerun.
#
# 2026-11-11, Docker Engine 29.9.2 on Docker Desktop, API 1.56, 90 seconds
# per try: api ok, stall, stall, ok, stall. cli ok five times.
#
# It builds a copy of docs/claude/image, the context agentcon run sends,
# RUNS times through each path, each try limited to TRY_SECONDS:
#   api: POST /build with the context as a tar body and version=2 (BuildKit),
#        the request agentcon makes, sent with curl.
#   cli: docker build, which streams the context through a BuildKit session.
#
# Run it on the host from any directory, after Ctrl-C on any stuck smoke:
#   SMOKE_CA_FILE=<ca.pem> bash .agentcon/build-stall.handoff.sh
#
# SMOKE_CA_FILE adds that CA to the copy, as the Claude smoke does.
# RUNS (default 5) and TRY_SECONDS (default 90) are optional.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE
REPO="$(cd "${HERE}/.." && pwd)"
readonly REPO
readonly RESULT="${HERE}/build-stall.handoff.result"
readonly RUNS="${RUNS:-5}"
readonly TRY_SECONDS="${TRY_SECONDS:-90}"

STEP="start"
STATUS="failed"
MESSAGE=""
ENDPOINT=""
API_VERSION=""
API_RUNS=""
CLI_RUNS=""
WORK=""

function flat {
  local value="${1:-}"
  value="${value//$'\r'/}"
  printf '%s' "${value//$'\n'/ | }"
}

function write_result {
  local code=$?
  if [[ "${STATUS}" != "success" && -z "${MESSAGE}" ]]; then
    MESSAGE="exited with code ${code} during ${STEP}"
  fi
  {
    printf 'status=%s\n' "${STATUS}"
    printf 'step=%s\n' "${STEP}"
    printf 'message=%s\n' "$(flat "${MESSAGE}")"
    printf 'endpoint=%s\n' "${ENDPOINT}"
    printf 'api_version=%s\n' "${API_VERSION}"
    printf 'try_seconds=%s\n' "${TRY_SECONDS}"
    printf 'api_runs=%s\n' "${API_RUNS}"
    printf 'cli_runs=%s\n' "${CLI_RUNS}"
  } > "${RESULT}"
  if [[ -n "${WORK}" ]]; then
    rm -rf "${WORK:?}"
  fi
  printf '\nResult written to %s\n' "${RESULT}"
}
trap write_result EXIT

function prepare {
  WORK="$(mktemp -d "${HERE}/stall.XXXXXX")"
  cp -a "${REPO}/docs/claude/image" "${WORK}/context"
  if [[ -n "${SMOKE_CA_FILE:-}" ]]; then
    cp "${SMOKE_CA_FILE}" "${WORK}/context/smoke-ca.pem"
    sed -i '/^FROM /a\
COPY smoke-ca.pem /etc/pki/ca-trust/source/anchors/\
RUN update-ca-trust extract' "${WORK}/context/Dockerfile"
  fi
  tar --directory "${WORK}/context" --create --file "${WORK}/context.tar" .
  ENDPOINT="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
  API_VERSION="$(docker version --format '{{.Server.APIVersion}}')"
}

# api_build posts the context tar to /build like agentcon does and prints
# "ok", "error", or "stall" with the seconds it took.
function api_build {
  local tag="$1" base start out rc=0
  local -a socket=()
  case "${ENDPOINT}" in
    unix://*)
      socket=(--unix-socket "${ENDPOINT#unix://}")
      base="http://localhost"
      ;;
    tcp://*) base="http://${ENDPOINT#tcp://}" ;;
    *)
      printf 'unsupported-endpoint'
      return
      ;;
  esac
  start=${SECONDS}
  out="$(timeout "${TRY_SECONDS}" curl --silent --show-error --no-buffer "${socket[@]}" \
    --header 'Content-Type: application/x-tar' \
    --data-binary "@${WORK}/context.tar" \
    "${base}/v${API_VERSION}/build?version=2&t=${tag}" 2>&1)" || rc=$?
  if ((rc == 124)); then
    printf 'stall@%ss' "$((SECONDS - start))"
  elif ((rc != 0)) || grep -q '"error"' <<< "${out}"; then
    printf 'error@%ss' "$((SECONDS - start))"
  else
    printf 'ok@%ss' "$((SECONDS - start))"
  fi
}

# cli_build runs docker build on the same context and prints its outcome.
function cli_build {
  local tag="$1" start rc=0
  start=${SECONDS}
  timeout "${TRY_SECONDS}" docker build --quiet --tag "${tag}" "${WORK}/context" > /dev/null 2>&1 || rc=$?
  if ((rc == 124)); then
    printf 'stall@%ss' "$((SECONDS - start))"
  elif ((rc != 0)); then
    printf 'error@%ss' "$((SECONDS - start))"
  else
    printf 'ok@%ss' "$((SECONDS - start))"
  fi
}

function main {
  STEP="prepare"
  prepare
  printf 'Endpoint %s, API %s, %s runs of %ss each\n' "${ENDPOINT}" "${API_VERSION}" "${RUNS}" "${TRY_SECONDS}"
  local i outcome
  for ((i = 1; i <= RUNS; i++)); do
    STEP="api ${i}"
    outcome="$(api_build "agentcon/stall-test:api-${i}")"
    printf 'api %s: %s\n' "${i}" "${outcome}"
    API_RUNS+="${outcome} "
    STEP="cli ${i}"
    outcome="$(cli_build "agentcon/stall-test:cli-${i}")"
    printf 'cli %s: %s\n' "${i}" "${outcome}"
    CLI_RUNS+="${outcome} "
  done
  STEP="done"
  STATUS="success"
  MESSAGE="ran ${RUNS} api and ${RUNS} cli builds"
}

main "$@"
