#!/usr/bin/env bash
#
# Verify issue 26: image builds through a BuildKit session on Docker Desktop.
#
# Kept for the record. It ran as .agentcon/session-build.handoff.sh, next to
# agentcon and moby integration test binaries cross-compiled from this
# branch into .agentcon/bin. Copy it back there to rerun.
#
# 2026-11-11, from a Docker-outside-of-Docker container on Docker Desktop:
#   integration: pass, five session builds in 2.87s, the slowest 0.77s.
#   run: ok five times, 1 to 3 seconds each including the session build.
#   stall: not run. The old tar upload path stalled 3 of 5 times on the same
#   host before this change, as recorded in issue 26.
# An earlier version wrapped agentcon run in timeout without --foreground.
# timeout then runs it in a background process group, so run's raw terminal
# setup stopped it with SIGTTOU between attach and start. That looked like a
# hang in attach until the stopped process failed with "set raw terminal:
# input/output error" once the script was killed.
#
# Run it from the Docker-outside-of-Docker container, from any directory:
#   SMOKE_CA_FILE=<ca.pem> bash .agentcon/session-build.handoff.sh
#
# 1. integration: the moby integration test binary, built from this branch
#    with -tags integration, builds a BuildKit-only context five times under
#    90 second deadlines and checks .dockerignore.
# 2. run: agentcon run with build set on the mock workspace image and no
#    bouncer, RUNS times, each under TRY_SECONDS.
# 3. stall: ad_hoc/issue-25/smoke/build-stall.handoff.sh again, which posts
#    the old tar body with curl, to show that path still stalls on this host.
#    SMOKE_CA_FILE is passed to it so its build can finish when it does not
#    stall.
#
# RUNS (default 5) and TRY_SECONDS (default 300) are optional.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE
REPO="$(cd "${HERE}/.." && pwd)"
readonly REPO
readonly RESULT="${HERE}/session-build.handoff.result"
RUNS="${RUNS:-5}"
readonly RUNS
export RUNS
readonly TRY_SECONDS="${TRY_SECONDS:-300}"
readonly RUN_IMAGE="agentcon/session-build-run:latest"

STEP="start"
STATUS="failed"
MESSAGE=""
INTEGRATION=""
INTEGRATION_DETAIL=""
RUN_RUNS=""
STALL_API=""
STALL_CLI=""
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
    printf 'integration=%s\n' "${INTEGRATION}"
    printf 'integration_detail=%s\n' "$(flat "${INTEGRATION_DETAIL}")"
    printf 'run_runs=%s\n' "${RUN_RUNS}"
    printf 'stall_api_runs=%s\n' "${STALL_API}"
    printf 'stall_cli_runs=%s\n' "${STALL_CLI}"
  } > "${RESULT}"
  if [[ -n "${WORK}" ]]; then
    rm -rf "${WORK:?}"
  fi
  docker image rm "${RUN_IMAGE}" > /dev/null 2>&1 || true
  printf '\nResult written to %s\n' "${RESULT}"
}
trap write_result EXIT

function arch {
  case "$(uname -m)" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) uname -m ;;
  esac
}

function integration {
  local bin out rc=0
  bin="${HERE}/bin/moby-integration-linux-$(arch).test"
  if [[ ! -x "${bin}" ]]; then
    MESSAGE="missing ${bin}"
    exit 1
  fi
  # The test reads its context from testdata beside the package.
  out="$(cd "${REPO}/pkg/container/moby" && "${bin}" -test.v -test.run TestBuildIntegration 2>&1 | tee /dev/stderr)" || rc=$?
  INTEGRATION_DETAIL="$(grep -E '^\s*--- (PASS|FAIL|SKIP)' <<< "${out}" || true)"
  if ((rc != 0)); then
    INTEGRATION="fail"
  elif grep -q -- '--- SKIP' <<< "${out}"; then
    INTEGRATION="skip"
  else
    INTEGRATION="pass"
  fi
}

function run_builds {
  local bin root i rc start
  bin="${HERE}/bin/agentcon-linux-$(arch)"
  root="${WORK}/root"
  mkdir -p "${WORK}/xdg/agentcon.d" "${root}/project"
  cat > "${WORK}/xdg/agentcon.d/run.yaml" << EOF_CONFIG
default_context: run
agents:
  mock:
    image: ${RUN_IMAGE}
    build:
      context: ${REPO}/docs/workspace
contexts:
  run:
    agent: mock
    root: ${root}
EOF_CONFIG
  for ((i = 1; i <= RUNS; i++)); do
    rc=0
    start=${SECONDS}
    # --foreground keeps agentcon in the terminal's foreground process group.
    # Without it, run's raw terminal setup stops the process with SIGTTOU.
    (cd "${root}/project" &&
      XDG_CONFIG_HOME="${WORK}/xdg" timeout --foreground -s KILL "${TRY_SECONDS}" \
        "${bin}" --log warn run --no-bouncer -- true) || rc=$?
    # A killed run leaves its container behind.
    docker ps --all --quiet --filter label=agentcon.context=run | xargs -r docker rm --force > /dev/null 2>&1 || true
    if ((rc == 137)); then
      RUN_RUNS+="stall@$((SECONDS - start))s "
    elif ((rc != 0)); then
      RUN_RUNS+="error${rc}@$((SECONDS - start))s "
    else
      RUN_RUNS+="ok@$((SECONDS - start))s "
    fi
    printf 'run %s: %s\n' "${i}" "$(awk '{print $NF}' <<< "${RUN_RUNS}")" >&2
  done
}

function stall {
  local copy="${HERE}/build-stall.handoff.sh"
  cp "${REPO}/ad_hoc/issue-25/smoke/build-stall.handoff.sh" "${copy}"
  # The stall script reads RUNS itself, and it is already exported here.
  bash "${copy}" || true
  STALL_API="$(sed -n 's/^api_runs=//p' "${HERE}/build-stall.handoff.result")"
  STALL_CLI="$(sed -n 's/^cli_runs=//p' "${HERE}/build-stall.handoff.result")"
  rm -f "${copy}" "${HERE}/build-stall.handoff.result"
}

function main {
  WORK="$(mktemp -d "${HERE}/work.XXXXXX")"
  STEP="integration"
  integration
  STEP="run"
  run_builds
  STEP="stall"
  stall
  STEP="done"
  if [[ "${INTEGRATION}" == "pass" && "${RUN_RUNS}" != *stall* && "${RUN_RUNS}" != *error* ]]; then
    STATUS="success"
    MESSAGE="session builds passed"
  else
    MESSAGE="expected integration=pass and every run ok"
  fi
}

main "$@"
