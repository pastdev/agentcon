#!/bin/bash

set -euo pipefail

readonly PROJECT_ROOT_DIR="$(dirname \
  "$(readlink --canonicalize-existing "${0}")")"
readonly IMAGE_TAG="pastdev.com/agentcon:latest"

readonly HARNESS="${HARNESS:-cursor}"
readonly WORKSPACE="${WORKSPACE:-"${HOME}/git"}"

function build {
  docker build \
    --progress plain \
    --tag "${IMAGE_TAG}" \
    "${PROJECT_ROOT_DIR}/image/base/"
}

function error_exit {
  echo "${1}" >&2
  exit "${2:-1}"
}

function run {
  local cmd workdir

  cmd=(
    docker run
    --group-add 0
    --interactive
    --mount "type=bind,source=${WORKSPACE},target=/workspace"
    --rm
    --tty
    --user "$(id -u):$(id -g)"
  )

  if [[ "$(pwd)" == "${WORKSPACE}" || "$(pwd)" == "${WORKSPACE}"/* ]]; then
    workdir="$(realpath --relative-to="${WORKSPACE}" .)"
  else
    workdir="/workspace"
  fi
  cmd+=(--workdir "/workspace/${workdir}")

  case "${HARNESS}" in
    cursor)
      mkdir --parents "${HOME}/.cursor"
      cmd+=(
        --mount "type=bind,source=${HOME}/.cursor,target=/agent/cursor"
      )
      ;;
    *)
      error_exit "unsupported harness '${HARNESS}'"
      ;;
  esac

  cmd+=("${IMAGE_TAG}" "$@")

  echo "running: $(printf '%s ' "${cmd[@]}" | sed 's/ $//')" >&2
  "${cmd[@]}"
}

function main {
  build
  run "$@"
}

main "$@"
