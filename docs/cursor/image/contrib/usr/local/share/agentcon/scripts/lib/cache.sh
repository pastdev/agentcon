# Shared helpers for BuildKit cache mounts under AGENTCON_CACHE_DIR.

AGENTCON_CACHE_DIR="${AGENTCON_CACHE_DIR:-/var/cache/agentcon}"

function cache_dest {
  local path url
  url="${1}"
  path="${url#http://}"
  path="${path#https://}"

  if [[ -z "${path}" || "${path}" == *..* ]]; then
    echo "refusing unsafe cache url: ${url}" >&2
    return 1
  fi

  printf '%s\n' "${AGENTCON_CACHE_DIR}/${path}"
}

function cache_fetch {
  local dest sha url
  url="${1}"
  sha="${2:-}"
  dest="$(cache_dest "${url}")"

  mkdir --parents "$(dirname "${dest}")"
  if [[ ! -f "${dest}" ]]; then
    curl --fail --silent --show-error --location \
      --output "${dest}.partial" \
      "${url}"
    mv "${dest}.partial" "${dest}"
  fi

  if [[ -n "${sha}" ]]; then
    echo "${sha}  ${dest}" | sha256sum --check --status
  fi

  printf '%s\n' "${dest}"
}
