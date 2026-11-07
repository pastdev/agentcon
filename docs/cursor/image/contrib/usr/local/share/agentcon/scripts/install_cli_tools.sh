#!/bin/bash
# Install CLI tools Cursor agents use while searching, editing, and talking to GitHub.

set -euo pipefail

# shellcheck source=lib/cache.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/cache.sh"

readonly BIN_DIR="${BIN_DIR:-/usr/local/bin}"
readonly PROFILE_DIR="${PROFILE_DIR:-/etc/profile.d}"
readonly PROFILE_FILE="${PROFILE_DIR}/cli_tools.sh"
readonly FD_VERSION="${FD_VERSION:-v10.5.2}"
readonly GH_VERSION="${GH_VERSION:-2.103.3}"
readonly JQ_VERSION="${JQ_VERSION:-1.8.2}"
readonly RIPGREP_VERSION="${RIPGREP_VERSION:-15.2.0}"
readonly SHELLCHECK_VERSION="${SHELLCHECK_VERSION:-v0.11.0}"
readonly YQ_VERSION="${YQ_VERSION:-v4.54.2}"

function uname_m {
  uname -m
}

function install_binary {
  local dest src
  src="${1}"
  dest="${2}"
  install --mode 0755 "${src}" "${dest}"
}

function install_jq {
  local arch sha url
  case "$(uname_m)" in
    x86_64)
      arch=amd64
      sha=b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f
      ;;
    aarch64)
      arch=arm64
      sha=8b85c817833814ddca00a144c33705546355afccf0cf39b188f3cdb48b852309
      ;;
    *)
      echo "unsupported arch $(uname_m)" >&2
      return 1
      ;;
  esac
  url="https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-${arch}"
  install_binary "$(cache_fetch "${url}" "${sha}")" "${BIN_DIR}/jq"
}

function install_yq {
  local arch sha url
  case "$(uname_m)" in
    x86_64)
      arch=amd64
      sha=44c7759059b4910827a0059a2757b22001e59360cdecdb2ef8dedc4b6c7e9f32
      ;;
    aarch64)
      arch=arm64
      sha=bd44211dcd29a5f0eb701d4b7eb5ccd0cfff3bd3966cb4f7f9bd5b13701d997e
      ;;
    *)
      echo "unsupported arch $(uname_m)" >&2
      return 1
      ;;
  esac
  url="https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${arch}"
  install_binary "$(cache_fetch "${url}" "${sha}")" "${BIN_DIR}/yq"
}

function install_ripgrep {
  local dest name sha url
  case "$(uname_m)" in
    x86_64)
      name="ripgrep-${RIPGREP_VERSION}-x86_64-unknown-linux-musl"
      sha=33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c
      ;;
    aarch64)
      name="ripgrep-${RIPGREP_VERSION}-aarch64-unknown-linux-musl"
      sha=800b1e7206afe799dfb5a6901f23147cfaabe0e52210538100f61e86e1740915
      ;;
    *)
      echo "unsupported arch $(uname_m)" >&2
      return 1
      ;;
  esac
  url="https://github.com/BurntSushi/ripgrep/releases/download/${RIPGREP_VERSION}/${name}.tar.gz"
  dest="$(cache_fetch "${url}" "${sha}")"
  tar --directory /tmp --extract --gzip --file "${dest}" "${name}/rg"
  install_binary "/tmp/${name}/rg" "${BIN_DIR}/rg"
  rm --recursive --force "/tmp/${name}"
}

function install_fd {
  local dest name sha url version
  version="${FD_VERSION}"
  case "$(uname_m)" in
    x86_64)
      name="fd-${version}-x86_64-unknown-linux-musl"
      sha=7e2d07fa2b8807642aaec67b7e2972a9fbe4db26fcb340a7372392db42b26694
      ;;
    aarch64)
      name="fd-${version}-aarch64-unknown-linux-musl"
      sha=63ea52cb31586e6d98efa2f06d73d542f16c7d0c4af0f07b579aaf9714cf907a
      ;;
    *)
      echo "unsupported arch $(uname_m)" >&2
      return 1
      ;;
  esac
  url="https://github.com/sharkdp/fd/releases/download/${version}/${name}.tar.gz"
  dest="$(cache_fetch "${url}" "${sha}")"
  tar --directory /tmp --extract --gzip --file "${dest}" "${name}/fd"
  install_binary "/tmp/${name}/fd" "${BIN_DIR}/fd"
  rm --recursive --force "/tmp/${name}"
}

function install_gh {
  local dest name sha url
  case "$(uname_m)" in
    x86_64)
      name="gh_${GH_VERSION}_linux_amd64"
      sha=4c806978ffce1cec70853302a56d70ac6da4f19bae7acca4e1a8ab00633dd91d
      ;;
    aarch64)
      name="gh_${GH_VERSION}_linux_arm64"
      sha=ee32df2323c8847f5fac6cb6b4b69ca75828e9329a8f22f677021f7b3306ce63
      ;;
    *)
      echo "unsupported arch $(uname_m)" >&2
      return 1
      ;;
  esac
  url="https://github.com/cli/cli/releases/download/v${GH_VERSION}/${name}.tar.gz"
  dest="$(cache_fetch "${url}" "${sha}")"
  tar --directory /tmp --extract --gzip --file "${dest}" "${name}/bin/gh"
  install_binary "/tmp/${name}/bin/gh" "${BIN_DIR}/gh"
  rm --recursive --force "/tmp/${name}"
}

function install_shellcheck {
  local dest name sha url
  case "$(uname_m)" in
    x86_64)
      name="shellcheck-${SHELLCHECK_VERSION}.linux.x86_64"
      sha=b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6
      ;;
    aarch64)
      name="shellcheck-${SHELLCHECK_VERSION}.linux.aarch64"
      sha=68a8133197a50beb8803f8d42f9908d1af1c5540d4bb05fdfca8c1fa47decefc
      ;;
    *)
      echo "unsupported arch $(uname_m)" >&2
      return 1
      ;;
  esac
  url="https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/${name}.tar.gz"
  dest="$(cache_fetch "${url}" "${sha}")"
  tar --directory /tmp --extract --gzip --file "${dest}" \
    "shellcheck-${SHELLCHECK_VERSION}/shellcheck"
  install_binary \
    "/tmp/shellcheck-${SHELLCHECK_VERSION}/shellcheck" \
    "${BIN_DIR}/shellcheck"
  rm --recursive --force "/tmp/shellcheck-${SHELLCHECK_VERSION}"
}

function write_profile {
  mkdir --parents "${PROFILE_DIR}"
  cat >"${PROFILE_FILE}" <<EOF
# Generated by install_cli_tools.sh
export PATH="${BIN_DIR}:\${PATH}"
EOF
}

function main {
  mkdir --parents "${BIN_DIR}"
  install_jq
  install_yq
  install_ripgrep
  install_fd
  install_gh
  install_shellcheck
  write_profile
}

main "$@"
