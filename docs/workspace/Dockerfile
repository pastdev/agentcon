# Minimal image that honors the README workspace contract.
# It is not an agent.
# The entrypoint creates a passwd line and home, then starts a mock.

FROM registry.access.redhat.com/ubi10/ubi-minimal:10.2

RUN mkdir --parents /home \
    && chmod g=u /etc/passwd /home

COPY <<'EOF' /entrypoint.sh
#!/bin/bash
set -euo pipefail

readonly AGENT_USER="${USER:-agent}"
readonly HOME="/home/${AGENT_USER}"
export HOME

function setup_user {
  printf '%s:x:%s:%s:Agent:%s:/bin/bash\n' \
    "${AGENT_USER}" \
    "$(id -u)" \
    "$(id -g)" \
    "${HOME}" \
    >> /etc/passwd
  mkdir --parents "${HOME}"
}

function mock_agent {
  printf 'mock agent uid=%s gid=%s home=%s cwd=%s host_root=%s\n' \
    "$(id -u)" \
    "$(id -g)" \
    "${HOME}" \
    "$(pwd)" \
    "${AGENTCON_HOST_ROOT:-}"
  if [[ "$#" -eq 0 ]]; then
    exec /bin/bash
  fi
  exec "$@"
}

setup_user
mock_agent "$@"
EOF

RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
