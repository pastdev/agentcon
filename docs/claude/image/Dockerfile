FROM registry.access.redhat.com/ubi10/ubi:10.2

RUN --mount=type=cache,target=/var/cache/libdnf5,sharing=locked \
    <<'EOF'
set -exo pipefail
dnf install --assumeyes --setopt=keepcache=1 git tar gzip findutils curl
mkdir --parents /agent/claude /agent/claude-install
chmod g=u /etc/passwd /home /agent/claude /agent/claude-install
EOF

COPY contrib/ /

# CLI tools agents use while searching, editing, and talking to GitHub.
RUN --mount=type=cache,target=/var/cache/libdnf5,sharing=locked \
    --mount=type=cache,target=/var/cache/agentcon,sharing=locked \
    <<'EOF'
set -exo pipefail
dnf install --assumeyes --setopt=keepcache=1 \
    python3 \
    procps-ng \
    diffutils \
    patch \
    make \
    unzip \
    which \
    file \
    less \
    hostname \
    openssl \
    rsync
chmod +x /usr/local/share/agentcon/scripts/*.sh
/usr/local/share/agentcon/scripts/install_cli_tools.sh
EOF

RUN --mount=type=cache,target=/var/cache/agentcon,sharing=locked \
    <<'EOF'
set -exo pipefail
chmod +x /usr/local/share/agentcon/scripts/*.sh
/usr/local/share/agentcon/scripts/install_go.sh
/usr/local/share/agentcon/scripts/install_golangci_lint.sh
/usr/local/share/agentcon/scripts/install_node.sh
EOF

ENTRYPOINT [ "/entrypoint.sh" ]
