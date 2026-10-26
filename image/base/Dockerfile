FROM registry.access.redhat.com/ubi10/ubi:10.2

RUN --mount=type=cache,target=/var/cache/libdnf5,sharing=locked \
    <<'EOF'
set -exo pipefail
dnf install --assumeyes --setopt=keepcache=1 git tar gzip findutils
mkdir --parents /agent/cursor
chmod g=u /etc/passwd /home /agent/cursor
EOF

COPY contrib/ /

RUN --mount=type=cache,target=/var/cache/agentcon,sharing=locked \
    <<'EOF'
set -exo pipefail
chmod +x /usr/local/share/agentcon/scripts/*.sh
/usr/local/share/agentcon/scripts/install_go.sh
/usr/local/share/agentcon/scripts/install_golangci_lint.sh
/usr/local/share/agentcon/scripts/install_node.sh
EOF

ENTRYPOINT [ "/entrypoint.sh" ]
