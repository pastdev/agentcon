FROM registry.access.redhat.com/ubi10/ubi-minimal:10.2

COPY . /context

# The heredoc and cache mount need BuildKit. The checks fail the build when
# the context is missing a file it should have or holds one it should not.
RUN --mount=type=cache,target=/var/cache/agentcon-test <<'EOF_RUN'
set -e
test -e /context/kept.txt
test ! -e /context/ignored.txt
date > /var/cache/agentcon-test/last-build
EOF_RUN
