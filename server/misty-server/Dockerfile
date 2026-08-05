# SPDX-FileCopyrightText: 2026 The Misty Authors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Build from the repository root, not from this directory — the build needs the
# workspace manifest and `Cargo.lock`:
#
#   docker build -f server/misty-server/Dockerfile -t misty-server .
#
# The repository root should carry a `.dockerignore` containing at least `target/`
# and `.git/`; without one, every byte of the build directory is uploaded to the
# daemon before anything happens. The `COPY` lines below name only what the build
# needs, so the image layers stay small either way.
#
# TLS is NOT terminated in this image. Put a reverse proxy that speaks TLS 1.3 in
# front of it. See README.md.

FROM rust:1-bookworm AS build

WORKDIR /src
# `rusqlite`'s bundled SQLite is C, so the build stage needs a compiler. It is
# present in the `rust` image; the runtime stage below does not need one, which is
# the whole reason for the split.
#
# `--locked` means the build fails rather than silently resolving a different
# dependency graph than the one that was tested.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY server ./server
RUN cargo build --release --locked -p misty-server

# The workspace release profile already strips symbols and sets `panic = "abort"`,
# so nothing further is done to the binary here.

FROM debian:bookworm-slim

# A fixed numeric uid so a volume mounted from the host has predictable ownership
# and so the container runs as the same unprivileged identity under a runtime that
# ignores the image's user database.
RUN set -eux; \
    groupadd --system --gid 10001 misty; \
    useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/misty misty; \
    mkdir -p /var/lib/misty; \
    chown 10001:10001 /var/lib/misty

COPY --from=build /src/target/release/misty-server /usr/local/bin/misty-server

USER 10001:10001
WORKDIR /var/lib/misty
VOLUME ["/var/lib/misty"]

# 0.0.0.0 inside a container is the container's own network namespace, not the
# host's. Publish it only behind a TLS proxy.
ENV MISTY_BIND=0.0.0.0:8080 \
    MISTY_DB=/var/lib/misty/misty.sqlite3 \
    MISTY_LOG=info

EXPOSE 8080

# No HEALTHCHECK: this image deliberately contains no HTTP client, and adding
# `curl` to a minimal runtime purely so Docker can poll `/healthz` is a poor
# trade. Use the orchestrator's own probe against `GET /healthz`, which checks
# storage as well as liveness.

ENTRYPOINT ["/usr/local/bin/misty-server"]
