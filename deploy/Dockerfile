# yara-sync, as a container.
#
# The host it runs on carries no Rust toolchain, no Caddy and no cloudflared —
# every service there is a container, and adding a language toolchain to a
# shared machine to build one binary is the kind of drift that makes a server
# impossible to reason about later. So the toolchain lives in a build stage and
# is thrown away.
#
# rusqlite is `bundled`, so there is no libsqlite3 to install and no chance of
# the build and the runtime disagreeing about its version. reqwest is on
# rustls, so there is no OpenSSL either. What survives into the runtime is one
# static-ish binary and a CA bundle.

FROM rust:1-bookworm AS build
WORKDIR /src

# The whole workspace, because Cargo has to parse every member's manifest to
# resolve the lockfile even when only one package is asked for. `-p yara-sync`
# is what keeps it from *compiling* the rest — which matters, because the
# broker's transport is named pipes and does not build on Linux at all.
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p yara-sync && \
    cp target/release/yara-sync /usr/local/bin/yara-sync

FROM debian:bookworm-slim

# ca-certificates is not optional: the icon proxy fetches favicons over TLS,
# and without a trust store every fetch fails in a way that looks like the
# remote site being down.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# A fixed uid rather than a name lookup, so the bind-mounted state directory on
# the host has stable ownership that does not depend on what order Debian
# happened to allocate system users in.
RUN groupadd --gid 10001 yara && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin yara

COPY --from=build /usr/local/bin/yara-sync /usr/local/bin/yara-sync

USER 10001:10001

# The binary defaults to 127.0.0.1:8787 because it was written for a machine
# where Caddy sat on the same loopback. Here Caddy is a different container, so
# it has to bind the container's interface — and what replaces loopback as the
# thing keeping strangers out is the compose network: this port is never
# published, so nothing outside the `app` network can open it.
ENV YARA_SYNC_ADDR=0.0.0.0:8787 \
    YARA_SYNC_DB=/var/lib/yara-sync/sync.db

EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/yara-sync"]
