# yara-sync, as a container.
#
# This image does not compile anything. It wraps the binary the release
# workflow already built, signed off with a checksum, and published as a
# release asset — `yara-sync-<version>-x86_64-linux`. Building from source here
# meant the deploy host ran a full Rust build of whatever happened to be
# checked out at /opt/yara, which is a different binary from the one CI tested
# and a Rust toolchain's worth of moving parts on a machine shared with other
# projects.
#
#   docker build deploy --build-arg YARA_VERSION=0.4.5
#
# What the checksum buys, stated plainly: it catches a truncated or corrupted
# download and pins the image to the exact artifact of that release. It is not
# a signature — the binary and its .sha256 come from the same place, so anyone
# who could replace one could replace the other. What actually guards this is
# that the release workflow is the only thing that writes there and that
# installing a new binary stays a deliberate act by an operator.
ARG YARA_VERSION
ARG YARA_REPO=sf0rzin/yara

FROM ubuntu:24.04 AS fetch
ARG YARA_VERSION
ARG YARA_REPO

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /fetch

# Fail here rather than downloading a URL with an empty version in it, which
# 404s in a way that reads like the release being missing.
RUN test -n "${YARA_VERSION}" || { echo "build with --build-arg YARA_VERSION=x.y.z" >&2; exit 1; }

RUN base="https://github.com/${YARA_REPO}/releases/download/v${YARA_VERSION}" && \
    name="yara-sync-${YARA_VERSION}-x86_64-linux" && \
    curl -fsSL --retry 3 -O "${base}/${name}" -O "${base}/${name}.sha256" && \
    sha256sum -c "${name}.sha256" && \
    install -m 0755 "${name}" /usr/local/bin/yara-sync

# Ubuntu 24.04 rather than a Debian slim image, and not by preference: the
# binary is linked against the glibc of the runner that built it, which
# release.yml pins to ubuntu-24.04 for this reason. A bookworm base is two glibc
# releases behind and the container simply fails to start, with a symbol
# version error that names neither file.
FROM ubuntu:24.04

# ca-certificates is not optional: the icon proxy fetches favicons over TLS,
# and without a trust store every fetch fails in a way that looks like the
# remote site being down.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# A fixed uid rather than a name lookup, so the bind-mounted state directory on
# the host has stable ownership that does not depend on what order the base
# image happened to allocate system users in.
RUN groupadd --gid 10001 yara && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin yara

COPY --from=fetch /usr/local/bin/yara-sync /usr/local/bin/yara-sync

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
