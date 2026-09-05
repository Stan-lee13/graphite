# Graphite Core Server - Multi-stage Dockerfile
# Build:  docker build -t graphite-core .
# Run:    docker run -p 7331:7331 -e GRAPHITE_API_KEY=... graphite-core
# Constitution P1: Only deterministic Rust core. Python AI Layer runs separately.
# Manifests are compile-time baked via include_str! (P12 fail-closed).

FROM rust:1.97-bookworm AS builder
WORKDIR /usr/src/graphite
# Cargo places target/ under the workspace root (graphite-core/) unless told
# otherwise; pin it so the COPY below can find the binary.
ENV CARGO_TARGET_DIR=/usr/src/graphite/target

# Copy Cargo.toml and Cargo.lock for dependency caching
COPY graphite-core/Cargo.toml graphite-core/Cargo.lock ./graphite-core/

# Pre-build dependencies against stub sources so this layer caches
# independently of application source changes.
#
# The stub set must satisfy EVERY target Cargo will try to resolve for the
# selected features, not just the library. `Cargo.toml` declares
# `[[bin]] name = "graphite" path = "src/bin/graphite.rs"` with
# `required-features = ["cli"]`, and `cli` is enabled below — so omitting the
# bin stub made Cargo abort at TARGET RESOLUTION ("can't find bin"), before
# compiling a single dependency. Combined with `2>/dev/null || true` that
# failure was invisible, and this layer cached nothing at all: every image
# build recompiled the entire dependency tree from scratch while claiming to
# be a cache step (found by the 2026-09-05 deployment audit).
RUN mkdir -p graphite-core/src/bin \
    && echo "pub fn _dummy() {}" > graphite-core/src/lib.rs \
    && echo "fn main() {}" > graphite-core/src/bin/graphite.rs
# No error suppression: if dependency compilation genuinely breaks, the build
# must fail here rather than silently degrade into an uncached rebuild.
RUN cargo build --manifest-path graphite-core/Cargo.toml --locked --release --features server,cli

# Copy actual source and protocols (needed for include_str! at compile time)
COPY graphite-core/src ./graphite-core/src
COPY graphite-core/protocols ./graphite-core/protocols

# Build the real binary. `--locked` fails the build if Cargo.lock and
# Cargo.toml have drifted, rather than silently re-resolving to different
# dependency versions than the ones that were tested.
RUN touch graphite-core/src/lib.rs \
    && cargo build --manifest-path graphite-core/Cargo.toml --locked --release --features server,cli

FROM debian:bookworm-slim
# ca-certificates is required for outbound TLS to GRAPHITE_RPC_URL (reqwest +
# rustls needs a trust store). curl is NOT installed: the healthcheck uses the
# binary's own `healthcheck` subcommand instead, keeping curl and its
# transitive libraries (libcurl, libssh2, libpsl, …) out of the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/graphite/target/release/graphite /usr/local/bin/graphite

# Fixed UID/GID (not an auto-allocated system UID) so the ownership of a
# mounted volume is predictable across rebuilds and can be matched by the
# host / compose `user:` directive.
#
# /data must exist AND be owned by the runtime user BEFORE the volume is
# mounted: Docker seeds a fresh named volume from the image's directory
# (including its ownership). Without this, the engine creates /data as
# root:root 0755, the unprivileged process cannot write, and the append-only
# audit trail silently never lands (Constitution P9). The server now probes
# writability at startup and refuses to boot if this regresses, so a
# misconfiguration fails loudly instead of serving un-audited traffic.
RUN groupadd -g 10001 graphite \
    && useradd -r -u 10001 -g graphite -s /usr/sbin/nologin graphite \
    && mkdir -p /data \
    && chown -R graphite:graphite /data
VOLUME ["/data"]
ENV GRAPHITE_DATA_DIR=/data

USER 10001:10001
EXPOSE 7331
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["graphite", "healthcheck"]
# 0.0.0.0 is explicit here because the CLI now defaults to loopback (so a bare
# `graphite server` on a host machine is not silently network-exposed). Inside
# a container, binding all interfaces is required for the published port to
# work, and the container boundary plus the mandatory GRAPHITE_API_KEY are what
# constrain exposure — the server refuses to bind a non-loopback address with
# no API key set.
CMD ["graphite", "server", "--host", "0.0.0.0"]
