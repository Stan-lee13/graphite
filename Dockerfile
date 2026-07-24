# Graphite Core Server - Multi-stage Dockerfile
# Build:  docker build -t graphite-core .
# Run:    docker run -p 7331:7331 graphite-core
# Constitution P1: Only deterministic Rust core. Python AI Layer runs separately.
# Manifests are compile-time baked via include_str! (P12 fail-closed).

FROM rust:1.82-bookworm AS builder
WORKDIR /usr/src/graphite

# Copy Cargo.toml and Cargo.lock for dependency caching
COPY graphite-core/Cargo.toml graphite-core/Cargo.lock ./graphite-core/

# Pre-build dependencies with dummy source
RUN mkdir -p graphite-core/src && echo "pub fn _dummy() {}" > graphite-core/src/lib.rs
RUN cargo build --manifest-path graphite-core/Cargo.toml --release --features server 2>/dev/null || true

# Copy actual source and protocols (needed for include_str! at compile time)
COPY graphite-core/src ./graphite-core/src
COPY graphite-core/protocols ./graphite-core/protocols

# Build the real binary
RUN touch graphite-core/src/lib.rs && cargo build --manifest-path graphite-core/Cargo.toml --release --features server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && apt-get clean
COPY --from=builder /usr/src/graphite/target/release/graphite /usr/local/bin/graphite
RUN useradd -r -s /bin/false graphite
USER graphite
EXPOSE 7331
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl -f http://localhost:7331/health || exit 1
CMD ["graphite", "server"]
