# ─── Graphite Core Server — Multi-stage Dockerfile ───────────────
#
# Builds the Graphite verification server as a standalone container.
# The server exposes POST /verify, GET /health, GET /manifests on port 7331.
#
# Build:  docker build -t graphite-core .
# Run:    docker run -p 7331:7331 graphite-core
#
# Constitution P1: This container runs ONLY the deterministic Rust core.
# The Python AI Layer (advisory) must run as a SEPARATE container/process.

# ─── Stage 1: Build ──────────────────────────────────────────────
FROM rust:1.82-bookworm AS builder

WORKDIR /usr/src/graphite

# Copy manifest first for better layer caching
COPY graphite-core/Cargo.toml graphite-core/Cargo.lock* ./graphite-core/
COPY Cargo.toml Cargo.lock* ./

# Copy source
COPY graphite-core/src ./graphite-core/src
COPY graphite-core/tests ./graphite-core/tests
COPY graphite-core/benches ./graphite-core/benches

# Build release binary with server feature
RUN cargo build --manifest-path graphite-core/Cargo.toml --release --features server

# ─── Stage 2: Runtime ────────────────────────────────────────────
FROM debian:bookworm-slim

# Install minimal runtime deps (ca-certificates for HTTPS, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the release binary
COPY --from=builder /usr/src/graphite/target/release/graphite /usr/local/bin/graphite

# Non-root user for security
RUN useradd -r -s /bin/false graphite
USER graphite

# Expose the verification server port
EXPOSE 7331

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:7331/health || exit 1

# Run the server
CMD ["graphite", "server"]
