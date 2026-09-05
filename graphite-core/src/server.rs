//! HTTP server for Graphite Core — exposes the verification API over HTTP.
//!
//! Production features:
//! - Optional API-key auth (`GRAPHITE_API_KEY` env; Bearer token, constant-time
//!   comparison). When unset the API is unauthenticated — set it in production.
//! - Per-IP rate limiting (`GRAPHITE_RATE_LIMIT` requests/second, default 30)
//! - CORS: denied by default; allow origins via `GRAPHITE_CORS_ORIGINS`
//!   (comma-separated). Servers calling the API don't need CORS at all.
//! - Request body size limit (1 MB max — prevents DoS via large payloads)
//! - Request timeout (10s max — prevents slow-loris attacks)
//! - Optional live L3 simulation: `GRAPHITE_RPC_URL` attaches a Solana RPC
//!   client so `simulateTransaction` actually runs (real compute usage feeds
//!   the trusted simulation baseline accumulator).
//! - Durability: `GRAPHITE_DATA_DIR` (default `./graphite-data`) holds the
//!   semantic-graph snapshot and an append-only `audit.jsonl` written after
//!   every verification.
//! - Graceful shutdown on SIGTERM/SIGINT (container-friendly)

use crate::account_resolution::AccountResolutionError;
use crate::durable::{audit_path, AuditErrorRecord, AuditLog, AuditRecord};
use crate::verification::{GraphiteCore, VerificationError, VerificationInput, VerificationResult};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::signal;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

/// Maximum request body size (1 MB). Verification inputs are small —
/// 10 accounts x 44 bytes + metadata ~= 2 KB. 1 MB is generous.
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Request timeout. Verification should complete in <1ms; 10s is
/// generous and prevents slow-loris style attacks.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Dashboard series caps: the confidence chart and the violations list only
/// ever materialize this many points per request (memory stays bounded as
/// the audit log grows); the response still reports the true totals.
const CONFIDENCE_SERIES_CAP: usize = 500;
const VIOLATIONS_CAP: usize = 200;

/// Shared application state.
#[derive(Clone)]
struct AppState {
    core: GraphiteCore,
    /// Bearer API key; `None` = unauthenticated (dev only).
    api_key: Option<Arc<String>>,
    audit: Option<AuditLog>,
    /// Community Manifest Registry engine (read-only dashboard view — P4).
    registry_engine: crate::manifest_registry::ManifestRegistryEngine,
    rate: RateLimiter,
    /// Only honor `X-Forwarded-For` when behind a trusted proxy.
    trust_proxy_hops: u8,
    /// Operational counters exported at `/metrics`.
    metrics: Metrics,
}

/// Process-lifetime counters for `/metrics`.
///
/// Deliberately a small set that is genuinely maintained at the point each
/// event happens — a metrics surface that looks comprehensive but is never
/// incremented is worse than none, because operators build alerts on it.
#[derive(Clone, Default)]
struct Metrics {
    verify_requests: Arc<std::sync::atomic::AtomicU64>,
    verify_approved: Arc<std::sync::atomic::AtomicU64>,
    verify_blocked: Arc<std::sync::atomic::AtomicU64>,
    verify_errors: Arc<std::sync::atomic::AtomicU64>,
    auth_failures: Arc<std::sync::atomic::AtomicU64>,
    rate_limited: Arc<std::sync::atomic::AtomicU64>,
}

impl Metrics {
    fn inc(counter: &Arc<std::sync::atomic::AtomicU64>) {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Per-IP token bucket (GCRA-style). Shared across clones via Arc.
///
/// The bucket map is BOUNDED at `MAX_BUCKETS` distinct IPs. When at capacity
/// the OLDEST-INSERTED bucket is evicted via a FIFO ring — O(1) amortized, so
/// an attacker rotating (spoofed, when behind a trusted proxy) IPs can never
/// trigger an O(n) full-map sweep. The previous implementation swept the
/// entire bucket map on every request at capacity, which was itself a CPU-DoS
/// vector at the exact layer meant to prevent DoS.
///
/// Tradeoff (recorded per Constitution P14): FIFO eviction means a client can
/// re-enter with a fresh bucket once MAX_BUCKETS distinct IPs have appeared.
/// At that scale per-IP limiting has already lost meaning, and bounding memory
/// is the priority.
#[derive(Clone)]
struct RateLimiter {
    buckets: Arc<Mutex<RateLimiterInner>>,
    per_second: f64,
    max_buckets: usize,
}

struct RateLimiterInner {
    buckets: HashMap<IpAddr, Bucket>,
    /// Insertion order, used as the FIFO eviction ring (bounded by MAX_BUCKETS).
    order: std::collections::VecDeque<IpAddr>,
}

const MAX_BUCKETS: usize = 1_000_000;

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(per_second: f64) -> Self {
        Self::with_capacity(MAX_BUCKETS, per_second)
    }

    /// Constructor with an explicit bucket cap (the production default is
    /// `MAX_BUCKETS`; small caps are used in tests to exercise FIFO eviction).
    fn with_capacity(max_buckets: usize, per_second: f64) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(RateLimiterInner {
                buckets: HashMap::new(),
                order: std::collections::VecDeque::new(),
            })),
            per_second: per_second.max(0.1),
            max_buckets: max_buckets.max(1),
        }
    }

    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut inner = self.buckets.lock().unwrap_or_else(|p| p.into_inner());

        // Bounded map: evict the oldest-inserted IP when a NEW IP arrives at
        // capacity. The while-loop amortizes to O(1): each pop_front removes
        // one entry from the ring even when the corresponding bucket was
        // already gone.
        if !inner.buckets.contains_key(&ip) && inner.buckets.len() >= self.max_buckets {
            while let Some(oldest) = inner.order.pop_front() {
                if inner.buckets.remove(&oldest).is_some() {
                    break;
                }
            }
        }

        // All map/ring mutations happen BEFORE the entry borrow, so the
        // HashMap entry never conflicts with the FIFO ring's borrow.
        let is_new = !inner.buckets.contains_key(&ip);
        if is_new {
            inner.order.push_back(ip);
        }
        let bucket = inner.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.per_second,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_second).min(self.per_second);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Constant-time string comparison (prevents timing-based API-key probing).
///
/// Both inputs are hashed to fixed 32-byte SHA-256 digests BEFORE comparison
/// so the LENGTH of the expected key is never leaked: an early `len != len`
/// return (the previous implementation) let a remote attacker measure key
/// length through response timing. Comparing only the digests runs in
/// constant time regardless of input length.
fn ct_eq(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    let da = Sha256::digest(a.as_bytes());
    let db = Sha256::digest(b.as_bytes());
    da.iter()
        .zip(db.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Best-effort client IP for per-IP rate limiting. `X-Forwarded-For` is
/// honored ONLY when the server is explicitly behind a trusted proxy
/// (`GRAPHITE_TRUST_PROXY`); otherwise the header is ignored entirely, so an
/// attacker who can reach the server directly cannot spoof it to rotate IPs
/// and bypass the limiter.
///
/// SECURITY (HIGH, 2026-09-05 production audit): this used to take the
/// LEFTMOST `X-Forwarded-For` entry, which is exactly the attacker-controlled
/// one. Every standard reverse proxy (nginx's `proxy_add_x_forwarded_for`,
/// Envoy, HAProxy, most CDNs) APPENDS the peer it actually observed to
/// whatever the client already sent, producing
/// `<client-supplied…>, <real client IP>`. Reading the left end therefore
/// read the client's own claim: an attacker set
/// `X-Forwarded-For: <random ip>` per request, got a fresh token bucket every
/// time, and the per-IP limit became a no-op — while a victim could also be
/// pinned to an attacker-chosen bucket.
///
/// The trustworthy entry is counted from the RIGHT: with `hops` trusted
/// proxies in front, the last `hops` entries were appended by infrastructure
/// under the operator's control, and the real client IP is the leftmost of
/// THOSE. Anything further left is caller-supplied and must never be
/// believed. If the header is missing, malformed, or has fewer entries than
/// the configured hop count (i.e. the request did not traverse the expected
/// proxy chain), we fall back to the direct peer address rather than trusting
/// a partial chain — fail-safe, never fail-open (P12).
fn client_ip(
    req: &axum::http::Request<axum::body::Body>,
    addr: SocketAddr,
    trust_proxy_hops: u8,
) -> IpAddr {
    if trust_proxy_hops == 0 {
        return addr.ip();
    }
    if let Some(header) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let entries: Vec<&str> = header
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        // Index from the right by the number of proxies we actually trust.
        // `entries.len() < hops` means the request did not come through the
        // full expected chain — do not trust any of it.
        if entries.len() >= trust_proxy_hops as usize {
            let idx = entries.len() - trust_proxy_hops as usize;
            if let Some(ip) = entries.get(idx).and_then(|v| v.parse::<IpAddr>().ok()) {
                return ip;
            }
        }
    }
    addr.ip()
}

/// Verify the data directory is actually WRITABLE, not merely present.
///
/// DURABILITY (CRITICAL, 2026-09-05 deployment audit): the standard container
/// failure is a Docker named volume mounted at `/data` that the engine
/// creates `root:root 0755` while the container process runs as an
/// unprivileged user. `create_dir_all` then SUCCEEDS (the directory exists),
/// the server starts, `/health` returns 200 — and every audit-log append and
/// semantic-graph snapshot silently fails for the lifetime of the deployment.
/// The operator sees a healthy service that is quietly not recording anything.
///
/// An unwritable data directory is an internal integrity failure, not
/// protocol uncertainty: Graphite cannot satisfy P9 (immutable audit trail
/// for every lifecycle event) or persist earned trust state. Per the
/// Constitution's Error Response framework that is a "stop, don't serve"
/// condition (response 5), not a degrade-and-continue one — so this returns
/// an error and the server refuses to start, loudly, with a message naming
/// the likely cause.
fn probe_data_dir_writable(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let probe = dir.join(".graphite-write-probe");
    match std::fs::write(&probe, b"graphite") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(format!(
            "data directory {} is not writable: {e}. Graphite refuses to start without a \
             durable audit trail (Constitution P9). If running in a container, ensure the \
             volume mounted here is owned by the container's user \
             (e.g. `mkdir -p /data && chown <uid>:<gid> /data` in the image, or \
             `user: \"<uid>:<gid>\"` in compose).",
            dir.display()
        )
        .into()),
    }
}

/// Install the global tracing subscriber.
///
/// OBSERVABILITY (2026-09-05 production audit): the crate emits
/// `tracing::info!/warn!/error!` throughout — including audit-log write
/// failures in `durable.rs` and RPC failures in `rpc_client.rs` — but no
/// subscriber was ever installed, so every one of those calls was a silent
/// no-op. An operator whose disk filled up got NO signal that the append-only
/// audit trail (P9) had stopped being written.
///
/// `GRAPHITE_LOG_FORMAT=json` emits structured JSON (the enterprise/log-
/// aggregator default); anything else emits human-readable text. Level is
/// controlled by `RUST_LOG` (default `info`). Idempotent: a second call is a
/// no-op rather than a panic, so embedding callers and tests that install
/// their own subscriber are unaffected.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("GRAPHITE_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    // `try_init` returns Err if a subscriber is already set — that is a
    // legitimate state (embedded use, tests), not a failure.
    let _ = if json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_current_span(false)
            .try_init()
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).try_init()
    };
}

pub async fn run_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    // ---- configuration from environment ----
    let data_dir = std::env::var("GRAPHITE_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("graphite-data"));
    std::fs::create_dir_all(&data_dir)?;
    // Creating the directory is not the same as being able to WRITE in it:
    // the common container failure is a volume mounted root-owned while the
    // process runs unprivileged, where `create_dir_all` succeeds (the dir
    // already exists) and every subsequent audit append fails. Durability of
    // the audit trail is a P9 guarantee, not a nice-to-have, so probe it now
    // and refuse to start rather than serve traffic with no audit trail.
    probe_data_dir_writable(&data_dir)?;

    let mut core = GraphiteCore::with_data_dir(data_dir.clone());

    // Plugin framework (Constitution P8): activate approved third-party plugin
    // manifests from GRAPHITE_PLUGINS_DIR (review gate — pending/rejected
    // manifests are skipped), and optionally mirror every verification event
    // to a JSON-lines file for production observability.
    if let Ok(dir) = std::env::var("GRAPHITE_PLUGINS_DIR") {
        if !dir.is_empty() {
            match core.attach_plugins_dir(std::path::Path::new(&dir)) {
                Ok(summary) => tracing_log(&format!(
                    "plugins: {} registered, {} pending (skipped), {} rejected (skipped) from {}",
                    summary.registered, summary.skipped_pending, summary.skipped_rejected, dir
                )),
                Err(e) => tracing_log(&format!("plugins: FAILED to load {}: {}", dir, e)),
            }
        }
    }
    if let Ok(events_file) = std::env::var("GRAPHITE_PLUGIN_EVENTS_FILE") {
        if !events_file.is_empty() {
            match core.attach_event_file_sink(std::path::Path::new(&events_file)) {
                Ok(()) => tracing_log(&format!(
                    "plugins: verification events appended to {}",
                    events_file
                )),
                Err(e) => tracing_log(&format!("plugins: event file sink not attached: {}", e)),
            }
        }
    }

    if let Ok(endpoint) = std::env::var("GRAPHITE_RPC_URL") {
        if !endpoint.is_empty() {
            let client = crate::rpc_client::SolanaRpcClient::new(crate::rpc_client::RpcConfig {
                endpoint,
                ..Default::default()
            });
            core.attach_rpc_client(client);
            tracing_log("RPC client attached — live L3 simulation enabled (GRAPHITE_RPC_URL)");
        }
    }

    let api_key = std::env::var("GRAPHITE_API_KEY")
        .ok()
        .filter(|k| !k.is_empty())
        .map(Arc::new);

    let rate_per_sec = std::env::var("GRAPHITE_RATE_LIMIT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(30.0);

    let cors_origins: Vec<HeaderValue> = std::env::var("GRAPHITE_CORS_ORIGINS")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.split(',')
                .filter_map(|s| s.trim().parse::<HeaderValue>().ok())
                .collect()
        })
        .unwrap_or_default();

    // Audit log rotation bounds BOTH unbounded disk growth and the dashboard
    // endpoints' full-file scan cost. Archives are kept forever by default
    // (P9): pruning is opt-in via GRAPHITE_AUDIT_MAX_ARCHIVES, so discarding
    // audit history is always an explicit operator decision.
    let rotate_bytes = std::env::var("GRAPHITE_AUDIT_ROTATE_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(crate::durable::DEFAULT_ROTATE_BYTES);
    let max_archives = std::env::var("GRAPHITE_AUDIT_MAX_ARCHIVES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let audit =
        match AuditLog::open_with_rotation(audit_path(&data_dir), rotate_bytes, max_archives) {
            Ok(log) => {
                tracing_log(&format!(
                    "audit log: {} (rotate at {} bytes, archives kept: {})",
                    audit_path(&data_dir).display(),
                    rotate_bytes,
                    if max_archives == 0 {
                        "all".to_string()
                    } else {
                        max_archives.to_string()
                    }
                ));
                Some(log)
            }
            Err(e) => {
                tracing_log(&format!("WARNING: audit log unavailable: {}", e));
                None
            }
        };

    // X-Forwarded-For is only honored behind an explicitly-trusted proxy.
    // The value is the NUMBER OF TRUSTED PROXY HOPS in front of this server
    // (`1` = the common single reverse-proxy/LB setup). `true` is accepted as
    // a compatibility alias for `1`; `0`/unset/anything else disables the
    // header entirely. See `client_ip` for why the count matters: entries are
    // trusted from the right, so an over-count would start believing
    // caller-supplied values again.
    let trust_proxy_hops: u8 = std::env::var("GRAPHITE_TRUST_PROXY")
        .ok()
        .map(|v| {
            if v.eq_ignore_ascii_case("true") {
                1
            } else {
                v.trim().parse::<u8>().unwrap_or(0)
            }
        })
        .unwrap_or(0);

    // Manifest Registry state (shared contract with the CLI: default
    // `registry_state.json`, override `GRAPHITE_REGISTRY_STATE`). Community
    // submissions accepted via `graphite registry submit` survive restarts
    // and are (C53) merged into the VERIFICATION core's registry, so accepted
    // community manifests resolve at verification time — not just in the
    // dashboard. A corrupt file fails loud (tracing error) rather than
    // silently resetting reviewer reputations.
    let registry_state_path = std::env::var("GRAPHITE_REGISTRY_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("registry_state.json"));
    let registry_engine = match std::fs::read_to_string(&registry_state_path) {
        Ok(json) => match crate::manifest_registry::ManifestRegistryEngine::from_json(&json) {
            Ok(engine) => {
                tracing_log(&format!(
                    "manifest registry: loaded {} accepted record(s) from {}",
                    engine.records().len(),
                    registry_state_path.display()
                ));
                engine
            }
            Err(e) => {
                tracing_log(&format!(
                    "manifest registry: CORRUPT state file {} — starting fresh: {}",
                    registry_state_path.display(),
                    e
                ));
                crate::manifest_registry::ManifestRegistryEngine::new()
            }
        },
        Err(_) => crate::manifest_registry::ManifestRegistryEngine::new(),
    };
    let merged = core.merge_community_manifests(&registry_engine);
    if merged > 0 {
        tracing_log(&format!(
            "manifest registry: merged {merged} community-accepted manifest(s) into the verification registry (C53)"
        ));
    }

    let state = AppState {
        core,
        api_key: api_key.clone(),
        audit,
        registry_engine,
        rate: RateLimiter::new(rate_per_sec),
        trust_proxy_hops,
        metrics: Metrics::default(),
    };

    tracing_log(&format!(
        "auth: {} | rate limit: {:.0} req/s/IP | CORS origins: {} | body limit: {}KB | timeout: {}s",
        if api_key.is_some() {
            "Bearer API key (GRAPHITE_API_KEY)"
        } else {
            "NONE (dev mode — set GRAPHITE_API_KEY in production)"
        },
        rate_per_sec,
        if cors_origins.is_empty() {
            "DENIED (default)".to_string()
        } else {
            cors_origins
                .iter()
                .filter_map(|o| o.to_str().ok())
                .collect::<Vec<_>>()
                .join(", ")
        },
        MAX_BODY_SIZE / 1024,
        REQUEST_TIMEOUT.as_secs(),
    ));

    let app = build_app(state, cors_origins);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing_log(&format!("Graphite server listening on {}", addr));

    // Graceful shutdown — SIGTERM (Docker/K8s) and SIGINT (Ctrl+C)
    let shutdown = async {
        #[cfg(unix)]
        {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut sigterm) => {
                    tokio::select! {
                        _ = sigterm.recv() => tracing_log("Received SIGTERM - shutting down gracefully"),
                        _ = signal::ctrl_c() => tracing_log("Received SIGINT - shutting down gracefully"),
                    }
                }
                Err(e) => {
                    tracing_log(&format!("Warning: failed to install SIGTERM handler: {}. Falling back to Ctrl-C only.", e));
                    let _ = signal::ctrl_c().await;
                    tracing_log("Received interrupt - shutting down gracefully");
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = signal::ctrl_c().await;
            tracing_log("Received interrupt - shutting down gracefully");
        }
    };

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}

fn build_app(state: AppState, cors_origins: Vec<HeaderValue>) -> Router {
    let cors = if cors_origins.is_empty() {
        // Default: no CORS headers — browsers cannot call cross-origin.
        // Server-to-server clients are unaffected.
        tower_http::cors::CorsLayer::new()
    } else {
        tower_http::cors::CorsLayer::new()
            .allow_origin(cors_origins)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
            .max_age(Duration::from_secs(3600))
    };

    Router::new()
        .route("/verify", post(verify_handler))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/manifests", get(manifests_handler))
        // Dashboard read-only API (Constitution P4 — no mutation).
        .route("/api/graph", get(graph_handler))
        .route("/api/confidence-history", get(confidence_history_handler))
        .route("/api/policy-violations", get(policy_violations_handler))
        .route("/api/protocols/top", get(top_protocols_handler))
        .route("/api/registry", get(registry_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        // Certification item: a panicking handler must not drop the connection
        // or destabilize the server — convert the panic to a clean 500 with a
        // generic message (no internal details leaked to the client). Logging
        // of the panic happens in the handler via tracing.
        .layer(CatchPanicLayer::custom(
            |_panic: Box<dyn std::any::Any + Send + 'static>| {
                tracing_log("internal error: handler panicked (caught by CatchPanicLayer)");
                axum::http::Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(axum::body::Bytes::from_static(
                        b"{\"error\":\"internal server error\"}",
                    )))
                    .unwrap()
            },
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .with_state(state)
}

/// API-key auth. `/health` stays open for load balancers.
async fn auth_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }
    if let Some(key) = &state.api_key {
        let provided = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !ct_eq(provided, key.as_str()) {
            Metrics::inc(&state.metrics.auth_failures);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "unauthorized",
                    "hint": "provide a valid Bearer API key (set via GRAPHITE_API_KEY)",
                })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Per-IP rate limiting (429 when a client exceeds its bucket).
async fn rate_limit_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = client_ip(&req, addr, state.trust_proxy_hops);
    if !state.rate.check(ip) {
        Metrics::inc(&state.metrics.rate_limited);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "rate limit exceeded" })),
        )
            .into_response();
    }
    next.run(req).await
}

/// Verify handler — returns 200 on success, 400 on bad input, 500 on internal error.
///
/// Error classification:
///   400 BAD_REQUEST: client provided invalid input (bad address, wrong account count,
///     unknown discriminator, invalid program ID). These are caller-fixable.
///   500 INTERNAL_SERVER_ERROR: internal failures (risk engine, policy engine,
///     confidence computation, PDA derivation, semantic graph). These indicate
///     bugs in Graphite, not caller errors. Per Constitution P12 (fail-closed),
///     the response body explains the error but the HTTP status tells the client
///     this is a server-side issue, not a transaction rejection.
/// Custom error response for verification failures
#[derive(Debug, Clone)]
pub enum VerificationHttpError {
    BadRequest(String),
    Internal(String),
}

impl VerificationHttpError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The FULL message, including internal detail. For server-side logging
    /// and the audit trail only — never send this to a client for a 5xx.
    pub fn message(&self) -> &str {
        match self {
            Self::BadRequest(msg) => msg,
            Self::Internal(msg) => msg,
        }
    }

    /// The message that is safe to return to the caller.
    ///
    /// SECURITY (2026-09-05 production audit): a `TransactionBuild` error
    /// whose text didn't match one of a handful of hardcoded substrings fell
    /// through to `Internal` and its RAW internal text was echoed verbatim in
    /// the 500 response body. That couples an information-disclosure boundary
    /// to incidental error wording elsewhere in the codebase — any future
    /// rewording silently changes what external callers can see.
    ///
    /// A 400 message is caller-fixable input feedback and is deliberately
    /// specific (P3 — the caller must be able to act on it). A 500 means a
    /// bug in Graphite, where the caller can act on nothing: they get a
    /// generic message while the detail goes to the log and audit trail.
    pub fn client_message(&self) -> &str {
        match self {
            Self::BadRequest(msg) => msg,
            Self::Internal(_) => {
                "internal verification error — the request was not approved; \
                 see server logs for detail"
            }
        }
    }
}

/// A stable, non-disclosing error CLASS for the client.
///
/// `format!("{:?}", e)` (used for the log line and the audit record) renders
/// the variant's payload too — e.g. `TransactionBuild("<internal detail>")` —
/// so it must never be returned to a caller. This returns only the variant
/// name: enough for a client to branch on programmatically, nothing about
/// Graphite's internals.
fn error_kind(e: &VerificationError) -> &'static str {
    use VerificationError::*;
    match e {
        AccountResolution(_) => "AccountResolution",
        RiskAssessment(_) => "RiskAssessment",
        PolicyEvaluation(_) => "PolicyEvaluation",
        TransactionBuild(_) => "TransactionBuild",
        SemanticGraph(_) => "SemanticGraph",
        Confidence(_) => "Confidence",
        InvalidInput(_) => "InvalidInput",
    }
}

/// Classify verification error into client (400) or server (500) error
fn classify_error(e: &VerificationError) -> VerificationHttpError {
    use crate::account_resolution::AccountResolutionError::*;
    use VerificationError::*;

    match e {
        // Client errors (400) - bad input
        AccountResolution(InvalidAddress(addr)) => {
            VerificationHttpError::BadRequest(format!("Invalid address: {}", addr))
        }
        AccountResolution(AccountCountMismatch { expected, actual }) => {
            VerificationHttpError::BadRequest(format!(
                "Account count mismatch: expected {}, got {}",
                expected, actual
            ))
        }
        AccountResolution(InstructionNotFound(program, disc)) => {
            VerificationHttpError::BadRequest(format!(
                "Instruction not found for program {} with discriminator {}",
                program, disc
            ))
        }
        TransactionBuild(msg) => {
            let msg = msg.clone();
            let lower = msg.to_lowercase();
            if lower.contains("invalid account")
                || lower.contains("invalid program_id")
                || lower.contains("invalid discriminator")
                || lower.contains("program_id cannot be empty")
                || lower.contains("missing accounts")
            {
                VerificationHttpError::BadRequest(msg)
            } else {
                VerificationHttpError::Internal(msg)
            }
        }
        AccountResolution(NoManifest(program_id)) => {
            VerificationHttpError::Internal(format!("No manifest found for program {}", program_id))
        }
        // Server errors (500) - internal failures
        AccountResolution(AccountResolutionError::PdaDerivationFailed { account, reason }) => {
            VerificationHttpError::Internal(format!(
                "PDA derivation failed for {}: {}",
                account, reason
            ))
        }
        Confidence(msg) => {
            VerificationHttpError::Internal(format!("Confidence engine error: {}", msg))
        }
        InvalidInput(msg) => VerificationHttpError::BadRequest(msg.clone()),
        RiskAssessment(msg) => {
            VerificationHttpError::Internal(format!("Risk engine error: {}", msg))
        }
        PolicyEvaluation(msg) => {
            VerificationHttpError::Internal(format!("Policy engine error: {}", msg))
        }
        SemanticGraph(msg) => {
            VerificationHttpError::Internal(format!("Semantic graph error: {}", msg))
        }
    }
}

async fn verify_handler(
    State(state): State<AppState>,
    payload: Result<Json<VerificationInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    // A malformed/unparseable body (422 from the Json extractor) is a probing
    // attempt and MUST be audited too — it never reaches the match below, so
    // it is handled here to leave a trail.
    let Json(input) = match payload {
        Ok(p) => p,
        Err(rejection) => {
            let message = rejection.body_text();
            if let Some(log) = &state.audit {
                log.append_error(&AuditErrorRecord {
                    timestamp: crate::durable::now_utc_rfc3339(),
                    program_id: "<malformed>".to_string(),
                    instruction_name: "<unparseable>".to_string(),
                    error: message.clone(),
                    error_type: "JsonRejection".to_string(),
                    status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                });
            }
            tracing_log(&format!("verify: 422 unparseable body — {}", message));
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": message,
                    "error_type": "JsonRejection",
                    "status": StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    "hint": "Fix the request input and retry",
                })),
            ));
        }
    };

    Metrics::inc(&state.metrics.verify_requests);
    match state.core.verify_async(&input).await {
        Ok(result) => {
            Metrics::inc(if result.approved {
                &state.metrics.verify_approved
            } else {
                &state.metrics.verify_blocked
            });
            tracing_log(&format!(
                "verify: {} | {} | confidence={:.2} | {}",
                input.program_id,
                if result.approved {
                    "APPROVED"
                } else {
                    "BLOCKED"
                },
                result.confidence,
                result.audit_trail_id
            ));

            // Durability: append to the audit log before responding (the line
            // is flushed synchronously). Best-effort — never fails the request.
            if let Some(log) = &state.audit {
                // GAP-2026-08-06-3: the audit trail records the REAL L3/L8 layer
                // states (never the old phantom `passed: true`). Layers are the
                // single source of truth for the pipeline report.
                let layer_status = |name: &str| -> String {
                    result
                        .layers
                        .iter()
                        .find(|l| l.layer == name)
                        .map(|l| l.status.as_str().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                };
                log.append(&AuditRecord {
                    timestamp: crate::durable::now_utc_rfc3339(),
                    audit_trail_id: result.audit_trail_id.clone(),
                    content_hash: result.content_hash.clone(),
                    program_id: input.program_id.clone(),
                    instruction_name: result.instruction_name.clone(),
                    protocol_name: result.protocol_name.clone(),
                    manifest_version: result.manifest_version.clone(),
                    approved: result.approved,
                    confidence: result.confidence,
                    risk_status: result.risk_verdict.status.clone(),
                    policy_verdict: result.policy_verdict.clone(),
                    l3_status: layer_status("L3_SimulationVerification"),
                    l8_status: layer_status("L8_ExecutionVerification"),
                });
            }

            Ok(Json(result))
        }
        Err(e) => {
            Metrics::inc(&state.metrics.verify_errors);
            let http_error = classify_error(&e);
            let status = http_error.status_code();
            let error_type = format!("{:?}", e);

            tracing_log(&format!(
                "verify: {} | ERROR [{}] | {} | {:?}",
                input.program_id,
                if status.is_client_error() {
                    "CLIENT"
                } else {
                    "SERVER"
                },
                e,
                error_type
            ));

            // Durability: rejected-by-error verifications are audit-worthy
            // too — probing attacks against /verify (malformed payloads,
            // oversized bodies, bad account counts) must leave a trail.
            // The record mirrors AuditRecord but carries the error instead
            // of a verdict.
            if let Some(log) = &state.audit {
                log.append_error(&AuditErrorRecord {
                    timestamp: crate::durable::now_utc_rfc3339(),
                    program_id: input.program_id.clone(),
                    instruction_name: input.instruction_discriminator.clone(),
                    error: http_error.message().to_string(),
                    error_type: error_type.clone(),
                    status: status.as_u16(),
                });
            }

            Err((
                status,
                Json(serde_json::json!({
                    // client_message()/error_kind() deliberately withhold
                    // internal detail on a 5xx — the full text is already in
                    // the log line above and the audit record below. A 4xx
                    // still carries the specific, caller-fixable message.
                    "error": http_error.client_message(),
                    "error_type": error_kind(&e),
                    "status": status.as_u16(),
                    "hint": if status.is_client_error() {
                        "Fix the request input and retry"
                    } else {
                        "Internal Graphite error — this is a bug, not a transaction rejection. Report it."
                    },
                })),
            ))
        }
    }
}

/// Liveness + durability health.
///
/// Reports whether the append-only audit trail is actually being written.
/// Audit writes are non-fatal by design (a failing audit disk must not take
/// down verification), which previously made a stopped audit trail invisible
/// to operators — `audit.writes_failed` is what makes it alertable.
async fn health_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let audit = state.audit.as_ref().map(|a| a.health());
    let degraded = match &audit {
        Some(h) => h.writes_failed > 0,
        // No audit log at all is degraded, not healthy: verification still
        // works, but the P9 trail does not exist.
        None => true,
    };
    Json(serde_json::json!({
        // `status` stays "ok" while the service can serve traffic so load
        // balancers don't pull a working node; `degraded` is the operator
        // signal.
        "status": "ok",
        "degraded": degraded,
        "service": "graphite-core",
        "version": env!("CARGO_PKG_VERSION"),
        "audit": match audit {
            Some(h) => serde_json::json!({
                "enabled": true,
                "writes_ok": h.writes_ok,
                "writes_failed": h.writes_failed,
                "active_bytes": h.active_bytes,
            }),
            None => serde_json::json!({ "enabled": false }),
        },
    }))
}

/// Prometheus text-format metrics.
///
/// Enterprise deployments had no numeric signal at all before this: no way to
/// alert on auth failures, rate-limit rejections, audit-write failures, or
/// approve/block ratios. Deliberately a small, honest set of counters that
/// are actually maintained — not a large surface of plausible-looking
/// metrics that are never incremented.
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let m = &state.metrics;
    let audit = state.audit.as_ref().map(|a| a.health());
    let mut out = String::with_capacity(1024);
    let mut push = |name: &str, help: &str, kind: &str, value: u64| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    };
    push(
        "graphite_verify_requests_total",
        "Verification requests that reached the handler.",
        "counter",
        m.verify_requests.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_verify_approved_total",
        "Verifications that returned approved=true.",
        "counter",
        m.verify_approved.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_verify_blocked_total",
        "Verifications that returned approved=false.",
        "counter",
        m.verify_blocked.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_verify_errors_total",
        "Verification requests that failed before producing a result.",
        "counter",
        m.verify_errors.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_auth_failures_total",
        "Requests rejected with 401 by the auth middleware.",
        "counter",
        m.auth_failures.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_rate_limited_total",
        "Requests rejected with 429 by the rate limiter.",
        "counter",
        m.rate_limited.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_audit_writes_ok_total",
        "Audit records successfully appended.",
        "counter",
        audit.map(|h| h.writes_ok).unwrap_or(0),
    );
    push(
        "graphite_audit_writes_failed_total",
        "Audit records that failed to append (durability is degraded).",
        "counter",
        audit.map(|h| h.writes_failed).unwrap_or(0),
    );
    push(
        "graphite_audit_active_bytes",
        "Size of the active audit log file in bytes.",
        "gauge",
        audit.map(|h| h.active_bytes).unwrap_or(0),
    );
    push(
        "graphite_audit_enabled",
        "1 when an audit log is attached, 0 otherwise.",
        "gauge",
        u64::from(audit.is_some()),
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], out)
}

async fn manifests_handler(
    State(state): State<AppState>,
) -> Json<Vec<crate::manifest::ProtocolManifest>> {
    let manifests: Vec<_> = state.core.list_manifests().into_iter().cloned().collect();
    Json(manifests)
}

/// Dashboard: Semantic Graph read-only snapshot (P4 — never mutates).
async fn graph_handler(State(state): State<AppState>) -> Json<crate::verification::GraphSnapshot> {
    Json(state.core.graph_snapshot())
}

/// Dashboard: confidence scores over time, from the audit log
/// (most recent first; the dashboard polls this for the time series).
async fn confidence_history_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Bounded read: the chart needs the most recent points; memory stays
    // bounded by the cap while `count` reports the exact total (P4 — the
    // dashboard is observability). The scan is O(log) per poll, which is
    // fine at the dashboard's cadence on a single core node.
    let (records, _, total, _) = match &state.audit {
        Some(log) => log.read_tail_filtered(CONFIDENCE_SERIES_CAP, |_| true),
        None => (Vec::new(), Vec::new(), 0, 0),
    };
    let series: Vec<serde_json::Value> = records
        .iter()
        .rev()
        .map(|r| {
            serde_json::json!({
                "timestamp": r.timestamp,
                "confidence": r.confidence,
                "approved": r.approved,
                "program_id": r.program_id,
                "audit_trail_id": r.audit_trail_id,
            })
        })
        .collect();
    Json(serde_json::json!({ "series": series, "count": total }))
}

/// Dashboard: policy-engine blocked transactions from the audit log
/// (most recent first). A violation is any record where the policy or risk
/// layer rejected the transaction.
async fn policy_violations_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Bounded read: only the most recent violations are surfaced; memory
    // stays bounded by the cap while `count` reports the exact total.
    let (records, errors, total_violations, _) = match &state.audit {
        Some(log) => log.read_tail_filtered(VIOLATIONS_CAP, |r| !r.approved),
        None => (Vec::new(), Vec::new(), 0, 0),
    };
    let violations: Vec<serde_json::Value> = records
        .iter()
        .rev()
        .map(|r| {
            serde_json::json!({
                "timestamp": r.timestamp,
                "program_id": r.program_id,
                "protocol_name": r.protocol_name,
                "instruction_name": r.instruction_name,
                "confidence": r.confidence,
                "policy_verdict": r.policy_verdict,
                "risk_status": r.risk_status,
                "audit_trail_id": r.audit_trail_id,
            })
        })
        .collect();
    // Error-path probes (malformed/oversized/bad-input requests) are
    // violations of the protocol contract too — surface them so blocked
    // traffic is fully observable.
    let error_violations: Vec<serde_json::Value> = errors
        .iter()
        .rev()
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "program_id": e.program_id,
                "instruction_name": e.instruction_name,
                "error": e.error,
                "error_type": e.error_type,
                "status": e.status,
            })
        })
        .collect();
    Json(serde_json::json!({
        "violations": violations,
        "error_violations": error_violations,
        "count": total_violations + error_violations.len(),
    }))
}

/// Dashboard: top 5 protocols by battle-tested volume (earned evidence, P7)
/// plus verified observation count from the audit log. Sorted descending by
/// volume; ties broken deterministically by program id.
async fn top_protocols_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Streaming per-program counts: memory is bounded by distinct programs,
    // never by log size.
    let observed = match &state.audit {
        Some(log) => log.observations_by_program(),
        None => std::collections::HashMap::new(),
    };
    // One graph lock per request: the snapshot is owned data, so the guard
    // drops before the audit-log reads below (no nested locking).
    let snapshot = state.core.graph_snapshot();
    let mut rows: Vec<serde_json::Value> = snapshot
        .nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "program_id": n.program_id,
                "name": n.name,
                "trust_tier": n.trust_tier,
                "battle_tested_tx_count": n.battle_tested_tx_count,
                "observed_verifications": observed.get(&n.program_id).copied().unwrap_or(0),
                "quarantined": n.quarantined,
            })
        })
        .collect();
    // Include programs observed via the audit log that have no graph node
    // (e.g. unknown programs that were verified and rejected).
    for (program_id, count) in &observed {
        if !snapshot.nodes.iter().any(|n| &n.program_id == program_id) {
            rows.push(serde_json::json!({
                "program_id": program_id,
                "name": program_id,
                "trust_tier": "Unknown",
                "battle_tested_tx_count": 0,
                "observed_verifications": count,
                "quarantined": false,
            }));
        }
    }
    // Descending by total volume (earned battle-tested tx + observed
    // verifications); ties broken by program id for determinism (P2).
    rows.sort_by(|a, b| {
        let total = |v: &serde_json::Value| -> u64 {
            v["battle_tested_tx_count"].as_u64().unwrap_or(0)
                + v["observed_verifications"].as_u64().unwrap_or(0)
        };
        total(b)
            .cmp(&total(a))
            .then_with(|| a["program_id"].as_str().cmp(&b["program_id"].as_str()))
    });
    rows.truncate(5);
    Json(serde_json::json!({ "top": rows }))
}

/// Dashboard: Manifest Registry state — accepted submissions with version
/// lineage, and registered reviewers (read-only view of the engine).
async fn registry_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let engine = &state.registry_engine;
    let records: Vec<serde_json::Value> = engine
        .records()
        .iter()
        .map(|r| {
            serde_json::json!({
                "program_id": r.program_id,
                "version_label": r.version_label,
                "previous_version_ref": r.previous_version_ref,
                "content_hash": r.content_hash,
                "trust_tier": r.trust_tier.as_str(),
                "source": r.source,
            })
        })
        .collect();
    let reviewers: Vec<serde_json::Value> = engine
        .reviewers()
        .iter()
        .map(|(pubkey, r)| {
            serde_json::json!({
                "pubkey": pubkey,
                "reputation_score": r.reputation_score,
            })
        })
        .collect();
    Json(serde_json::json!({
        "records": records,
        "reviewers": reviewers,
        "record_count": records.len(),
    }))
}

fn tracing_log(msg: &str) {
    eprintln!("[graphite] {}", msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── X-Forwarded-For spoofing (HIGH, 2026-09-05 production audit) ────────
    //
    // The per-IP rate limiter is only as strong as its notion of "who is the
    // client". Before the fix, `client_ip` read the LEFTMOST `X-Forwarded-For`
    // entry — the one the CLIENT supplies — so an attacker rotated that header
    // per request, got a fresh token bucket every time, and the limiter became
    // a no-op. These tests are written from the attacker's side: each one is a
    // concrete spoofing attempt that must NOT succeed.

    fn req_with_xff(xff: Option<&str>) -> axum::http::Request<axum::body::Body> {
        let mut b = axum::http::Request::builder().uri("/verify");
        if let Some(v) = xff {
            b = b.header("x-forwarded-for", v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    const PEER: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)), 9);

    /// With no trusted proxy configured, the header must be ignored entirely —
    /// a directly-reachable server must never believe a caller-supplied IP.
    #[test]
    fn xff_is_ignored_when_no_proxy_is_trusted() {
        let req = req_with_xff(Some("1.2.3.4"));
        assert_eq!(client_ip(&req, PEER, 0), PEER.ip());
    }

    /// The canonical attack: nginx's `proxy_add_x_forwarded_for` APPENDS the
    /// real peer to whatever the client sent, so the header becomes
    /// `<attacker's claim>, <real client IP>`. Reading the left end returned
    /// the attacker's claim. With one trusted hop we must read the RIGHTMOST
    /// entry — the one our own proxy wrote.
    #[test]
    fn spoofed_leftmost_xff_entry_is_not_believed() {
        let req = req_with_xff(Some("6.6.6.6, 198.51.100.42"));
        let ip = client_ip(&req, PEER, 1);
        assert_eq!(
            ip,
            "198.51.100.42".parse::<IpAddr>().unwrap(),
            "must use the proxy-appended (rightmost) entry, not the client's claim"
        );
        assert_ne!(ip, "6.6.6.6".parse::<IpAddr>().unwrap());
    }

    /// Rotating the spoofed prefix must NOT produce different rate-limit
    /// identities — this is the actual bypass, stated as a property: every
    /// request from one real client must map to one bucket key regardless of
    /// what the client puts in the header.
    #[test]
    fn rotating_spoofed_xff_prefixes_cannot_rotate_the_rate_limit_identity() {
        let attacker_claims = [
            "1.1.1.1",
            "9.9.9.9",
            "8.8.8.8, 7.7.7.7",
            "203.0.113.99, 10.0.0.1, 172.16.0.9",
        ];
        let resolved: Vec<IpAddr> = attacker_claims
            .iter()
            .map(|claim| {
                let header = format!("{claim}, 198.51.100.42");
                client_ip(&req_with_xff(Some(&header)), PEER, 1)
            })
            .collect();

        let real = "198.51.100.42".parse::<IpAddr>().unwrap();
        assert!(
            resolved.iter().all(|ip| *ip == real),
            "every spoofing attempt must collapse to the same real client identity, got {resolved:?}"
        );
    }

    /// Two trusted proxies: the real client is the entry immediately left of
    /// the two our infrastructure appended.
    #[test]
    fn multiple_trusted_hops_index_from_the_right() {
        // <spoofed>, <real client>, <proxy-1 saw>, appended by proxy-2
        let req = req_with_xff(Some("6.6.6.6, 198.51.100.42, 10.0.0.1"));
        assert_eq!(
            client_ip(&req, PEER, 2),
            "198.51.100.42".parse::<IpAddr>().unwrap()
        );
    }

    /// A request that did NOT traverse the expected proxy chain (fewer
    /// entries than configured hops) must fall back to the direct peer, never
    /// trust a partial chain. Otherwise an attacker who can reach the server
    /// directly, bypassing the proxy, sends a single-entry header and picks
    /// their own identity.
    #[test]
    fn short_xff_chain_falls_back_to_peer_instead_of_trusting_it() {
        let req = req_with_xff(Some("6.6.6.6"));
        assert_eq!(
            client_ip(&req, PEER, 2),
            PEER.ip(),
            "a chain shorter than the trusted hop count must not be believed"
        );
    }

    /// Malformed, empty, and garbage headers must degrade to the peer address
    /// rather than panicking or producing a wildcard identity.
    #[test]
    fn malformed_xff_headers_degrade_to_the_peer_address() {
        for header in ["", "   ", ",,,", "not-an-ip", "999.999.999.999", ", ,"] {
            assert_eq!(
                client_ip(&req_with_xff(Some(header)), PEER, 1),
                PEER.ip(),
                "malformed header {header:?} must fall back to the peer"
            );
        }
        assert_eq!(client_ip(&req_with_xff(None), PEER, 1), PEER.ip());
    }

    /// IPv6 entries (and the bracketed form proxies sometimes emit) must
    /// resolve correctly rather than silently falling back — a fallback here
    /// would collapse all IPv6 clients behind the proxy into one bucket.
    #[test]
    fn ipv6_xff_entries_resolve() {
        let req = req_with_xff(Some("6.6.6.6, 2001:db8::42"));
        assert_eq!(
            client_ip(&req, PEER, 1),
            "2001:db8::42".parse::<IpAddr>().unwrap()
        );
    }

    /// Whitespace padding must not defeat parsing (proxies emit `a, b` with
    /// varying spacing) — a parse failure would fall back to the shared peer
    /// address and re-collapse every client into one bucket.
    #[test]
    fn whitespace_padded_entries_still_parse() {
        let req = req_with_xff(Some("6.6.6.6 ,   198.51.100.42   "));
        assert_eq!(
            client_ip(&req, PEER, 1),
            "198.51.100.42".parse::<IpAddr>().unwrap()
        );
    }

    /// FIFO eviction must keep the bucket map bounded: with a cap of 3,
    /// inserting a 4th distinct IP evicts the oldest-inserted one (O(1), no
    /// full-map sweep).
    #[test]
    fn rate_limiter_evicts_oldest_at_capacity() {
        let rl = RateLimiter::with_capacity(3, 1000.0); // huge refill rate: never tokens-starved
        let ips: Vec<IpAddr> = (0..6).map(|i| IpAddr::from([10, 0, 0, i as u8])).collect();

        for ip in &ips {
            assert!(
                rl.check(*ip),
                "all requests allowed under a huge refill rate"
            );
        }

        let inner = rl.buckets.lock().unwrap();
        assert!(
            inner.buckets.len() <= 3,
            "bucket map must stay bounded at the cap, got {}",
            inner.buckets.len()
        );
        // The first two IPs inserted must have been evicted (FIFO); the last
        // three remain.
        assert!(inner.buckets.contains_key(&ips[3]));
        assert!(inner.buckets.contains_key(&ips[4]));
        assert!(inner.buckets.contains_key(&ips[5]));
        assert!(!inner.buckets.contains_key(&ips[0]));
        assert!(!inner.buckets.contains_key(&ips[1]));
    }

    /// Per-IP limiting still holds with the FIFO ring in place: a client that
    /// exhausts its bucket is denied until the refill window passes.
    #[test]
    fn rate_limiter_denies_after_bucket_exhausted() {
        let rl = RateLimiter::with_capacity(8, 2.0); // 2 tokens/s
        let ip = IpAddr::from([10, 0, 0, 9]);
        // 2 allowed immediately (bucket starts full at 2 tokens), 3rd denied.
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip));
        // A different IP is unaffected.
        assert!(rl.check(IpAddr::from([10, 0, 0, 10])));
    }
    // ─── Dashboard read-only API (P4) ────────────────────────────────────────

    /// Build an app state with a seeded core + an audit log in a temp dir.
    /// Each call gets a unique dir (parallel tests must never share the audit
    /// file — appends from one test would leak into another's readout).
    fn test_state() -> (AppState, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "graphite-dash-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = crate::verification::GraphiteCore::with_data_dir(dir.clone());
        // Earned evidence for the System Program (battle-tested tier + baseline).
        use crate::semantic_graph_store::{Behavior, BehaviorEvidence};
        use crate::simulation_integrity::ComputeBaseline;
        core.seed_behavior(Behavior {
            program_id: "11111111111111111111111111111111".to_string(),
            version: "1.0.0".to_string(),
            expected_state_changes: vec!["debits accounts.from by amount".to_string()],
            allowed_cpis: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()],
            trust_tier: crate::TrustTier::Unknown,
            evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 2,
                battle_tested_tx_count: 1500,
                simulation_match_count: 100,
            },
            quarantined: false,
            quarantine_reason: None,
        })
        .unwrap();
        core.seed_simulation_baseline(
            "11111111111111111111111111111111",
            ComputeBaseline {
                mean_compute_units: 150.0,
                std_compute_units: 1.0,
                sample_count: 50,
                mean_account_writes: 2.0,
                std_account_writes: 0.5,
                mean_cpi_hops: 0.0,
                std_cpi_hops: 0.1,
                ..Default::default()
            },
        )
        .unwrap();
        let audit = AuditLog::open(audit_path(&dir)).unwrap();
        let state = AppState {
            core,
            api_key: None,
            audit: Some(audit),
            registry_engine: crate::manifest_registry::ManifestRegistryEngine::new(),
            rate: RateLimiter::new(1000.0),
            trust_proxy_hops: 0,
            metrics: Metrics::default(),
        };
        (state, dir)
    }

    async fn get_json(app: &Router, path: &str) -> (axum::http::StatusCode, serde_json::Value) {
        use axum::body::Body;
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();
        // The rate-limit middleware reads ConnectInfo (provided by the real
        // listener via into_make_service_with_connect_info); oneshot tests
        // must inject it explicitly.
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn dashboard_graph_endpoint_is_read_only_snapshot() {
        let (state, _dir) = test_state();
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/graph").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let nodes = json["nodes"].as_array().expect("nodes array");
        assert!(!nodes.is_empty(), "seed manifests must appear as nodes");
        // System Program node carries earned evidence.
        let sys = nodes
            .iter()
            .find(|n| n["program_id"] == "11111111111111111111111111111111")
            .expect("system node");
        assert_eq!(sys["battle_tested_tx_count"], 1500);
        assert_eq!(sys["baseline_samples"], 50);
        assert_eq!(sys["trust_tier"], "BattleTested");
        // CPI edges derived from allowed_cpis.
        let edges = json["edges"].as_array().unwrap();
        assert!(
            edges.iter().any(|e| {
                e["from"] == "11111111111111111111111111111111"
                    && e["to"] == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            }),
            "CPI edge System -> Token must exist"
        );
    }

    #[tokio::test]
    async fn dashboard_confidence_history_reads_audit_log() {
        let (state, dir) = test_state();
        // Append two audit records directly (verification happened over HTTP).
        let log = state.audit.as_ref().unwrap();
        let ts = crate::durable::now_utc_rfc3339();
        log.append(&AuditRecord {
            timestamp: ts.clone(),
            audit_trail_id: "gr-a".to_string(),
            content_hash: "h1".to_string(),
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "System Program".to_string(),
            manifest_version: Some("1.0.0".to_string()),
            approved: true,
            confidence: 0.9,
            risk_status: "Clear".to_string(),
            policy_verdict: "Approved".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
        });
        log.append(&AuditRecord {
            timestamp: ts,
            audit_trail_id: "gr-b".to_string(),
            content_hash: "h2".to_string(),
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "System Program".to_string(),
            manifest_version: Some("1.0.0".to_string()),
            approved: false,
            confidence: 0.3,
            risk_status: "Blocked".to_string(),
            policy_verdict: "RejectedBelowThreshold".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
        });
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/confidence-history").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(json["count"], 2);
        let series = json["series"].as_array().unwrap();
        assert_eq!(series[0]["confidence"], 0.3, "most recent first");
        let _ = dir;
    }

    #[tokio::test]
    async fn dashboard_policy_violations_lists_blocked_records() {
        let (state, dir) = test_state();
        let log = state.audit.as_ref().unwrap();
        log.append(&AuditRecord {
            timestamp: crate::durable::now_utc_rfc3339(),
            audit_trail_id: "gr-blocked".to_string(),
            content_hash: "h3".to_string(),
            program_id: "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M".to_string(),
            instruction_name: "openDca".to_string(),
            protocol_name: "Jupiter DCA".to_string(),
            manifest_version: None,
            approved: false,
            confidence: 0.4,
            risk_status: "Blocked".to_string(),
            policy_verdict: "RejectedRiskEngineBlock".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
        });
        // Error-path probe (malformed request) must surface as a violation too.
        log.append_error(&crate::durable::AuditErrorRecord {
            timestamp: crate::durable::now_utc_rfc3339(),
            program_id: "probe".to_string(),
            instruction_name: "n/a".to_string(),
            error: "missing proposed_intent".to_string(),
            error_type: "bad_input".to_string(),
            status: 400,
        });
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/policy-violations").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        // count = blocked verifications + error-path probes (both surfaced).
        assert_eq!(json["count"], 2);
        assert_eq!(
            json["violations"][0]["program_id"],
            "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M"
        );
        assert_eq!(
            json["violations"][0]["policy_verdict"],
            "RejectedRiskEngineBlock"
        );
        // The error-path probe is surfaced separately, most recent first.
        assert_eq!(json["error_violations"][0]["program_id"], "probe");
        assert_eq!(json["error_violations"][0]["error_type"], "bad_input");
        let _ = dir;
    }

    #[tokio::test]
    async fn dashboard_top_protocols_ranks_by_volume() {
        let (state, dir) = test_state();
        let log = state.audit.as_ref().unwrap();
        // 3 verifications of the System program.
        for i in 0..3 {
            log.append(&AuditRecord {
                timestamp: crate::durable::now_utc_rfc3339(),
                audit_trail_id: format!("gr-top-{i}"),
                content_hash: format!("h{i}"),
                program_id: "11111111111111111111111111111111".to_string(),
                instruction_name: "transfer".to_string(),
                protocol_name: "System Program".to_string(),
                manifest_version: None,
                approved: true,
                confidence: 0.9,
                risk_status: "Clear".to_string(),
                policy_verdict: "Approved".to_string(),
                l3_status: "inconclusive".to_string(),
                l8_status: "inconclusive".to_string(),
            });
        }
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/protocols/top").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let top = json["top"].as_array().unwrap();
        assert!(!top.is_empty() && top.len() <= 5, "top 5 protocols");
        // System Program (1500 battle-tested + 3 observed) must rank first.
        assert_eq!(top[0]["program_id"], "11111111111111111111111111111111");
        assert_eq!(top[0]["observed_verifications"], 3);
        let _ = dir;
    }

    #[tokio::test]
    async fn dashboard_registry_returns_records_and_reviewers() {
        let (state, dir) = test_state();
        let mut engine = crate::manifest_registry::ManifestRegistryEngine::new();
        engine.register_reviewer("reviewerPubkey1", 1000).unwrap();
        let mut state = state;
        state.registry_engine = engine;
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/registry").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(json["record_count"], 0, "no submissions yet (read-only)");
        assert_eq!(json["reviewers"][0]["pubkey"], "reviewerPubkey1");
        assert_eq!(json["reviewers"][0]["reputation_score"], 1000);
        let _ = dir;
    }

    #[tokio::test]
    async fn dashboard_endpoints_respect_api_key_auth() {
        let (state, dir) = test_state();
        let state = AppState {
            api_key: Some(std::sync::Arc::new("sekret".to_string())),
            ..state
        };
        let app = build_app(state, vec![]);
        use axum::body::Body;
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .uri("/api/graph")
            .body(Body::empty())
            .unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        let _ = dir;
    }

    /// A 5xx must never echo internal error text to the caller. The detail
    /// belongs in the log and the audit record; the client gets a generic
    /// message plus a stable error CLASS it can branch on.
    ///
    /// Asserted at the classification boundary rather than by trying to
    /// provoke a specific internal failure over HTTP: the property under test
    /// is "Internal never discloses its payload", which is exactly what this
    /// checks, and it keeps holding as new internal error sources are added.
    #[test]
    fn internal_errors_never_disclose_their_detail_to_clients() {
        let secret = "connection string user=admin password=hunter2 at /srv/internal";
        let err = VerificationHttpError::Internal(secret.to_string());

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            !err.client_message().contains(secret),
            "internal detail leaked to the client: {}",
            err.client_message()
        );
        assert!(
            !err.client_message().contains("password"),
            "internal detail leaked to the client: {}",
            err.client_message()
        );
        // …but it is still available for the log line and audit record.
        assert!(
            err.message().contains(secret),
            "internal detail must remain available server-side for diagnosis"
        );

        // A 400 is caller-fixable input feedback and stays specific (P3).
        let bad = VerificationHttpError::BadRequest("Invalid address: xyz".to_string());
        assert_eq!(bad.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(bad.client_message(), "Invalid address: xyz");
    }

    /// `error_type` is returned to clients, so it must be the variant NAME
    /// only — `format!("{:?}", e)` renders the payload too and would leak the
    /// same internal detail the message redaction just removed.
    #[test]
    fn error_kind_exposes_only_the_variant_name() {
        let secret = "internal path /srv/graphite/secret";
        let e = VerificationError::TransactionBuild(secret.to_string());
        assert_eq!(error_kind(&e), "TransactionBuild");
        assert!(
            !error_kind(&e).contains(secret),
            "error_type must not carry the payload"
        );
        // Guard the actual regression: the Debug form (used for logs/audit)
        // DOES contain the payload, which is exactly why it must not be the
        // thing sent to clients.
        assert!(
            format!("{e:?}").contains(secret),
            "Debug is the detailed form — if this ever stops being true, the \
             log/audit path lost detail"
        );
    }

    /// `/metrics` exposes operational counters — but it also reveals traffic
    /// volume, block rates, and auth-failure counts, so it must sit BEHIND the
    /// API key like every other non-health endpoint. Only `/health` is open,
    /// for load balancers.
    #[tokio::test]
    async fn metrics_endpoint_requires_auth_and_health_does_not() {
        let (state, dir) = test_state();
        let state = AppState {
            api_key: Some(std::sync::Arc::new("sekret".to_string())),
            ..state
        };
        let app = build_app(state, vec![]);
        use axum::body::Body;
        use tower::ServiceExt;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let mut unauth = axum::http::Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        unauth.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(
            app.clone().oneshot(unauth).await.unwrap().status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "/metrics must not be publicly readable"
        );

        let mut health = axum::http::Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        health.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(
            app.clone().oneshot(health).await.unwrap().status(),
            axum::http::StatusCode::OK,
            "/health stays open for load balancers"
        );
        let _ = dir;
    }

    /// The metrics surface must be real: counters that are exported but never
    /// incremented are worse than absent, because operators build alerts on
    /// them. Drive a rejected request and assert the counter actually moves.
    #[tokio::test]
    async fn metrics_counters_reflect_real_events() {
        let (state, dir) = test_state();
        let state = AppState {
            api_key: Some(std::sync::Arc::new("sekret".to_string())),
            ..state
        };
        let app = build_app(state, vec![]);
        use axum::body::Body;
        use tower::ServiceExt;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Two unauthenticated calls -> two auth failures.
        for _ in 0..2 {
            let mut req = axum::http::Request::builder()
                .uri("/manifests")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            let _ = app.clone().oneshot(req).await.unwrap();
        }

        let mut req = axum::http::Request::builder()
            .uri("/metrics")
            .header(header::AUTHORIZATION, "Bearer sekret")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);

        assert!(
            text.contains("graphite_auth_failures_total 2"),
            "auth failures must be counted, got:\n{text}"
        );
        // Prometheus text format requires HELP/TYPE metadata to be parseable.
        assert!(text.contains("# TYPE graphite_auth_failures_total counter"));
        assert!(text.contains("graphite_audit_enabled 1"));
        let _ = dir;
    }

    /// Real-listener concurrency storm: 8 parallel workers × 25 /verify calls
    /// plus concurrent dashboard reads against one bound server. Proves the
    /// shared state (Arc<Mutex<SemanticGraphStore>>, Mutex-guarded audit log,
    /// per-IP rate limiter) survives real parallelism with zero 5xx/panics,
    /// and that the audit log durably records every concurrent verification.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_verify_storm_shares_state_and_stays_healthy() {
        let (mut state, dir) = test_state();
        // Raise the per-IP limit so the storm exercises concurrency, not 429s.
        state.rate = RateLimiter::with_capacity(10_000, 100_000.0);
        let assert_core = state.core.clone();
        let app = build_app(state, vec![]);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serve = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        );
        let server_task = tokio::spawn(async move {
            serve.await.expect("server must run");
        });

        let client = reqwest::Client::new();
        let base = format!("http://{addr}");
        let body = serde_json::json!({
            "proposed_intent": {
                "intent_type": "transfer",
                "raw_natural_language": "Transfer 1 SOL to friend",
                "confidence_of_parse": 0.95
            },
            "program_id": "11111111111111111111111111111111",
            "protocol_version": "1.0.0",
            "instruction_discriminator": "02000000",
            "account_addresses": [
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"
            ],
            "wallet_profile": "TradingBot"
        })
        .to_string();

        const WORKERS: usize = 8;
        const PER_WORKER: usize = 25;
        let start = std::time::Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..WORKERS {
            let client = client.clone();
            let body = body.clone();
            let base = base.clone();
            tasks.push(tokio::spawn(async move {
                let mut results = Vec::with_capacity(PER_WORKER);
                for _ in 0..PER_WORKER {
                    let resp = client
                        .post(format!("{base}/verify"))
                        .header("content-type", "application/json")
                        .body(body.clone())
                        .send()
                        .await
                        .expect("post must succeed");
                    let status = resp.status();
                    let json: serde_json::Value =
                        resp.json().await.unwrap_or(serde_json::Value::Null);
                    results.push((status, json.get("confidence").and_then(|c| c.as_f64())));
                }
                results
            }));
        }
        // Concurrent dashboard reads on the same server.
        let mut readers = Vec::new();
        for _ in 0..4 {
            let client = client.clone();
            let base = base.clone();
            readers.push(tokio::spawn(async move {
                let mut out = Vec::new();
                for path in [
                    "/manifests",
                    "/api/graph",
                    "/api/confidence-history",
                    "/health",
                ] {
                    let r = client
                        .get(format!("{base}{path}"))
                        .send()
                        .await
                        .expect("get must succeed");
                    out.push((path.to_string(), r.status()));
                }
                out
            }));
        }
        let mut all: Vec<(reqwest::StatusCode, Option<f64>)> = Vec::new();
        for t in tasks {
            all.extend(t.await.expect("worker task must not panic"));
        }
        for r in readers {
            for (path, status) in r.await.expect("reader task must not panic") {
                assert_eq!(status, reqwest::StatusCode::OK, "GET {path} under load");
            }
        }
        let elapsed = start.elapsed();

        for (status, confidence) in &all {
            assert_eq!(*status, reqwest::StatusCode::OK, "verify under concurrency");
            let c = confidence.expect("confidence must be a number");
            assert!(
                c.is_finite() && (0.0..=1.0).contains(&c),
                "confidence out of range: {c}"
            );
        }
        assert_eq!(all.len(), WORKERS * PER_WORKER, "every verify answered");

        // The shared semantic graph survived uncorrupted: the seeded System
        // evidence is still intact (verify_async is a read-only scorer — see
        // forensic report C10).
        let snapshot = assert_core.graph_snapshot();
        let sys = snapshot
            .nodes
            .iter()
            .find(|n| n.program_id == "11111111111111111111111111111111")
            .expect("seeded system node must survive the storm");
        assert_eq!(sys.battle_tested_tx_count, 1500);

        // Durability: the audit log durably recorded ALL 200 verifications
        // despite 8 concurrent writers (Mutex-guarded append). Valid only
        // because the server task is fully joined above (abort → router drop
        // → audit File handle drop → flush), so every append is visible to a
        // fresh open.
        let log = AuditLog::open(audit_path(&dir)).unwrap();
        let (records, errors, total, _) = log.read_tail_filtered(10_000, |_| true);
        assert_eq!(
            total,
            WORKERS * PER_WORKER,
            "every concurrent verification must reach the audit log"
        );
        assert_eq!(records.len(), WORKERS * PER_WORKER);
        assert!(errors.is_empty(), "no error records from a clean storm");

        server_task.abort();
        let _ = server_task.await;
        let rate = (WORKERS * PER_WORKER) as f64 / elapsed.as_secs_f64();
        println!(
            "stress: {WORKERS}×{PER_WORKER} verifies + 16 dashboard reads in {}ms → {rate:.0} verifies/s (includes dashboard reads)",
            elapsed.as_millis()
        );
    }

    /// Hostile-body battery against /verify: invalid JSON, wrong types, deep
    /// nesting, a >1MB body (body-limit middleware), a 200k-account list
    /// (body cap), a 2k-account list (semantic MAX_ACCOUNTS cap), and random
    /// bytes. Every case must be a clean 4xx — never a 5xx, never a panic —
    /// and the server must still answer /health afterwards.
    #[tokio::test]
    async fn hostile_verify_bodies_never_return_5xx() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mut state, _dir) = test_state();
        state.rate = RateLimiter::with_capacity(10_000, 100_000.0);
        let app = build_app(state, vec![]);

        let two_k_accounts: String = (0..2_000)
            .map(|_| "\"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"")
            .collect::<Vec<_>>()
            .join(",");
        let two_hundred_k_accounts: String = (0..200_000)
            .map(|_| "\"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"")
            .collect::<Vec<_>>()
            .join(",");
        let deep = format!("{{\"a\":{}}}", "[".repeat(5000) + &"]".repeat(5000));
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("invalid json", b"{ not json".to_vec()),
            ("empty body", Vec::new()),
            ("null", b"null".to_vec()),
            ("json array", b"[1,2,3]".to_vec()),
            ("wrong types", br#"{"program_id": 123, "account_addresses": "x"}"#.to_vec()),
            ("partial input", br#"{"program_id":"11111111111111111111111111111111"}"#.to_vec()),
            ("deeply nested", deep.into_bytes()),
            ("5MB string", format!("{{\"program_id\":\"{}\"}}", "1".repeat(5_000_000)).into_bytes()),
            (
                "200k accounts (over body cap)",
                format!(
                    "{{\"program_id\":\"11111111111111111111111111111111\",\"instruction_discriminator\":\"02000000\",\"account_addresses\":[{two_hundred_k_accounts}]}}"
                )
                .into_bytes(),
            ),
            (
                "2k accounts (over MAX_ACCOUNTS=64)",
                format!(
                    "{{\"program_id\":\"11111111111111111111111111111111\",\"instruction_discriminator\":\"02000000\",\"account_addresses\":[{two_k_accounts}]}}"
                )
                .into_bytes(),
            ),
            ("random bytes", vec![0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f]),
        ];

        for (name, bytes) in cases {
            let mut req = axum::http::Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(bytes))
                .unwrap();
            let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            let resp = app
                .clone()
                .oneshot(req)
                .await
                .expect("router must never panic on hostile input");
            let status = resp.status();
            assert!(
                status.is_client_error(),
                "{name}: expected 4xx, got {status} — a 5xx here is a bug"
            );
        }

        // Server still healthy after the barrage.
        let (status, _) = get_json(&app, "/health").await;
        assert_eq!(status, axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn panicking_handler_returns_500_and_server_survives() {
        // Certification item: a handler that panics must produce a clean 500
        // (no connection drop, no internal details leaked) and the server must
        // continue serving subsequent requests.
        use tower::ServiceExt;

        // A dedicated panicking route wrapped in the SAME catch-panic layer
        // the production router uses.
        async fn boom() -> Response {
            panic!("deliberate test panic — must be caught");
        }
        let app = Router::new()
            .route("/boom", get(boom))
            .route("/alive", get(|| async { "ok" }))
            .layer(CatchPanicLayer::custom(
                |_panic: Box<dyn std::any::Any + Send + 'static>| {
                    axum::http::Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(axum::body::Bytes::from_static(
                            b"{\"error\":\"internal server error\"}",
                        )))
                        .unwrap()
                },
            ));

        let mut req = axum::http::Request::builder()
            .uri("/boom")
            .body(axum::body::Body::empty())
            .unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "panic must map to 500"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("internal server error") && !body.contains("deliberate test panic"),
            "panic body must be generic, got: {body}"
        );

        // The router is still alive after the panic.
        let mut alive = axum::http::Request::builder()
            .uri("/alive")
            .body(axum::body::Body::empty())
            .unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        alive.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(alive).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "server must continue serving after a handler panic"
        );
    }
}
