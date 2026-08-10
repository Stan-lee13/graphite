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
    trust_proxy: bool,
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

/// Best-effort client IP: honors `X-Forwarded-For` first hop ONLY when the
/// server is explicitly behind a trusted proxy (`GRAPHITE_TRUST_PROXY=1`).
/// Otherwise the header is ignored entirely — an attacker who can reach the
/// server directly must NOT be able to spoof the header to rotate IPs and
/// bypass per-IP rate limiting.
fn client_ip(
    req: &axum::http::Request<axum::body::Body>,
    addr: SocketAddr,
    trust_proxy: bool,
) -> IpAddr {
    if trust_proxy {
        if let Some(ip) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next().map(str::trim))
            .and_then(|v| v.parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    addr.ip()
}

pub async fn run_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    // ---- configuration from environment ----
    let data_dir = std::env::var("GRAPHITE_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("graphite-data"));
    std::fs::create_dir_all(&data_dir)?;

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

    let audit = match AuditLog::open(audit_path(&data_dir)) {
        Ok(log) => {
            tracing_log(&format!("audit log: {}", audit_path(&data_dir).display()));
            Some(log)
        }
        Err(e) => {
            tracing_log(&format!("WARNING: audit log unavailable: {}", e));
            None
        }
    };

    // X-Forwarded-For is only honored behind an explicitly-trusted proxy.
    let trust_proxy = std::env::var("GRAPHITE_TRUST_PROXY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let state = AppState {
        core,
        api_key: api_key.clone(),
        audit,
        // Fresh engine per process: submissions and reviewer registrations are
        // operator/PR-flow writes (Phase 2/3); the dashboard reads current
        // state. Persistence is intentionally deferred to the PR workflow
        // milestone — nothing is lost because nothing is writable over HTTP
        // yet (read-only surface, P4).
        registry_engine: crate::manifest_registry::ManifestRegistryEngine::new(),
        rate: RateLimiter::new(rate_per_sec),
        trust_proxy,
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
    let ip = client_ip(&req, addr, state.trust_proxy);
    if !state.rate.check(ip) {
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

    pub fn message(&self) -> &str {
        match self {
            Self::BadRequest(msg) => msg,
            Self::Internal(msg) => msg,
        }
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

    match state.core.verify_async(&input).await {
        Ok(result) => {
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
                    "error": http_error.message(),
                    "error_type": error_type,
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

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "graphite-core",
        "version": env!("CARGO_PKG_VERSION"),
    }))
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
            ..Default::default()},
        )
        .unwrap();
        let audit = AuditLog::open(audit_path(&dir)).unwrap();
        let state = AppState {
            core,
            api_key: None,
            audit: Some(audit),
            registry_engine: crate::manifest_registry::ManifestRegistryEngine::new(),
            rate: RateLimiter::new(1000.0),
            trust_proxy: false,
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
}
