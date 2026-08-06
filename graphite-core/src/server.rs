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

/// Shared application state.
#[derive(Clone)]
struct AppState {
    core: GraphiteCore,
    /// Bearer API key; `None` = unauthenticated (dev only).
    api_key: Option<Arc<String>>,
    audit: Option<AuditLog>,
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
}
