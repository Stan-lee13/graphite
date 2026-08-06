//! HTTP server for Graphite Core — exposes the verification API over HTTP.
//!
//! Production features:
//! - CORS (configurable origins, defaults to permissive for alpha)
//! - Request body size limit (1 MB max — prevents DoS via large payloads)
//! - Request timeout (10s max — prevents slow-loris attacks)
//! - Graceful shutdown on SIGTERM/SIGINT (container-friendly)
//! - Plain-text logging to stderr (structured logging is Phase 2)

use crate::account_resolution::AccountResolutionError;
use crate::verification::{GraphiteCore, VerificationError, VerificationInput, VerificationResult};
use axum::http::StatusCode;
use axum::{extract::State, routing::get, routing::post, Json, Router};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::signal;
use tower_http::trace::TraceLayer;

/// Maximum request body size (1 MB). Verification inputs are small —
/// 10 accounts x 44 bytes + metadata ~= 2 KB. 1 MB is generous.
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Request timeout. Verification should complete in <1ms; 10s is
/// generous and prevents slow-loris style attacks.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let core = GraphiteCore::new();
    let app = build_app(core);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing_log(&format!("Graphite server listening on {}", addr));
    tracing_log(&format!(
        "CORS: permissive (all origins) | Body limit: {}KB | Timeout: {:?}",
        MAX_BODY_SIZE / 1024,
        REQUEST_TIMEOUT
    ));

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

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

fn build_app(core: GraphiteCore) -> Router {
    Router::new()
        .route("/verify", post(verify_handler))
        .route("/health", get(health_handler))
        .route("/manifests", get(manifests_handler))
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                ])
                .max_age(Duration::from_secs(3600)),
        )
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .with_state(core)
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
    State(core): State<GraphiteCore>,
    Json(input): Json<VerificationInput>,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    match core.verify_async(&input).await {
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
    State(core): State<GraphiteCore>,
) -> Json<Vec<crate::manifest::ProtocolManifest>> {
    let manifests: Vec<_> = core.list_manifests().into_iter().cloned().collect();
    Json(manifests)
}

fn tracing_log(msg: &str) {
    eprintln!("[graphite] {}", msg);
}
