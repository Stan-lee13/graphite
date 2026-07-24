//! HTTP server for Graphite Core — exposes the verification API over HTTP.
//!
//! Production features:
//! - CORS (configurable origins, defaults to permissive for alpha)
//! - Request body size limit (1 MB max — prevents DoS via large payloads)
//! - Request timeout (10s max — prevents slow-loris attacks)
//! - Graceful shutdown on SIGTERM/SIGINT (container-friendly)
//! - Structured logging (stderr, JSON-parseable)

use crate::verification::{GraphiteCore, VerificationInput, VerificationResult};
use axum::http::StatusCode;
use axum::{extract::State, routing::get, routing::post, Json, Router};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::signal;

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
    tracing_log(&format!("CORS: permissive (all origins) | Body limit: {}KB | Timeout: {:?}",
        MAX_BODY_SIZE / 1024, REQUEST_TIMEOUT));

    // Graceful shutdown — SIGTERM (Docker/K8s) and SIGINT (Ctrl+C)
    let shutdown = async {
        #[cfg(unix)]
        {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
            tokio::select! {
                _ = sigterm.recv() => tracing_log("Received SIGTERM - shutting down gracefully"),
                _ = signal::ctrl_c() => tracing_log("Received SIGINT - shutting down gracefully"),
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
        .layer(tower_http::limit::RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT))
        .with_state(core)
}

/// Verify handler — returns 200 on success, 400 on bad input, 500 on internal error.
async fn verify_handler(
    State(core): State<GraphiteCore>,
    Json(input): Json<VerificationInput>,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    match core.verify(&input) {
        Ok(result) => {
            tracing_log(&format!(
                "verify: {} | {} | confidence={:.2} | {}",
                input.program_id,
                if result.approved { "APPROVED" } else { "BLOCKED" },
                result.confidence,
                result.audit_trail_id
            ));
            Ok(Json(result))
        }
        Err(e) => {
            let error_type = format!("{:?}", e);
            let status = StatusCode::BAD_REQUEST;
            tracing_log(&format!(
                "verify: {} | ERROR | {} | {:?}",
                input.program_id, e, error_type
            ));
            Err((status, Json(serde_json::json!({
                "error": e.to_string(),
                "error_type": error_type,
                "status": status.as_u16(),
            }))))
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
