//! HTTP server for Graphite Core — exposes the verification API over HTTP.

use crate::verification::{GraphiteCore, VerificationInput, VerificationResult};
use axum::http::StatusCode;
use axum::{extract::State, routing::get, routing::post, Json, Router};
use std::net::SocketAddr;

pub async fn run_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let core = GraphiteCore::new();
    let app = build_app(core);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing_log(&format!("Graphite server listening on {}", addr));
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_app(core: GraphiteCore) -> Router {
    Router::new()
        .route("/verify", post(verify_handler))
        .route("/health", get(health_handler))
        .route("/manifests", get(manifests_handler))
        .with_state(core)
}

/// Verify handler — returns 200 on success, 400 on bad input, 500 on internal error.
async fn verify_handler(
    State(core): State<GraphiteCore>,
    Json(input): Json<VerificationInput>,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    match core.verify(&input) {
        Ok(result) => Ok(Json(result)),
        Err(e) => {
            let error_type = format!("{:?}", e);
            // Input validation errors (bad addresses, invalid discriminator, etc.) = 400
            // All current VerificationError variants are input-related
            let status = StatusCode::BAD_REQUEST;
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
