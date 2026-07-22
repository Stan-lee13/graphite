//! HTTP server for Graphite Core — exposes the verification API over HTTP.

use crate::verification::{GraphiteCore, VerificationInput, VerificationResult};
use axum::{routing::post, routing::get, Router, Json, extract::State};
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

async fn verify_handler(
    State(core): State<GraphiteCore>,
    Json(input): Json<VerificationInput>,
) -> Result<Json<VerificationResult>, Json<serde_json::Value>> {
    match core.verify(&input) {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err(Json(serde_json::json!({
            "error": e.to_string(),
            "error_type": format!("{:?}", e),
        }))),
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
