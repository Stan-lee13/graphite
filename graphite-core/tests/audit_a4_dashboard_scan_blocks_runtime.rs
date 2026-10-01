//! A4-04 (2026-09-29 audit): the dashboard's `/api/*` scans run off the async
//! runtime.
//!
//! Round 19 (F-19-18) moved the audit-trail lookups of `/audit/event` and
//! `/verify/execution` onto the blocking pool, because on the async runtime a
//! scan pinned a worker for as long as it took. The dashboard handlers were
//! not moved: `confidence_history_handler`, `policy_violations_handler`
//! (`AuditLog::read_tail_filtered`) and `top_protocols_handler`
//! (`AuditLog::observations_by_program`) parsed the whole active audit file,
//! up to 64 MiB by default, synchronously on a Tokio worker. Any holder of the
//! verify key (the agent, which the threat model assumes can be
//! prompt-injected) could send as many as there are workers, and every other
//! request, `/verify` and the unauthenticated `/health` a load balancer polls
//! included, waited behind them. `TimeoutLayer` could not fire either: its
//! timer needs a free worker.
//!
//! The fix runs the three scan handlers through `off_runtime`, which is
//! `spawn_blocking`, as F-19-18 did for the other scans.
//!
//! The test pre-fills the audit file, starts the server with two workers,
//! calibrates against one scan and an idle `/health` so it does not depend on the
//! machine's speed, and pins that `/health` answers in under half a scan while
//! four dashboard reads run. The test profile is opt-level 2, so the timings
//! are release-like.
#![cfg(feature = "server")]

use graphite_core::durable::{AuditRecord, LifecycleEvent};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// ~48 MB of verification records (below the 64 MiB rotation threshold).
const RECORDS: usize = 120_000;

fn prefill(dir: &std::path::Path) {
    let mut out = String::with_capacity(RECORDS * 420);
    for i in 0..RECORDS {
        let r = AuditRecord {
            event_type: LifecycleEvent::Verification,
            timestamp: "2026-09-29T00:00:00.000Z".to_string(),
            audit_trail_id: format!("gr-a4-{i:012}"),
            content_hash: format!("{:016x}", i as u64),
            transaction_sha256: Some(format!("{:064x}", i as u128)),
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "Transfer".to_string(),
            protocol_name: "System Program".to_string(),
            manifest_version: Some("1.0.0".to_string()),
            approved: i % 3 != 0,
            confidence: 0.61,
            risk_status: "Clear".to_string(),
            policy_verdict: "Approved".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
            wallet_profile: None,
        };
        out.push_str(&serde_json::to_string(&r).unwrap());
        out.push('\n');
    }
    std::fs::write(graphite_core::durable::audit_path(dir), out).unwrap();
}

fn start_server() -> SocketAddr {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "graphite-a4-dash-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    prefill(&dir);
    for k in [
        "GRAPHITE_API_KEY",
        "GRAPHITE_ADMIN_API_KEY",
        "GRAPHITE_RPC_URL",
        "GRAPHITE_RPC_WITNESS_URL",
        "GRAPHITE_PLUGINS_DIR",
        "GRAPHITE_PLUGIN_EVENTS_FILE",
        "GRAPHITE_WALLET_PROFILE",
        "GRAPHITE_ALLOW_PERMISSIVE_PROFILES",
        "GRAPHITE_TRUST_PROXY",
        "GRAPHITE_AUDIT_ROTATE_BYTES",
        "GRAPHITE_AUDIT_MAX_ARCHIVES",
        "GRAPHITE_MAX_CONCURRENT",
        "GRAPHITE_ALLOW_DURABLE_NONCE",
        "GRAPHITE_CORS_ORIGINS",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var("GRAPHITE_DEV_MODE", "1");
    std::env::set_var("GRAPHITE_RATE_LIMIT", "1000");
    std::env::set_var("GRAPHITE_DATA_DIR", &dir);
    std::env::set_var("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = rt.block_on(graphite_core::server::run_server(addr)) {
            eprintln!("server exited: {e}");
        }
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if get(addr, "/health").0 == 200 {
            return addr;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("server did not start");
}

/// `GET path`; (status, elapsed). Status 0 on a connection failure.
fn get(addr: SocketAddr, path: &str) -> (u16, Duration) {
    let started = Instant::now();
    let Ok(mut s) = TcpStream::connect(addr) else {
        return (0, started.elapsed());
    };
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return (0, started.elapsed());
    }
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let status = String::from_utf8_lossy(&out)
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, started.elapsed())
}

#[test]
fn dashboard_reads_do_not_stall_the_rest_of_the_server() {
    let addr = start_server();

    // Calibrate: one scan of the active file, alone.
    let (status, one_scan) = get(addr, "/api/policy-violations");
    assert_eq!(status, 200);
    let (_, idle_health) = get(addr, "/health");
    eprintln!(
        "one /api/policy-violations: {:?}; idle /health: {:?}",
        one_scan, idle_health
    );
    // Relative, not absolute: the comparison below needs a scan to be long
    // next to an idle /health, whatever the machine. A fixed 300 ms floor
    // failed on fast release runners for no defect (review F13).
    assert!(
        one_scan >= idle_health.max(Duration::from_millis(1)) * 20,
        "one scan ({one_scan:?}) is not long next to an idle /health ({idle_health:?}); raise \
         RECORDS, or the measurement below means nothing"
    );

    // Two workers; four concurrent dashboard reads.
    let readers: Vec<_> = (0..4)
        .map(|_| std::thread::spawn(move || get(addr, "/api/policy-violations")))
        .collect();
    std::thread::sleep(Duration::from_millis(100));
    let (health_status, health_latency) = get(addr, "/health");
    for r in readers {
        let _ = r.join();
    }
    eprintln!("/health during the scans: {health_status} in {health_latency:?}");
    assert_eq!(health_status, 200);
    assert!(
        health_latency < one_scan / 2,
        "/health took {health_latency:?} while four dashboard reads ran (one scan alone: \
         {one_scan:?}, idle /health: {idle_health:?}) — the scans ran on the async workers and \
         everything else queued behind them"
    );
}
