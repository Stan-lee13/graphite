//! Audit 2026-10-20: configuration the server cannot honour is a startup
//! error, never a silent fallback or a panic.
//!
//! - L2: `GRAPHITE_CORS_ORIGINS=*` reached tower-http's origin list, which
//!   panics on a wildcard: the server died at startup with a backtrace.
//! - Several settings fell back to their defaults on a value that did not
//!   parse (`GRAPHITE_TRUST_PROXY`, `GRAPHITE_MAX_CONCURRENT`,
//!   `GRAPHITE_MAX_CONNECTIONS`, `GRAPHITE_MAX_CONNECTIONS_PER_IP`,
//!   `GRAPHITE_CONNECTION_LIFETIME_SECS`, `GRAPHITE_AUDIT_ROTATE_BYTES`,
//!   `GRAPHITE_AUDIT_MAX_ARCHIVES`, the boolean switches), while
//!   `GRAPHITE_RATE_LIMIT` beside them refused to start.
//! - A corrupt registry state file started the server with an EMPTY registry
//!   (every accepted community manifest gone, every reviewer forgotten), while
//!   the CLI reading the same file refused it.
//! - A `GRAPHITE_PLUGIN_EVENTS_FILE` that could not be attached logged a line
//!   and started without the event stream; an unloadable
//!   `GRAPHITE_PLUGINS_DIR` was already a startup error.
//!
//! Each case calls `run_server` with one bad setting and pins that it returns
//! an error naming the setting, without binding. One test function, because
//! the cases share the process environment.
#![cfg(feature = "server")]

use std::net::{SocketAddr, TcpListener};

const CLEARED: &[&str] = &[
    "GRAPHITE_API_KEY",
    "GRAPHITE_ADMIN_API_KEY",
    "GRAPHITE_RPC_URL",
    "GRAPHITE_RPC_WITNESS_URL",
    "GRAPHITE_PLUGINS_DIR",
    "GRAPHITE_PLUGIN_EVENTS_FILE",
    "GRAPHITE_WALLET_PROFILE",
    "GRAPHITE_ALLOW_PERMISSIVE_PROFILES",
    "GRAPHITE_TRUST_PROXY",
    "GRAPHITE_TRUSTED_PROXIES",
    "GRAPHITE_RATE_LIMIT",
    "GRAPHITE_AUDIT_ROTATE_BYTES",
    "GRAPHITE_AUDIT_MAX_ARCHIVES",
    "GRAPHITE_MAX_CONCURRENT",
    "GRAPHITE_MAX_CONNECTIONS",
    "GRAPHITE_MAX_CONNECTIONS_PER_IP",
    "GRAPHITE_CONNECTION_LIFETIME_SECS",
    "GRAPHITE_ALLOW_DURABLE_NONCE",
    "GRAPHITE_QUARANTINE_ON_UPGRADE",
    "GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS",
    "GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT",
    "GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS",
    "GRAPHITE_CORS_ORIGINS",
    "GRAPHITE_AUDIT_KEY_FILE",
    "GRAPHITE_AUDIT_ANCHOR_DIR",
];

/// Run the server with `extra` set on top of a clean dev-mode environment;
/// return its startup error. Panics if it started.
fn startup_error(case: usize, extra: &[(&str, String)]) -> String {
    let dir = std::env::temp_dir().join(format!(
        "graphite-startup-refusals-{}-{case}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for k in CLEARED {
        std::env::remove_var(k);
    }
    std::env::set_var("GRAPHITE_DEV_MODE", "1");
    std::env::set_var("GRAPHITE_DATA_DIR", &dir);
    std::env::set_var("GRAPHITE_REGISTRY_STATE", dir.join("no-registry.json"));
    for (k, v) in extra {
        std::env::set_var(k, v);
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            graphite_core::server::run_server(addr),
        )
        .await
    });
    let _ = std::fs::remove_dir_all(&dir);
    match outcome {
        Ok(Err(e)) => e.to_string(),
        Ok(Ok(())) => panic!("case {case}: the server started and shut down: {extra:?}"),
        Err(_) => panic!("case {case}: the server STARTED with {extra:?}"),
    }
}

/// A well-formed audit key that group and others can read: refused on Unix
/// (`chmod 600`); elsewhere a key that is too short, refused everywhere.
fn loose_key_file() -> String {
    let path = std::env::temp_dir().join(format!(
        "graphite-startup-refusals-{}-audit.key",
        std::process::id()
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&path, "ab".repeat(32)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    #[cfg(not(unix))]
    std::fs::write(&path, "ab".repeat(8)).unwrap();
    path.display().to_string()
}

#[test]
fn configuration_the_server_cannot_honour_refuses_to_start() {
    let s = |v: &str| v.to_string();
    let cases: Vec<(Vec<(&str, String)>, &str)> = vec![
        (
            vec![("GRAPHITE_CORS_ORIGINS", s("*"))],
            "GRAPHITE_CORS_ORIGINS",
        ),
        (
            vec![("GRAPHITE_CORS_ORIGINS", s("https://ok.example, *"))],
            "GRAPHITE_CORS_ORIGINS",
        ),
        (
            vec![("GRAPHITE_TRUST_PROXY", s("yes"))],
            "GRAPHITE_TRUST_PROXY",
        ),
        // Round 40 (R39-CB-8): a hop count with no proxy list would believe
        // X-Forwarded-For from any peer; the refusal names both variables.
        (
            vec![("GRAPHITE_TRUST_PROXY", s("1"))],
            "GRAPHITE_TRUST_PROXY=1 is set and GRAPHITE_TRUSTED_PROXIES is unset",
        ),
        (
            vec![
                ("GRAPHITE_TRUST_PROXY", s("true")),
                ("GRAPHITE_TRUSTED_PROXIES", s(" ")),
            ],
            "GRAPHITE_TRUSTED_PROXIES is empty",
        ),
        (
            vec![
                ("GRAPHITE_TRUST_PROXY", s("1")),
                ("GRAPHITE_TRUSTED_PROXIES", s("127.0.0.1,caddy")),
            ],
            "GRAPHITE_TRUSTED_PROXIES entry \"caddy\"",
        ),
        (
            vec![
                ("GRAPHITE_TRUST_PROXY", s("1")),
                ("GRAPHITE_TRUSTED_PROXIES", s("0.0.0.0/0")),
            ],
            "trusts every peer",
        ),
        (
            vec![("GRAPHITE_TRUSTED_PROXIES", s("10.0.0.1/33"))],
            "GRAPHITE_TRUSTED_PROXIES entry \"10.0.0.1/33\"",
        ),
        (
            vec![("GRAPHITE_MAX_CONCURRENT", s("3O"))],
            "GRAPHITE_MAX_CONCURRENT",
        ),
        (
            vec![("GRAPHITE_MAX_CONCURRENT", s("0"))],
            "GRAPHITE_MAX_CONCURRENT",
        ),
        (
            vec![("GRAPHITE_MAX_CONNECTIONS", s("lots"))],
            "GRAPHITE_MAX_CONNECTIONS",
        ),
        (
            vec![("GRAPHITE_MAX_CONNECTIONS_PER_IP", s("-1"))],
            "GRAPHITE_MAX_CONNECTIONS_PER_IP",
        ),
        (
            vec![("GRAPHITE_CONNECTION_LIFETIME_SECS", s("2m"))],
            "GRAPHITE_CONNECTION_LIFETIME_SECS",
        ),
        (
            vec![("GRAPHITE_AUDIT_ROTATE_BYTES", s("64MB"))],
            "GRAPHITE_AUDIT_ROTATE_BYTES",
        ),
        (
            vec![("GRAPHITE_AUDIT_MAX_ARCHIVES", s("all"))],
            "GRAPHITE_AUDIT_MAX_ARCHIVES",
        ),
        (
            vec![("GRAPHITE_ALLOW_PERMISSIVE_PROFILES", s("yes"))],
            "GRAPHITE_ALLOW_PERMISSIVE_PROFILES",
        ),
        (
            vec![("GRAPHITE_ALLOW_DURABLE_NONCE", s("on"))],
            "GRAPHITE_ALLOW_DURABLE_NONCE",
        ),
        // Round 32: the relaxations of the production defaults.
        (
            vec![("GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS", s("yes"))],
            "GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS",
        ),
        (
            vec![(
                "GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT",
                s("on"),
            )],
            "GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT",
        ),
        (
            vec![("GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS", s("2"))],
            "GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS",
        ),
        (
            vec![(
                "GRAPHITE_PLUGIN_EVENTS_FILE",
                s("/nonexistent-graphite-dir/events.jsonl"),
            )],
            "GRAPHITE_PLUGIN_EVENTS_FILE",
        ),
        // Round 30 (G-07): an operator who set a key file or an anchor
        // directory must not get an unkeyed or unanchored trail.
        (
            vec![("GRAPHITE_AUDIT_KEY_FILE", s(" "))],
            "GRAPHITE_AUDIT_KEY_FILE",
        ),
        (
            vec![(
                "GRAPHITE_AUDIT_KEY_FILE",
                s("/nonexistent-graphite-dir/audit.key"),
            )],
            "GRAPHITE_AUDIT_KEY_FILE",
        ),
        (
            vec![("GRAPHITE_AUDIT_KEY_FILE", loose_key_file())],
            "GRAPHITE_AUDIT_KEY_FILE",
        ),
        (
            vec![(
                "GRAPHITE_AUDIT_ANCHOR_DIR",
                s("/nonexistent-graphite-anchor"),
            )],
            "GRAPHITE_AUDIT_ANCHOR_DIR",
        ),
    ];
    for (i, (extra, names)) in cases.iter().enumerate() {
        let e = startup_error(i, extra);
        assert!(e.contains(names), "case {i} {extra:?}: {e}");
    }

    // A corrupt registry state file.
    let corrupt = std::env::temp_dir().join(format!(
        "graphite-startup-refusals-{}-registry.json",
        std::process::id()
    ));
    std::fs::write(&corrupt, "{ this is not a registry").unwrap();
    let e = startup_error(
        cases.len(),
        &[("GRAPHITE_REGISTRY_STATE", corrupt.display().to_string())],
    );
    let _ = std::fs::remove_file(&corrupt);
    assert!(e.contains("CORRUPT"), "{e}");
}
