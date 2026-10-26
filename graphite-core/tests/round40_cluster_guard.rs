//! Round 40 (bootstrap, follow-up): census evidence is mainnet-beta's, and
//! the server will not serve it through another cluster's RPC.
//!
//! `graphite evidence import-census` requires `--cluster mainnet-beta` and
//! records in the data directory that its evidence is mainnet-beta's. At
//! start, a server with `GRAPHITE_RPC_URL` asks the RPC `getGenesisHash`;
//! when the data directory holds imported evidence and the answer is not
//! mainnet-beta's genesis hash (or there is no answer), it refuses to start.
//! Everything here is the real binary against a loopback mock RPC.
#![cfg(feature = "server")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const MAINNET: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const DEVNET: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const SYSTEM: &str = "11111111111111111111111111111111";

fn graphite(args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_graphite"));
    c.args(args).env_clear();
    if let Ok(path) = std::env::var("PATH") {
        c.env("PATH", path);
    }
    c
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r40-cluster-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A loopback RPC answering `getGenesisHash` with `genesis` (`None`: an
/// error); every other method `null`.
fn rpc(genesis: Option<&'static str>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = vec![0u8; 1 << 16];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let answer = match (req.contains("getGenesisHash"), genesis) {
                (true, Some(g)) => format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{g}"}}"#),
                (true, None) => {
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#
                        .to_string()
                }
                _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
                )
                .as_bytes(),
            );
        }
    });
    format!("http://{addr}")
}

fn healthy(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200")
}

/// Start the server over `data` with `rpc_url`; `Ok(())` once `/health`
/// answers, `Err(stderr)` when it exits first.
fn start(data: &Path, rpc_url: &str) -> Result<(), String> {
    let port = free_port();
    let err = data.join("server.err");
    let mut child: Child = graphite(&["server", "--port", &port.to_string()])
        .env("GRAPHITE_API_KEY", "k".repeat(64))
        .env("GRAPHITE_DATA_DIR", data)
        .env("GRAPHITE_REGISTRY_STATE", data.join("registry_state.json"))
        .env("GRAPHITE_RPC_URL", rpc_url)
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&err).unwrap()))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let outcome = loop {
        if let Ok(Some(status)) = child.try_wait() {
            break Err(format!(
                "exited {status}: {}",
                std::fs::read_to_string(&err).unwrap_or_default()
            ));
        }
        if healthy(port) {
            break Ok(());
        }
        if Instant::now() > deadline {
            break Err("neither healthy nor exited within 30 s".to_string());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = child.kill();
    let _ = child.wait();
    outcome
}

fn import(data: &Path, cluster: Option<&str>) -> std::process::Output {
    let mut c = graphite(&[
        "evidence",
        "import-census",
        "--program",
        SYSTEM,
        "--data-dir",
    ]);
    c.arg(data);
    if let Some(cluster) = cluster {
        c.args(["--cluster", cluster]);
    }
    c.output().unwrap()
}

#[test]
fn the_import_names_mainnet_beta_or_does_nothing() {
    let data = temp_dir("arg");
    for cluster in [None, Some("devnet"), Some("testnet"), Some("mainnet")] {
        let o = import(&data, cluster);
        assert!(!o.status.success(), "{cluster:?} was accepted");
        let err = String::from_utf8_lossy(&o.stderr).to_string();
        assert!(err.contains("mainnet-beta"), "{cluster:?}: {err}");
        assert!(
            !data.join("semantic_graph.json").exists(),
            "{cluster:?}: a refused import wrote the graph"
        );
    }
    assert!(import(&data, Some("mainnet-beta")).status.success());
    let _ = std::fs::remove_dir_all(&data);
}

/// The refusal: imported evidence, an RPC on devnet (or one that will not
/// say) — the server does not start, and says why.
#[test]
fn a_server_refuses_to_start_on_another_clusters_rpc_with_imported_evidence() {
    let data = temp_dir("refuse");
    assert!(import(&data, Some("mainnet-beta")).status.success());
    let e = start(&data, &rpc(Some(DEVNET))).unwrap_err();
    assert!(
        e.contains("refusing to start") && e.contains(DEVNET) && e.contains(MAINNET),
        "{e}"
    );
    let e = start(&data, &rpc(None)).unwrap_err();
    assert!(
        e.contains("refusing to start") && e.contains("could not say which cluster"),
        "{e}"
    );
    let _ = std::fs::remove_dir_all(&data);
}

/// The acceptance: the same data directory on a mainnet-beta RPC starts;
/// a data directory with no imported evidence starts on any cluster.
#[test]
fn a_server_starts_on_mainnet_beta_and_without_imported_evidence_anywhere() {
    let data = temp_dir("accept");
    assert!(import(&data, Some("mainnet-beta")).status.success());
    start(&data, &rpc(Some(MAINNET))).unwrap();
    let fresh = temp_dir("fresh");
    start(&fresh, &rpc(Some(DEVNET))).unwrap();
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&fresh);
}
