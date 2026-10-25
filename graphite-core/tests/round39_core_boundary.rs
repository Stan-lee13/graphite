//! Round 39 (core-boundary audit): the system boundary, end to end through
//! the real `graphite` binary on loopback.
//!
//! - R39-CB-1: a record of another trail under the same key, appended to the
//!   end of the active file, made a restarted server resume onto that trail.
//! - R39-CB-2: with stdout and stderr both unwritable, the server panicked
//!   at its first log line (exit 101), and once running dropped every
//!   request that logged without a response.
//! - R39-CB-3: `graphite healthcheck --strict` followed a redirect to any
//!   host and passed on that host's answer.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_graphite")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "graphite-r39-cb-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A command with only what the test gives it: no `GRAPHITE_*` name of the
/// environment the tests run in reaches the binary.
fn graphite(args: &[&str]) -> Command {
    let mut c = Command::new(bin());
    c.args(args).env_clear();
    if let Ok(path) = std::env::var("PATH") {
        c.env("PATH", path);
    }
    c
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One HTTP/1.1 exchange on loopback; `None` when no response came.
fn http(port: u16, method: &str, path: &str, body: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut out = Vec::new();
    s.read_to_end(&mut out).ok()?;
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text.split(' ').nth(1)?.parse().ok()?;
    Some((status, text))
}

fn wait_for_health(port: u16, child: &mut Child) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }
        if let Some((200, _)) = http(port, "GET", "/health", "") {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

const INPUT: &str = r#"{"proposed_intent":{"intent_type":"transfer","raw_natural_language":"Transfer 1 SOL","confidence_of_parse":0.95},"program_id":"11111111111111111111111111111111","protocol_version":"1.0.0","instruction_discriminator":"02000000","account_addresses":["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU","8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"],"wallet_profile":"TradingBot"}"#;

/// A dev-mode server on loopback over `data`, with `stdout`/`stderr`.
fn dev_server(data: &Path, port: u16, stdout: Stdio, stderr: Stdio) -> Child {
    graphite(&["server", "--port", &port.to_string()])
        .env("GRAPHITE_DEV_MODE", "1")
        .env("GRAPHITE_DATA_DIR", data)
        .env("GRAPHITE_REGISTRY_STATE", data.join("registry_state.json"))
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap()
}

/// R39-CB-2. `tracing-subscriber` reported a log line it could not write
/// with `eprintln!`, which panics when stderr cannot be written either.
#[cfg(target_os = "linux")]
#[test]
fn a_server_whose_log_cannot_be_written_still_starts_and_answers() {
    let data = temp_dir("devfull");
    let port = free_port();
    let full = || Stdio::from(std::fs::File::create("/dev/full").unwrap());
    let mut child = dev_server(&data, port, full(), full());
    let up = wait_for_health(port, &mut child);
    let exited = child.try_wait().ok().flatten();
    let verdict = up.then(|| http(port, "POST", "/verify", INPUT)).flatten();
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        up,
        "the server did not come up with stdout and stderr unwritable (exited: {exited:?}; 101 is a panic)"
    );
    let (status, text) = verdict.expect("no response to /verify: the connection was dropped");
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("\"decision\""), "{text}");
    // Benign control: the verdict is on the trail, the record the log is not.
    let trail = std::fs::read_to_string(data.join("audit.jsonl")).unwrap();
    assert_eq!(trail.lines().count(), 1, "{trail}");
    std::fs::remove_dir_all(&data).ok();
}

/// A loopback server answering every request with `response`.
fn canned(response: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn ok_health() -> String {
    let body = r#"{"status":"ok","degraded":false}"#;
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// R39-CB-3. The probe is for the process on this host, at this port.
#[test]
fn healthcheck_does_not_follow_a_redirect() {
    let elsewhere = canned(ok_health());
    let redirector = canned(format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{elsewhere}/health\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ));
    let out = graphite(&["healthcheck", "--port", &redirector.to_string(), "--strict"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "the healthcheck passed on the answer of the host a redirect named"
    );
    // Benign control: the same answer, served at the port itself, passes.
    let out = graphite(&["healthcheck", "--port", &elsewhere.to_string(), "--strict"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A 32-byte hex key file, mode 600, outside any data directory.
fn key_file(tag: &str) -> PathBuf {
    let dir = temp_dir(&format!("key-{tag}"));
    let path = dir.join("audit.key");
    std::fs::write(&path, "41".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

/// `n` keyed records on the trail of `data`, written offline by
/// `graphite quarantine add` (it writes the server's trail).
fn records(data: &Path, key: &Path, n: usize) {
    for program in [
        "11111111111111111111111111111111",
        "Vote111111111111111111111111111111111111111",
        "Stake11111111111111111111111111111111111111",
    ]
    .iter()
    .take(n)
    {
        let out = graphite(&[
            "quarantine",
            "add",
            "--data-dir",
            data.to_str().unwrap(),
            "--program",
            program,
            "--reason",
            "r39",
        ])
        .env("GRAPHITE_AUDIT_KEY_FILE", key)
        .output()
        .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// R39-CB-1 through the binary: `graphite server` and `graphite audit
/// verify` over a trail with another trail's record appended.
#[test]
fn a_server_does_not_resume_onto_another_trails_record() {
    let key = key_file("cb-1");
    let target = temp_dir("cb-1-target");
    let other = temp_dir("cb-1-other");
    records(&target, &key, 3);
    records(&other, &key, 1);
    let foreign = std::fs::read_to_string(other.join("audit.jsonl"))
        .unwrap()
        .lines()
        .last()
        .unwrap()
        .to_string();
    let path = target.join("audit.jsonl");
    let genuine = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{genuine}{foreign}\n")).unwrap();

    let verify = graphite(&[
        "audit",
        "verify",
        "--data-dir",
        target.to_str().unwrap(),
        "--key-file",
        key.to_str().unwrap(),
    ])
    .output()
    .unwrap();
    assert_eq!(
        verify.status.code(),
        Some(1),
        "audit verify names the break"
    );

    let start = |data: &Path| -> (bool, String) {
        let port = free_port();
        let (out, err) = (data.join("server.out"), data.join("server.err"));
        let mut child = graphite(&["server", "--port", &port.to_string()])
            .env("GRAPHITE_API_KEY", "k".repeat(64))
            .env("GRAPHITE_AUDIT_KEY_FILE", &key)
            .env("GRAPHITE_DATA_DIR", data)
            .env("GRAPHITE_REGISTRY_STATE", data.join("registry_state.json"))
            .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
            .stderr(Stdio::from(std::fs::File::create(&err).unwrap()))
            .spawn()
            .unwrap();
        let up = wait_for_health(port, &mut child);
        let _ = child.kill();
        let _ = child.wait();
        let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
        (up, format!("{}{}", read(&out), read(&err)))
    };
    let (up, log) = start(&target);
    assert!(
        !up,
        "the server resumed onto another trail's record appended at the end"
    );
    assert!(log.contains("another trail"), "{log}");

    // Benign control: the genuine trail starts.
    std::fs::write(&path, &genuine).unwrap();
    let (up, log) = start(&target);
    assert!(up, "{log}");
    for d in [&target, &other] {
        std::fs::remove_dir_all(d).ok();
    }
    std::fs::remove_dir_all(key.parent().unwrap()).ok();
}
