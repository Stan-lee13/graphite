//! Round 40 (assurance): the shared conformance corpus,
//! `examples/decisions/conformance.json`, through the two surfaces that
//! Round 39 left out — the HTTP server's JSON and the `graphite` CLI
//! (invariants 3 and 11 of `docs/audit/INVARIANT_EVIDENCE_MATRIX.md`).
//!
//! Neither surface reads a verdict: both BUILD one from a request and then
//! serialise it (the server through axum's `Json`, the CLI with
//! `serde_json::to_string_pretty`) and the CLI turns it into an exit status
//! with `cli::verify_exit_code`. So the corpus is driven through them in two
//! ways:
//!
//! 1. every vector the Core's types read goes through the narrowest function
//!    of each surface that decides — `verify_exit_code` (0 only for an
//!    executable verdict) and each surface's serialiser, whose output must
//!    read back to the same answer;
//! 2. each of the corpus's four bases (`executable_approved`,
//!    `analysis_only`, `inconclusive`, `blocked`) is produced again by the
//!    real `graphite` binary — `graphite server` on loopback against a
//!    loopback mock cluster, and `graphite verify` / `graphite explain` —
//!    and what comes back on the wire (the HTTP body, the dashboard's
//!    `/api/confidence-history` row, the CLI's stdout and exit status) must
//!    carry the decision the committed base carries.
//!
//! The dashboard's half is `dashboard/src/conformance.test.ts`.
#![cfg(feature = "cli")]

use graphite_core::cli::verify_exit_code;
use graphite_core::verification::{ExecutionDecision, VerificationResult};
use serde_json::Value;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../examples/decisions")
}

fn corpus() -> Value {
    let raw =
        std::fs::read_to_string(dir().join("conformance.json")).expect("the corpus is committed");
    let c: Value = serde_json::from_str(&raw).expect("the corpus is JSON");
    assert_eq!(c["version"], 1);
    c
}

/// The vector's text: its base with the exact replacements applied (the
/// corpus's own rule, as `round39_conformance_corpus.rs` applies it).
fn vector_text(v: &Value) -> String {
    let base = v["base"].as_str().expect("base");
    let mut text =
        std::fs::read_to_string(dir().join(format!("{base}.json"))).expect("base verdict");
    for pair in v["raw_replace"].as_array().into_iter().flatten() {
        let (from, to) = (pair[0].as_str().unwrap(), pair[1].as_str().unwrap());
        assert_eq!(text.matches(from).count(), 1, "{}: {from:?}", v["name"]);
        text = text.replacen(from, to, 1);
    }
    text
}

fn apply_edits(v: &Value, doc: &mut Value) {
    for e in v["edits"].as_array().into_iter().flatten() {
        let path = e["path"].as_array().expect("path");
        let (last, parents) = path.split_last().expect("a non-empty path");
        let mut at = &mut *doc;
        for step in parents {
            at = match step {
                Value::String(k) => &mut at[k.as_str()],
                Value::Number(i) => &mut at[i.as_u64().unwrap() as usize],
                other => panic!("path step {other}"),
            };
        }
        match (e["op"].as_str().unwrap(), last) {
            ("set", Value::String(k)) => at[k.as_str()] = e["value"].clone(),
            ("set", Value::Number(i)) => at[i.as_u64().unwrap() as usize] = e["value"].clone(),
            ("delete", Value::String(k)) => {
                at.as_object_mut().unwrap().remove(k.as_str());
            }
            ("push", Value::String(k)) => at[k.as_str()]
                .as_array_mut()
                .unwrap()
                .push(e["value"].clone()),
            (op, step) => panic!("{}: edit {op} at {step}", v["name"]),
        }
    }
}

/// The vector as the Core's type reads it; `None` where the Core refuses to
/// read it (the corpus's `unreadable`).
fn read(v: &Value) -> Option<VerificationResult> {
    let text = vector_text(v);
    if v.get("edits").is_some() {
        let mut doc: Value = serde_json::from_str(&text).expect("edits start from valid JSON");
        apply_edits(v, &mut doc);
        serde_json::from_value(doc).ok()
    } else {
        serde_json::from_str(&text).ok()
    }
}

fn outcome(r: &VerificationResult) -> &'static str {
    if r.is_executable() {
        "executable"
    } else {
        "not_executable"
    }
}

/// The exit status `graphite verify` / `graphite explain` documents
/// (`src/cli.rs`, `verify_exit_code`; README "exit codes"): 0 only for a
/// verdict that permits signing, 1 for a refusal (`blocked`,
/// `inconclusive`, or anything not approved), 3 for an approval that does
/// not permit signing. Stated from the corpus, not from the function: 0
/// exactly where the corpus says the Core's rule is `executable`.
fn documented_exit(r: &VerificationResult, corpus_rust: &str) -> i32 {
    if corpus_rust == "executable" {
        0
    } else if matches!(
        r.decision,
        ExecutionDecision::Blocked | ExecutionDecision::Inconclusive
    ) || !r.approved
    {
        1
    } else {
        3
    }
}

/// The CLI's decision over every corpus verdict the Core can read: exit 0
/// for exactly the vectors the corpus marks executable, and the documented
/// 1 or 3 for every other one — including the 23 that still SAY
/// `decision: executable_approved, executable: true` beside a residual, a
/// failed layer or a policy refusal that takes the permission away.
#[test]
fn the_cli_exit_status_decides_every_corpus_verdict_as_the_corpus_says() {
    let c = corpus();
    let verdicts = c["verdicts"].as_array().expect("verdicts");
    assert!(verdicts.len() >= 90, "{} verdict vectors", verdicts.len());
    let (mut wrong, mut by_code, mut unreadable, mut claims) = (Vec::new(), [0usize; 4], 0, 0);
    for v in verdicts {
        let want = v["expect"]["rust"].as_str().unwrap();
        let Some(r) = read(v) else {
            assert_eq!(want, "unreadable", "{}", v["name"]);
            // The CLI never reads a verdict; one the Core cannot read
            // never reaches `verify_exit_code` at all.
            unreadable += 1;
            continue;
        };
        assert_eq!(outcome(&r), want, "{}: the Core's rule", v["name"]);
        let got = verify_exit_code(&r);
        let expected = documented_exit(&r, want);
        if got != expected {
            wrong.push(format!("{}: exit {got}, documented {expected}", v["name"]));
        }
        if got == 0 && want != "executable" {
            wrong.push(format!(
                "{}: exit 0 for a verdict that is not executable",
                v["name"]
            ));
        }
        if r.decision == ExecutionDecision::ExecutableApproved
            && r.executable
            && want != "executable"
        {
            claims += 1;
        }
        by_code[got.clamp(0, 3) as usize] += 1;
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    // The corpus exercises every status the CLI documents, and the forged
    // claims are among what it reads (at Round 40: exit 0 / 1 / 3 for
    // 21 / 9 / 43 vectors, 29 unreadable, 23 forged claims).
    assert!(by_code[0] >= 7, "exit 0: {}", by_code[0]);
    assert!(by_code[1] >= 4, "exit 1: {}", by_code[1]);
    assert!(by_code[3] >= 4, "exit 3: {}", by_code[3]);
    assert_eq!(by_code[2], 0, "exit 2 is not a verdict's status");
    assert!(unreadable >= 20, "{unreadable} unreadable");
    assert!(
        claims >= 15,
        "{claims} vectors claim executable and are not"
    );
}

/// What each surface writes for a verdict reads back to the same answer: the
/// server's body (axum's `Json`, the handler's own return type) and the
/// CLI's `to_string_pretty`. A field the serialiser drops, renames or
/// defaults differently would turn an approval into a different decision on
/// the wire than in the Core.
#[cfg(feature = "server")]
#[test]
fn the_server_and_cli_json_of_every_corpus_verdict_reads_back_to_the_same_decision() {
    use axum::response::IntoResponse;
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let c = corpus();
    let mut checked = 0;
    for v in c["verdicts"].as_array().unwrap() {
        let Some(r) = read(v) else { continue };
        let want = v["expect"]["rust"].as_str().unwrap();
        let response = axum::Json(r.clone()).into_response();
        assert_eq!(response.status(), 200, "{}", v["name"]);
        assert_eq!(
            response.headers()["content-type"],
            "application/json",
            "{}",
            v["name"]
        );
        let body = rt
            .block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
            .unwrap();
        let http = String::from_utf8(body.to_vec()).unwrap();
        let cli = serde_json::to_string_pretty(&r).unwrap();
        for (surface, text) in [("http", &http), ("cli", &cli)] {
            let wire: Value = serde_json::from_str(text).unwrap();
            // The two fields a client gates on are on the wire, as the Core
            // holds them.
            assert_eq!(
                wire["decision"],
                r.decision.as_str(),
                "{surface}: {}",
                v["name"]
            );
            assert_eq!(wire["executable"], r.executable, "{surface}: {}", v["name"]);
            assert_eq!(wire["approved"], r.approved, "{surface}: {}", v["name"]);
            let back: VerificationResult = serde_json::from_str(text).unwrap_or_else(|e| {
                panic!(
                    "{surface}: {}: the Core cannot read its own JSON: {e}",
                    v["name"]
                )
            });
            assert_eq!(outcome(&back), want, "{surface}: {}", v["name"]);
            assert_eq!(
                verify_exit_code(&back),
                verify_exit_code(&r),
                "{surface}: {}",
                v["name"]
            );
            // A fixed point: written again, the same bytes.
            let again = if surface == "http" {
                serde_json::to_string(&back).unwrap()
            } else {
                serde_json::to_string_pretty(&back).unwrap()
            };
            assert_eq!(&again, text, "{surface}: {}: not a fixed point", v["name"]);
        }
        checked += 1;
    }
    assert!(checked >= 70, "{checked} readable vectors");
}

/// The corpus's four bases, produced again through the real binary.
#[cfg(feature = "server")]
mod real_binary {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const SYSTEM: &str = "11111111111111111111111111111111";

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "graphite-r40-surface-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Only what the test gives it: no `GRAPHITE_*` of the environment the
    /// tests run in reaches the binary.
    fn graphite(args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_graphite"));
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

    fn http(port: u16, method: &str, path: &str, body: &str) -> Option<(u16, String)> {
        let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).ok()?;
        let mut out = Vec::new();
        s.read_to_end(&mut out).ok()?;
        let text = String::from_utf8_lossy(&out).to_string();
        let status = text.split(' ').nth(1)?.parse().ok()?;
        let body = text.split_once("\r\n\r\n")?.1.to_string();
        Some((status, body))
    }

    fn account(lamports: u64) -> String {
        format!(
            r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
        )
    }

    #[derive(Clone, Copy, Debug)]
    enum Sim {
        Clean,
        Errored,
        RpcError,
    }

    /// The loopback cluster `round30_decision_fixtures.rs` produced the
    /// committed bases against: `getMultipleAccounts` and
    /// `simulateTransaction` answered as `sim` says, anything else `null`.
    fn cluster(sim: Sim) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body_json: Value = req
                    .split("\r\n\r\n")
                    .nth(1)
                    .and_then(|b| serde_json::from_str(b).ok())
                    .unwrap_or(Value::Null);
                let body = match body_json["method"].as_str().unwrap_or("?") {
                    "getMultipleAccounts" => {
                        let count = body_json["params"][0]
                            .as_array()
                            .map(|a| a.len())
                            .unwrap_or(0);
                        let vals: Vec<String> = (0..count)
                            .map(|i| account(if i == 0 { 1_000_000_000 } else { 1_000_000 }))
                            .collect();
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":[{}]}}}}"#,
                            vals.join(",")
                        )
                    }
                    "simulateTransaction" => {
                        let count = body_json["params"][1]["accounts"]["addresses"]
                            .as_array()
                            .map(|a| a.len())
                            .unwrap_or(0);
                        let post: Vec<String> = (0..count)
                            .map(|i| account(if i == 0 { 997_995_000 } else { 3_000_000 }))
                            .collect();
                        let complete = |err: &str, accounts: &str| {
                            format!(
                                r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                                "err":{err},"logs":[],"unitsConsumed":150,"fee":5000,
                                "preBalances":[1000000000,1000000,1],"postBalances":[997995000,3000000,1],
                                "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                                {accounts}"returnData":null}}}}}}"#
                            )
                        };
                        match sim {
                            Sim::Clean => complete("null", &format!(r#""accounts":[{}],"#, post.join(","))),
                            Sim::Errored => complete(r#"{"InstructionError":[0,"Custom(1)"]}"#, r#""accounts":null,"#),
                            Sim::RpcError => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"node is behind"}}"#.to_string(),
                        }
                    }
                    _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    /// The request the bases were produced for (`round30_decision_fixtures.rs`
    /// `transfer()`): the bridge corpus's legacy transfer of 2,000,000
    /// lamports, described faithfully, under a Custom 0.40 / OfficialManifest
    /// profile.
    fn transfer_input(profile: Value) -> String {
        let raw: Value =
            serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
                .unwrap();
        let entry = raw["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == "legacy_single_transfer")
            .expect("corpus entry")
            .clone();
        let keys = entry["static_keys"].as_array().unwrap();
        let mut data = vec![2u8, 0, 0, 0];
        data.extend_from_slice(&2_000_000u64.to_le_bytes());
        serde_json::json!({
            "proposed_intent": {
                "intent_type": "transfer",
                "raw_natural_language": "send SOL",
                "confidence_of_parse": 0.95,
                "extracted_parameters": {
                    "amount": "0.002",
                    "destination": keys[1],
                    "input_token": "SOL"
                }
            },
            "program_id": SYSTEM,
            "protocol_version": "1.0.0",
            "instruction_discriminator": "02000000",
            "account_addresses": [keys[0], keys[1]],
            "instruction_data": data,
            "cpi_targets": [],
            "wallet_profile": profile,
            "compute_units": 150,
            "account_writes": 2,
            "cpi_hops": 0,
            "signed_transaction": entry["raw"]
        })
        .to_string()
    }

    fn base_profile() -> Value {
        serde_json::json!({ "Custom": { "min_confidence": 0.40, "min_trust_tier": "OfficialManifest" } })
    }

    fn base(name: &str) -> VerificationResult {
        serde_json::from_str(&std::fs::read_to_string(dir().join(format!("{name}.json"))).unwrap())
            .unwrap()
    }

    /// The corpus's own expectation for a base as the Core wrote it.
    fn corpus_expectation(name: &str) -> String {
        corpus()["verdicts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| {
                v["base"] == name && v.get("edits").is_none() && v.get("raw_replace").is_none()
            })
            .unwrap_or_else(|| panic!("no unedited vector for {name}"))["expect"]["rust"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// What a verdict's decision rests on, compared with the committed base:
    /// the decision fields and the residual codes (`audit_trail_id` and the
    /// timestamps differ per run).
    fn assert_matches_base(got: &VerificationResult, name: &str, surface: &str) {
        let want = base(name);
        assert_eq!(
            got.decision, want.decision,
            "{surface} {name}: {}",
            got.summary
        );
        assert_eq!(got.executable, want.executable, "{surface} {name}");
        assert_eq!(got.approved, want.approved, "{surface} {name}");
        assert_eq!(
            got.risk_verdict.status, want.risk_verdict.status,
            "{surface} {name}"
        );
        assert_eq!(got.policy_verdict, want.policy_verdict, "{surface} {name}");
        let codes = |r: &VerificationResult| match &r.scope {
            graphite_core::verification::VerificationScope::ArtifactBound {
                unobserved_codes,
                ..
            } => Some(unobserved_codes.clone()),
            _ => None,
        };
        assert_eq!(codes(got), codes(&want), "{surface} {name}: residual codes");
        assert_eq!(outcome(got), corpus_expectation(name), "{surface} {name}");
        assert_eq!(got.is_executable(), got.executable, "{surface} {name}");
    }

    fn server(data: &Path, rpc: Option<&str>) -> (Child, u16) {
        let port = free_port();
        let mut c = graphite(&["server", "--port", &port.to_string()]);
        c.env("GRAPHITE_DEV_MODE", "1")
            .env("GRAPHITE_DATA_DIR", data)
            .env("GRAPHITE_REGISTRY_STATE", data.join("registry_state.json"))
            // The bases were produced under a Custom 0.40 profile, which the
            // server otherwise clamps to the weakest built-in (a fresh
            // instance's 0.44 would then be refused by policy, not by what
            // each base is about). The operator's single-tenant opt-out.
            .env("GRAPHITE_ALLOW_PERMISSIVE_PROFILES", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(rpc) = rpc {
            c.env("GRAPHITE_RPC_URL", rpc);
        }
        let mut child = c.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().ok().flatten() {
                panic!("the server exited ({status}) before it answered /health");
            }
            if let Some((200, _)) = http(port, "GET", "/health", "") {
                return (child, port);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("the server did not come up");
    }

    /// `graphite server`, over HTTP, for each base: the body is the decision
    /// the committed base carries, the Core's rule on the body is the
    /// corpus's answer for that base, and the row the dashboard reads
    /// (`/api/confidence-history`) carries the same decision, `executable`
    /// and binding — the only fields `dashboard/src/figures.ts` decides on.
    #[test]
    fn the_real_server_reproduces_each_corpus_base_on_the_wire_and_on_the_dashboard_row() {
        for (name, sim) in [
            ("executable_approved", Some(Sim::Clean)),
            ("blocked", Some(Sim::Errored)),
            ("inconclusive", Some(Sim::RpcError)),
            ("analysis_only", None),
        ] {
            let data = temp_dir(name);
            let rpc = sim.map(cluster);
            let (mut child, port) = server(&data, rpc.as_deref());
            let verdict = http(port, "POST", "/verify", &transfer_input(base_profile()));
            let history = http(port, "GET", "/api/confidence-history", "");
            let _ = child.kill();
            let _ = child.wait();
            let (status, body) = verdict.expect("no response to /verify");
            assert_eq!(status, 200, "{name}: {body}");
            let got: VerificationResult =
                serde_json::from_str(&body).unwrap_or_else(|e| panic!("{name}: {e}: {body}"));
            assert_matches_base(&got, name, "http");
            assert_eq!(
                verify_exit_code(&got),
                if name == "executable_approved" {
                    0
                } else if got.approved {
                    3
                } else {
                    1
                },
                "{name}"
            );

            let (status, history) = history.expect("no response to /api/confidence-history");
            assert_eq!(status, 200, "{name}: {history}");
            let history: Value = serde_json::from_str(&history).unwrap();
            let series = history["series"].as_array().unwrap();
            assert_eq!(series.len(), 1, "{name}: {history}");
            let row = &series[0];
            assert_eq!(row["audit_trail_id"], got.audit_trail_id.as_str(), "{name}");
            assert_eq!(row["approved"], got.approved, "{name}");
            assert_eq!(row["decision"], got.decision.as_str(), "{name}");
            assert_eq!(
                row["executable"],
                got.is_executable(),
                "{name}: the row's executable is the Core's rule"
            );
            let bound = match &got.scope {
                graphite_core::verification::VerificationScope::ArtifactBound {
                    transaction_sha256,
                    ..
                } => Value::from(transaction_sha256.as_str()),
                _ => Value::Null,
            };
            assert_eq!(row["transaction_sha256"], bound, "{name}");
            std::fs::remove_dir_all(&data).ok();
        }
    }

    /// `graphite verify` and `graphite explain` attach no RPC, so the bases
    /// they can produce are `analysis_only` (exit 3) and a refusal (exit 1);
    /// exit 0 is unreachable from them by construction, and the function
    /// that would give it is held to the corpus above.
    #[test]
    fn the_real_cli_reproduces_the_bases_it_can_produce_with_the_documented_exit_status() {
        let work = temp_dir("cli");
        let run = |cmd: &str, profile: Value| {
            let file = work.join(format!("input-{cmd}.json"));
            std::fs::write(&file, transfer_input(profile)).unwrap();
            graphite(&[cmd, "--file"])
                .arg(&file)
                .env("GRAPHITE_DATA_DIR", work.join("data"))
                .env("GRAPHITE_REGISTRY_STATE", work.join("no-registry.json"))
                .env("GRAPHITE_ALLOW_PERMISSIVE_PROFILES", "1")
                .output()
                .unwrap()
        };

        // analysis_only: the same request as the base, with no RPC.
        let out = run("verify", base_profile());
        let stdout = String::from_utf8_lossy(&out.stdout);
        let got: VerificationResult = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("{e}: {stdout}\n{}", String::from_utf8_lossy(&out.stderr)));
        assert_matches_base(&got, "analysis_only", "cli");
        assert_eq!(out.status.code(), Some(3), "analysis_only exits 3");
        let out = run("explain", base_profile());
        assert_eq!(out.status.code(), Some(3), "explain: analysis_only exits 3");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("decision: analysis_only"),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );

        // A refusal: the same bytes under the Treasury profile (0.44 is
        // below its floor).
        let out = run("verify", Value::from("Treasury"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let got: VerificationResult = serde_json::from_str(&stdout).unwrap();
        assert_eq!(got.decision, ExecutionDecision::Blocked, "{}", got.summary);
        assert!(!got.executable && !got.approved);
        assert_eq!(outcome(&got), "not_executable");
        assert_eq!(out.status.code(), Some(1), "blocked exits 1");
        let out = run("explain", Value::from("Treasury"));
        assert_eq!(out.status.code(), Some(1), "explain: blocked exits 1");
        std::fs::remove_dir_all(&work).ok();
    }
}
