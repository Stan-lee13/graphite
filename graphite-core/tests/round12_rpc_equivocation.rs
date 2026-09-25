//! Requires the `rpc` feature: every case here is about what an RPC says.
#![cfg(feature = "rpc")]

//! Round 12: an RPC that equivocates about inclusion.
//!
//! Round 11 bound the bytes an RPC returns to the signature they were
//! fetched under, so an RPC can no longer say which transaction executed.
//! It could still say WHETHER one did — `getSignatureStatuses` was taken at
//! its word, at any commitment, with any slot, from one endpoint — and it
//! could say two different things about one signature in two calls without
//! either being noticed. These pin what L8 now does with each way an RPC
//! can be wrong about inclusion:
//!
//! - a status at `processed` commitment is one node's view and no positive
//!   conclusion rests on it; the alarm on a blocked verdict still fires;
//! - a status and a transaction that disagree about the slot or the outcome
//!   are an RPC contradicting itself; no positive conclusion;
//! - a status that says "included" beside a `getTransaction` that says
//!   `null` is disclosed as `chain_bytes_unavailable`, so the caller-key
//!   attribution that follows is visibly not the chain's;
//! - a malformed status (no slot, neither Ok nor Err, no or unknown
//!   commitment) is `Unavailable`, never "included and failed";
//! - a 3xx answer is not followed anywhere;
//! - with an inclusion witness attached, a positive conclusion needs both
//!   endpoints to agree, either endpoint's sighting of a BLOCKED
//!   transaction alarms, and a witness that is the primary is refused.
//!
//! Every RPC here is a loopback mock. Nothing touches a public endpoint.

use graphite_core::durable::{audit_path, AuditLog, AuditRecord, LifecycleEvent};
use graphite_core::rpc_client::{
    validate_endpoint, EndpointError, InclusionCommitment, RpcConfig, SolanaRpcClient,
};
use graphite_core::tx_artifact::{artifact_sha256_of_signed, message_bytes};
use graphite_core::verification::{
    ExecutionAttribution, ExecutionKeys, ExecutionReconciliation, ExecutionVerification,
    GraphiteCore,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";

fn payer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
}

fn corpus_entry(name: &str) -> serde_json::Value {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
            .expect("corpus must parse");
    raw["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("corpus entry {name}"))
        .clone()
}

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

/// The corpus transfer under the test's fee payer, signed for real, so the
/// chain's bytes bind to the signature (Round 11).
fn signed_transfer() -> Vec<u8> {
    use ed25519_dalek::Signer;
    let entry = corpus_entry("legacy_single_transfer");
    let keys: Vec<String> = entry["static_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    let old = bs58::decode(&keys[0]).into_vec().unwrap();
    let mut raw = bytes(&entry["raw"]);
    let pos = raw
        .windows(32)
        .position(|w| w == old.as_slice())
        .expect("the corpus fee payer is in the frame");
    raw[pos..pos + 32].copy_from_slice(&payer().verifying_key().to_bytes());
    let sig = payer().sign(message_bytes(&raw).unwrap());
    raw[1..65].copy_from_slice(&sig.to_bytes());
    raw
}

fn sig_of(signed: &[u8]) -> String {
    bs58::encode(&signed[1..65]).into_string()
}

/// A JSON-RPC answer body for one method, given the request's params.
type Answer = Arc<dyn Fn(&str, &serde_json::Value) -> String + Send + Sync>;

/// A mock cluster on loopback answering with `answer`; `hits` counts
/// requests.
fn cluster(answer: Answer, hits: Arc<AtomicUsize>) -> String {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
    let addr = listener.local_addr().unwrap();
    let server = Arc::clone(&listener);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = server.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body_json: serde_json::Value = req
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str(b).ok())
                .unwrap_or(serde_json::Value::Null);
            hits.fetch_add(1, Ordering::SeqCst);
            let method = body_json["method"].as_str().unwrap_or("?").to_string();
            let body = answer(&method, &body_json["params"]);
            let head = if let Some(location) = body.strip_prefix("REDIRECT ") {
                format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            };
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.flush();
        }
    });
    std::mem::forget(listener);
    format!("http://{addr}")
}

fn status_body(slot: u64, ok: bool, commitment: &str) -> String {
    let status = if ok {
        r#"{"Ok":null}"#
    } else {
        r#"{"Err":{"InstructionError":[0,"Custom"]}}"#
    };
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":2}},"value":[{{"slot":{slot},"confirmations":10,"confirmationStatus":"{commitment}","err":null,"status":{status}}}]}}}}"#
    )
}

const UNKNOWN: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[null]}}"#;

fn tx_body(signed: &[u8], slot: u64, ok: bool) -> String {
    use base64::Engine;
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":{slot},"transaction":["{}","base64"],"meta":{{"err":{}}}}}}}"#,
        base64::engine::general_purpose::STANDARD.encode(signed),
        if ok {
            "null"
        } else {
            r#"{"InstructionError":[0,"Custom"]}"#
        }
    )
}

/// The standard honest cluster: confirmed in `slot`, bytes in the same slot
/// with the same outcome.
fn honest(signed: Vec<u8>, slot: u64, ok: bool, commitment: &'static str) -> Answer {
    Arc::new(move |method, _| match method {
        "getSignatureStatuses" => status_body(slot, ok, commitment),
        "getTransaction" => tx_body(&signed, slot, ok),
        _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
    })
}

fn client(endpoint: &str) -> SolanaRpcClient {
    SolanaRpcClient::new(RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: std::time::Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    })
}

fn core_at(endpoint: &str) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client(endpoint));
    core
}

fn temp_log(tag: &str) -> (AuditLog, std::path::PathBuf) {
    let d = std::env::temp_dir().join(format!(
        "graphite-r12-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    (AuditLog::open(audit_path(&d)).unwrap(), d)
}

/// A verification row for the signed transfer, approved or blocked.
fn record(log: &AuditLog, signed: &[u8], approved: bool) -> AuditRecord {
    let r = AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: graphite_core::durable::now_utc_rfc3339(),
        audit_trail_id: format!("gr-r12-{}", if approved { "approved" } else { "blocked" }),
        content_hash: "48c65c638aceb5de".to_string(),
        transaction_sha256: Some(artifact_sha256_of_signed(signed).unwrap()),
        program_id: SYSTEM.to_string(),
        instruction_name: "Transfer".to_string(),
        protocol_name: "System Program".to_string(),
        manifest_version: Some("1.0.0".to_string()),
        approved,
        confidence: if approved { 0.9 } else { 0.3 },
        risk_status: "Clear".to_string(),
        policy_verdict: if approved { "Approved" } else { "Rejected" }.to_string(),
        l3_status: "inconclusive".to_string(),
        l8_status: "inconclusive".to_string(),
    };
    assert!(log.append(&r));
    r
}

fn unavailable_reason(r: &ExecutionReconciliation) -> &str {
    match r {
        ExecutionReconciliation::Unavailable { reason } => reason,
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

// ─── commitment ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_processed_status_is_not_a_positive_conclusion() {
    let signed = signed_transfer();
    let sig = sig_of(&signed);
    let hits = Arc::new(AtomicUsize::new(0));
    let core = core_at(&cluster(
        honest(signed.clone(), 12345, true, "processed"),
        hits,
    ));

    let (log, dir) = temp_log("processed");
    record(&log, &signed, true);
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    match &audit.chain_status {
        ExecutionVerification::Confirmed { commitment, .. } => {
            assert_eq!(*commitment, InclusionCommitment::Processed)
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(audit.attribution, ExecutionAttribution::Chain);
    let reason = unavailable_reason(&audit.reconciliation);
    assert!(
        reason.contains("processed") && reason.contains("one node"),
        "{reason}"
    );

    // The same sighting of a BLOCKED transaction is the alarm, at any
    // commitment.
    let (log, dir2) = temp_log("processed-blocked");
    record(&log, &signed, false);
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );
    assert!(audit.reconciliation.is_discrepancy());

    // At confirmed and finalized the positive conclusion stands.
    for commitment in ["confirmed", "finalized"] {
        let hits = Arc::new(AtomicUsize::new(0));
        let core = core_at(&cluster(
            honest(signed.clone(), 12345, true, commitment),
            hits,
        ));
        let (log, d) = temp_log(commitment);
        record(&log, &signed, true);
        let audit = core
            .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
            .await;
        assert_eq!(
            audit.reconciliation,
            ExecutionReconciliation::ApprovedAndExecuted,
            "{commitment}"
        );
        let _ = std::fs::remove_dir_all(d);
    }
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(dir2);
}

// ─── self-contradiction ─────────────────────────────────────────────────────

#[tokio::test]
async fn an_rpc_that_contradicts_itself_gets_no_positive_conclusion() {
    let signed = signed_transfer();
    let sig = sig_of(&signed);

    // Slot: the status says 12345, the transaction says 12346.
    let s = signed.clone();
    let answer: Answer = Arc::new(move |method, _| match method {
        "getSignatureStatuses" => status_body(12345, true, "finalized"),
        "getTransaction" => tx_body(&s, 12346, true),
        _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
    });
    let core = core_at(&cluster(answer, Arc::new(AtomicUsize::new(0))));
    let (log, dir) = temp_log("slot");
    record(&log, &signed, true);
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    let why = audit
        .chain_inconsistent
        .as_deref()
        .expect("the contradiction is named");
    assert!(why.contains("12345") && why.contains("12346"), "{why}");
    let reason = unavailable_reason(&audit.reconciliation);
    assert!(reason.contains("contradicts itself"), "{reason}");
    // The bytes were still bound and attributed — the contradiction is
    // about inclusion, and it is the conclusion that is withheld.
    assert_eq!(audit.attribution, ExecutionAttribution::Chain);
    assert_eq!(audit.recorded_approved, Some(true));

    // Outcome: the status says Ok, the transaction's meta says it failed.
    let s = signed.clone();
    let answer: Answer = Arc::new(move |method, _| match method {
        "getSignatureStatuses" => status_body(12345, true, "finalized"),
        "getTransaction" => tx_body(&s, 12345, false),
        _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
    });
    let core = core_at(&cluster(answer, Arc::new(AtomicUsize::new(0))));
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    let why = audit.chain_inconsistent.as_deref().expect("named");
    assert!(why.contains("succeeded") && why.contains("failed"), "{why}");
    assert!(matches!(
        audit.reconciliation,
        ExecutionReconciliation::Unavailable { .. }
    ));

    // A BLOCKED transaction under the same contradiction still alarms:
    // the inconsistency withholds the good news, never the bad.
    let (log, dir2) = temp_log("slot-blocked");
    record(&log, &signed, false);
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(dir2);
}

// ─── included, but no bytes ─────────────────────────────────────────────────

#[tokio::test]
async fn a_status_without_bytes_is_disclosed_as_caller_attributed() {
    let signed = signed_transfer();
    let sig = sig_of(&signed);
    let answer: Answer = Arc::new(move |method, _| match method {
        "getSignatureStatuses" => status_body(12345, true, "finalized"),
        _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
    });
    let core = core_at(&cluster(answer, Arc::new(AtomicUsize::new(0))));
    let (log, dir) = temp_log("nobytes");
    let rec = record(&log, &signed, true);

    // With the exact key, the caller's attestation stands in — and the
    // answer says so twice: `attribution` and `chain_bytes_unavailable`.
    let audit = core
        .audit_execution(
            &sig,
            ExecutionKeys {
                audit_trail_id: Some(&rec.audit_trail_id),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted
    );
    assert_eq!(audit.attribution, ExecutionAttribution::AuditTrailId);
    let why = audit.chain_bytes_unavailable.as_deref().expect("disclosed");
    assert!(why.contains("null"), "{why}");
    assert!(audit.chain_transaction_sha256.is_none());

    // With no key there is nothing to stand in.
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert!(matches!(
        audit.reconciliation,
        ExecutionReconciliation::Unavailable { .. }
    ));
    assert!(audit.chain_bytes_unavailable.is_some());
    let _ = std::fs::remove_dir_all(dir);
}

// ─── malformed statuses ─────────────────────────────────────────────────────

#[tokio::test]
async fn a_malformed_status_is_never_a_conclusion() {
    let signed = signed_transfer();
    let sig = sig_of(&signed);
    let cases: Vec<(&str, String)> = vec![
        (
            "no slot",
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"confirmations":10,"confirmationStatus":"finalized","err":null,"status":{"Ok":null}}]}}"#.to_string(),
        ),
        (
            "neither Ok nor Err",
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"slot":12345,"confirmations":10,"confirmationStatus":"finalized","err":null,"status":{}}]}}"#.to_string(),
        ),
        (
            "no confirmationStatus",
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"slot":12345,"confirmations":10,"err":null,"status":{"Ok":null}}]}}"#.to_string(),
        ),
        (
            "unknown confirmationStatus",
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"slot":12345,"confirmations":10,"confirmationStatus":"probably","err":null,"status":{"Ok":null}}]}}"#.to_string(),
        ),
    ];
    let (log, dir) = temp_log("malformed");
    record(&log, &signed, true);
    for (label, body) in cases {
        let s = signed.clone();
        let answer: Answer = Arc::new(move |method, _| match method {
            "getSignatureStatuses" => body.clone(),
            "getTransaction" => tx_body(&s, 12345, true),
            _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
        });
        let core = core_at(&cluster(answer, Arc::new(AtomicUsize::new(0))));
        let audit = core
            .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
            .await;
        assert!(
            matches!(audit.chain_status, ExecutionVerification::Unavailable(_)),
            "{label}: {:?}",
            audit.chain_status
        );
        let reason = unavailable_reason(&audit.reconciliation);
        assert!(reason.contains("getSignatureStatuses"), "{label}: {reason}");
        // Before Round 12, "neither Ok nor Err" read as included-and-failed.
        assert!(
            !matches!(
                audit.reconciliation,
                ExecutionReconciliation::ApprovedButFailedOnChain { .. }
            ),
            "{label}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

// ─── redirects ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_redirecting_rpc_is_not_followed() {
    let signed = signed_transfer();
    let sig = sig_of(&signed);
    // Where the redirect points: an RPC that would happily confirm anything.
    let elsewhere_hits = Arc::new(AtomicUsize::new(0));
    let elsewhere = cluster(
        honest(signed.clone(), 12345, true, "finalized"),
        Arc::clone(&elsewhere_hits),
    );
    let target = format!("{elsewhere}/");
    let answer: Answer = Arc::new(move |_, _| format!("REDIRECT {target}"));
    let core = core_at(&cluster(answer, Arc::new(AtomicUsize::new(0))));
    let (log, dir) = temp_log("redirect");
    record(&log, &signed, true);
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    let reason = unavailable_reason(&audit.reconciliation);
    assert!(reason.contains("redirect"), "{reason}");
    assert_eq!(
        elsewhere_hits.load(Ordering::SeqCst),
        0,
        "the redirect target must never be contacted"
    );
    let _ = std::fs::remove_dir_all(dir);
}

// ─── the inclusion witness ──────────────────────────────────────────────────

#[tokio::test]
async fn a_positive_conclusion_needs_the_witness_to_agree() {
    let signed = signed_transfer();
    let sig = sig_of(&signed);
    let primary = cluster(
        honest(signed.clone(), 12345, true, "finalized"),
        Arc::new(AtomicUsize::new(0)),
    );
    let (log, dir) = temp_log("witness");
    record(&log, &signed, true);

    // Agreeing witness: the conclusion stands and says both agreed.
    let witness_hits = Arc::new(AtomicUsize::new(0));
    let witness = cluster(
        honest(signed.clone(), 12345, true, "confirmed"),
        Arc::clone(&witness_hits),
    );
    let mut core = core_at(&primary);
    core.attach_inclusion_witness(client(&witness)).unwrap();
    assert!(core.has_inclusion_witness());
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted
    );
    let w = audit.inclusion_witness.as_ref().expect("witness consulted");
    assert!(w.agrees, "{}", w.detail);
    assert_eq!(w.seen, Some(true));
    assert_eq!(w.commitment, Some(InclusionCommitment::Confirmed));
    assert_eq!(
        witness_hits.load(Ordering::SeqCst),
        1,
        "one call per reconciliation"
    );

    // A witness with no record: the primary's "included" is one endpoint's
    // word, and the conclusion is withheld.
    let witness = cluster(
        Arc::new(|_, _| UNKNOWN.to_string()),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut core = core_at(&primary);
    core.attach_inclusion_witness(client(&witness)).unwrap();
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    let reason = unavailable_reason(&audit.reconciliation);
    assert!(reason.contains("disagree"), "{reason}");
    let w = audit.inclusion_witness.as_ref().unwrap();
    assert!(!w.agrees && w.seen == Some(false), "{}", w.detail);

    // A witness in a different slot: same.
    let witness = cluster(
        honest(signed.clone(), 99999, true, "finalized"),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut core = core_at(&primary);
    core.attach_inclusion_witness(client(&witness)).unwrap();
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert!(matches!(
        audit.reconciliation,
        ExecutionReconciliation::Unavailable { .. }
    ));
    let w = audit.inclusion_witness.as_ref().unwrap();
    assert!(w.detail.contains("99999"), "{}", w.detail);

    // An unreachable witness: no second source, no conclusion.
    // Owned for the life of the test and answering nothing: a port that is
    // bound and dropped can be taken by another test's mock in this binary.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                drop(stream);
            }
        });
        format!("http://{a}")
    };
    let mut core = core_at(&primary);
    core.attach_inclusion_witness(client(&closed)).unwrap();
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert!(matches!(
        audit.reconciliation,
        ExecutionReconciliation::Unavailable { .. }
    ));
    let w = audit.inclusion_witness.as_ref().unwrap();
    assert!(
        w.seen.is_none() && w.detail.contains("could not be consulted"),
        "{}",
        w.detail
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn either_endpoint_seeing_a_blocked_transaction_alarms() {
    let signed = signed_transfer();
    let sig = sig_of(&signed);
    let (log, dir) = temp_log("witness-blocked");
    let rec = record(&log, &signed, false);

    // The primary has no record; the witness does.
    let primary = cluster(
        Arc::new(|_, _| UNKNOWN.to_string()),
        Arc::new(AtomicUsize::new(0)),
    );
    let witness = cluster(
        honest(signed.clone(), 12345, true, "processed"),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut core = core_at(&primary);
    core.attach_inclusion_witness(client(&witness)).unwrap();
    let audit = core
        .audit_execution(&sig, ExecutionKeys::default(), Some(&log))
        .await;
    assert!(matches!(
        audit.chain_status,
        ExecutionVerification::UnknownSignature(_)
    ));
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedButExecuted
    );
    // The bytes that named the verdict came from the witness, bound to the
    // signature like any other chain bytes.
    assert_eq!(audit.attribution, ExecutionAttribution::Chain);
    assert_eq!(
        audit.recorded_audit_trail_id.as_deref(),
        Some(rec.audit_trail_id.as_str())
    );
    // Without the witness the same primary answer read as "correctly never
    // landed".
    let core = core_at(&primary);
    let audit = core
        .audit_execution(
            &sig,
            ExecutionKeys {
                audit_trail_id: Some(&rec.audit_trail_id),
                ..Default::default()
            },
            Some(&log),
        )
        .await;
    assert_eq!(
        audit.reconciliation,
        ExecutionReconciliation::BlockedAndNotExecuted
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_witness_that_is_the_primary_is_refused() {
    let mut core = core_at("http://127.0.0.1:1");
    let err = core
        .attach_inclusion_witness(client("http://127.0.0.1:1"))
        .expect_err("refused");
    assert!(err.contains("same endpoint"), "{err}");
    assert!(!core.has_inclusion_witness());
    core.attach_inclusion_witness(client("http://127.0.0.1:2"))
        .expect("a different endpoint is a witness");
    assert!(core.has_inclusion_witness());
}

// ─── the endpoint itself ────────────────────────────────────────────────────

#[test]
fn endpoints_are_validated_before_a_client_exists() {
    assert!(matches!(
        validate_endpoint("ftp://rpc.example/"),
        Err(EndpointError::Scheme(s)) if s == "ftp"
    ));
    assert!(matches!(
        validate_endpoint("file:///etc/passwd"),
        Err(EndpointError::Scheme(_))
    ));
    assert!(matches!(
        validate_endpoint("not a url"),
        Err(EndpointError::NotAUrl(_))
    ));
    assert!(matches!(
        validate_endpoint("https://rpc.example/#frag"),
        Err(EndpointError::Fragment)
    ));
    assert!(matches!(
        validate_endpoint("http://:8899"),
        Err(EndpointError::NotAUrl(_) | EndpointError::NoHost)
    ));

    let f = validate_endpoint("http://127.0.0.1:8899").unwrap();
    assert!(f.loopback && f.scheme == "http" && !f.has_query && !f.has_userinfo);
    let f = validate_endpoint("http://localhost:8899/").unwrap();
    assert!(f.loopback);
    let f = validate_endpoint("http://[::1]:8899/").unwrap();
    assert!(f.loopback);
    let f = validate_endpoint("https://user:secret@rpc.example/v1/?api-key=k").unwrap();
    assert!(!f.loopback && f.scheme == "https" && f.has_query && f.has_userinfo);

    // The refusal never carries the endpoint: a provider URL is a secret.
    let err = validate_endpoint("ftp://user:secret@rpc.example/?api-key=k").unwrap_err();
    let text = err.to_string();
    assert!(
        !text.contains("secret") && !text.contains("api-key") && !text.contains("rpc.example"),
        "{text}"
    );
}
