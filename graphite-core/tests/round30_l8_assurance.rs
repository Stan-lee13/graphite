//! Requires the `rpc` feature: every case here is about what an RPC says.
#![cfg(feature = "rpc")]

//! Round 30 (G-08): what an L8 reconciliation's account of inclusion rests
//! on, and the high-assurance mode that requires an independent witness.
//!
//! L8 asks RPC providers about the chain; it checks no light-client proof.
//! Before this round a reconciliation did not say whether its account came
//! from one provider or two, and nothing judged whether a configured witness
//! was a different provider at all — `https://a.example` and
//! `https://b.example` on one machine were "two sources". These pin:
//!
//! - every reconciliation carries `inclusion_assurance`: `single_provider`,
//!   `witnessed`, `witnessed_not_independent`, `witness_disputed` or
//!   `witness_unavailable`;
//! - a witness on the same host, the same registrable domain, or loopback
//!   beside a loopback primary is not independent;
//! - in high-assurance mode no statement of what the chain holds — executed,
//!   failed, absent — rests on less than an independent witness that agrees,
//!   while the alarm on a blocked transaction is never withheld;
//! - each way a primary or witness can be wrong (censoring, lagging, lying
//!   about the slot, substituting bytes signed by another key, padding
//!   signature slots, redirecting) leaves no positive conclusion.
//!
//! Every RPC here is a loopback mock. Nothing touches a public endpoint.

use graphite_core::durable::{audit_path, AuditLog, AuditRecord, LifecycleEvent};
use graphite_core::rpc_client::{
    validate_endpoint, witness_independence, EndpointError, RpcConfig, SolanaRpcClient,
    WitnessIndependence,
};
use graphite_core::tx_artifact::{artifact_sha256_of_signed, message_bytes};
use graphite_core::verification::{
    ExecutionAudit, ExecutionKeys, ExecutionReconciliation, GraphiteCore, InclusionAssurance,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SYSTEM: &str = "11111111111111111111111111111111";

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
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

/// The corpus transfer with `signer` as fee payer, signed for real.
fn signed_by(signer: &ed25519_dalek::SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let entry = corpus_entry("legacy_single_transfer");
    let old = bs58::decode(entry["static_keys"][0].as_str().unwrap())
        .into_vec()
        .unwrap();
    let mut raw: Vec<u8> = entry["raw"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    let pos = raw
        .windows(32)
        .position(|w| w == old.as_slice())
        .expect("the corpus fee payer is in the frame");
    raw[pos..pos + 32].copy_from_slice(&signer.verifying_key().to_bytes());
    let sig = signer.sign(message_bytes(&raw).unwrap());
    raw[1..65].copy_from_slice(&sig.to_bytes());
    raw
}

fn sig_of(signed: &[u8]) -> String {
    bs58::encode(&signed[1..65]).into_string()
}

type Answer = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// A mock RPC on loopback; a body starting `REDIRECT ` answers 307.
fn cluster(answer: Answer) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let method = req
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                .and_then(|v| v["method"].as_str().map(str::to_string))
                .unwrap_or_default();
            let body = answer(&method);
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
        }
    });
    format!("http://{addr}")
}

fn status_body(slot: u64, commitment: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":2}},"value":[{{"slot":{slot},"confirmations":10,"confirmationStatus":"{commitment}","err":null,"status":{{"Ok":null}}}}]}}}}"#
    )
}

const UNKNOWN: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[null]}}"#;
const NULL: &str = r#"{"jsonrpc":"2.0","id":1,"result":null}"#;

fn tx_body(bytes: &[u8], slot: u64) -> String {
    use base64::Engine;
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"slot":{slot},"transaction":["{}","base64"],"meta":{{"err":null}}}}}}"#,
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

/// Finalized in `slot`, serving `bytes` for the signature.
fn serving(bytes: Vec<u8>, slot: u64) -> Answer {
    Arc::new(move |method| match method {
        "getSignatureStatuses" => status_body(slot, "finalized"),
        "getTransaction" => tx_body(&bytes, slot),
        _ => NULL.to_string(),
    })
}

fn knows_nothing() -> Answer {
    Arc::new(|method| match method {
        "getSignatureStatuses" => UNKNOWN.to_string(),
        _ => NULL.to_string(),
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

/// A core on `primary`, with `witness` when given. `independent` records the
/// operator's assessment that the witness is another provider — the mocks
/// all live on loopback, which the URL check alone rightly calls one machine.
fn core(primary: &str, witness: Option<&str>, independent: bool, high: bool) -> GraphiteCore {
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client(primary));
    if let Some(w) = witness {
        core.attach_inclusion_witness(client(w)).unwrap();
        if independent {
            core.set_witness_independence(WitnessIndependence::Distinct);
        }
    }
    core.set_require_independent_witness(high);
    core
}

fn temp_log(tag: &str) -> (AuditLog, std::path::PathBuf) {
    let d = std::env::temp_dir().join(format!(
        "graphite-r30-l8-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    (AuditLog::open(audit_path(&d)).unwrap(), d)
}

fn record(log: &AuditLog, signed: &[u8], approved: bool) {
    assert!(log.append(&AuditRecord {
        event_type: LifecycleEvent::Verification,
        timestamp: graphite_core::durable::now_utc_rfc3339(),
        audit_trail_id: format!("gr-r30-{}", if approved { "approved" } else { "blocked" }),
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
        wallet_profile: None,
    }));
}

/// Reconcile `signed` against a trail holding one verdict for it. The
/// caller's `transaction_sha256` is supplied, as the agent guard supplies it,
/// so a source with no bytes still finds the record.
async fn reconcile(core: &GraphiteCore, signed: &[u8], approved: bool, tag: &str) -> ExecutionAudit {
    let (log, dir) = temp_log(tag);
    record(&log, signed, approved);
    let digest = artifact_sha256_of_signed(signed).unwrap();
    let keys = ExecutionKeys {
        transaction_sha256: Some(&digest),
        ..Default::default()
    };
    let audit = core
        .audit_execution(&sig_of(signed), keys, Some(&log))
        .await;
    let _ = std::fs::remove_dir_all(dir);
    audit
}

fn unavailable(r: &ExecutionReconciliation) -> &str {
    match r {
        ExecutionReconciliation::Unavailable { reason } => reason,
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

// ─── the label ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn every_reconciliation_says_what_its_account_rests_on() {
    let signed = signed_by(&key(0x42));
    let honest = cluster(serving(signed.clone(), 777));

    // No witness: the primary's word.
    let a = reconcile(&core(&honest, None, false, false), &signed, true, "single").await;
    assert_eq!(a.reconciliation, ExecutionReconciliation::ApprovedAndExecuted);
    assert_eq!(a.inclusion_assurance, InclusionAssurance::SingleProvider);

    // A loopback witness beside a loopback primary agrees, but it is one
    // machine: reported as such, and outside high-assurance the conclusion
    // stands as before.
    let twin = cluster(serving(signed.clone(), 777));
    let a = reconcile(&core(&honest, Some(&twin), false, false), &signed, true, "twin").await;
    assert_eq!(a.reconciliation, ExecutionReconciliation::ApprovedAndExecuted);
    assert_eq!(a.inclusion_assurance, InclusionAssurance::WitnessedNotIndependent);

    // Assessed independent: witnessed.
    let a = reconcile(&core(&honest, Some(&twin), true, false), &signed, true, "indep").await;
    assert_eq!(a.reconciliation, ExecutionReconciliation::ApprovedAndExecuted);
    assert_eq!(a.inclusion_assurance, InclusionAssurance::Witnessed);

    // The label reaches the wire, and a record without it reads back as the
    // weakest claim.
    let json = serde_json::to_value(&a).unwrap();
    assert_eq!(json["inclusion_assurance"], "witnessed");
    let mut old = json.clone();
    old.as_object_mut().unwrap().remove("inclusion_assurance");
    let back: ExecutionAudit = serde_json::from_value(old).unwrap();
    assert_eq!(back.inclusion_assurance, InclusionAssurance::SingleProvider);
}

// ─── high assurance ─────────────────────────────────────────────────────────

#[tokio::test]
async fn high_assurance_states_nothing_about_the_chain_on_one_providers_word() {
    let signed = signed_by(&key(0x42));
    let honest = cluster(serving(signed.clone(), 777));
    let twin = cluster(serving(signed.clone(), 777));

    // Single provider: executed, but not stated.
    let a = reconcile(&core(&honest, None, false, true), &signed, true, "ha-single").await;
    let why = unavailable(&a.reconciliation);
    assert!(why.contains("high-assurance") && why.contains("single_provider"), "{why}");
    assert!(why.contains("ApprovedAndExecuted"), "the withheld answer is named: {why}");

    // A witness that is not independent is not enough.
    let a = reconcile(&core(&honest, Some(&twin), false, true), &signed, true, "ha-twin").await;
    assert!(unavailable(&a.reconciliation).contains("witnessed_not_independent"));

    // An independent witness that agrees: the conclusion stands.
    let a = reconcile(&core(&honest, Some(&twin), true, true), &signed, true, "ha-ok").await;
    assert_eq!(a.reconciliation, ExecutionReconciliation::ApprovedAndExecuted);
    assert_eq!(a.inclusion_assurance, InclusionAssurance::Witnessed);

    // The negative statements need it too: "the blocked transaction did not
    // land" and "the approved one is not there" on one provider's word are
    // exactly what a censoring primary would say.
    let empty = cluster(knows_nothing());
    for approved in [false, true] {
        let a = reconcile(&core(&empty, None, false, true), &signed, approved, "ha-neg").await;
        assert!(
            unavailable(&a.reconciliation).contains("single_provider"),
            "approved={approved}"
        );
        // Off, the same answers are what they were.
        let a = reconcile(&core(&empty, None, false, false), &signed, approved, "neg").await;
        assert_eq!(
            a.reconciliation,
            if approved {
                ExecutionReconciliation::NotFound
            } else {
                ExecutionReconciliation::BlockedAndNotExecuted
            }
        );
    }
    let empty_twin = cluster(knows_nothing());
    let a = reconcile(&core(&empty, Some(&empty_twin), true, true), &signed, false, "ha-neg-ok").await;
    assert_eq!(a.reconciliation, ExecutionReconciliation::BlockedAndNotExecuted);
}

#[tokio::test]
async fn high_assurance_never_withholds_the_alarm() {
    let signed = signed_by(&key(0x42));
    // The primary saw the blocked transaction; no witness at all.
    let honest = cluster(serving(signed.clone(), 777));
    let a = reconcile(&core(&honest, None, false, true), &signed, false, "alarm-primary").await;
    assert_eq!(a.reconciliation, ExecutionReconciliation::BlockedButExecuted);
    assert!(a.reconciliation.is_discrepancy());

    // The primary censors it; a witness — even one that is not independent —
    // saw it. One sighting is the alarm.
    let censor = cluster(knows_nothing());
    let saw = cluster(serving(signed.clone(), 777));
    for independent in [false, true] {
        let a = reconcile(&core(&censor, Some(&saw), independent, true), &signed, false, "alarm-witness").await;
        assert_eq!(
            a.reconciliation,
            ExecutionReconciliation::BlockedButExecuted,
            "independent={independent}"
        );
        assert_eq!(a.inclusion_assurance, InclusionAssurance::WitnessDisputed);
    }
}

// ─── ways to be wrong ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_witness_that_lags_lies_or_redirects_leaves_no_positive_conclusion() {
    let signed = signed_by(&key(0x42));
    let honest = cluster(serving(signed.clone(), 777));

    // Lags: no record yet.
    let lagging = cluster(knows_nothing());
    // Lies about the slot.
    let liar = cluster(serving(signed.clone(), 778));
    // Redirects somewhere else (not followed).
    let redirect = cluster(Arc::new(|_| "REDIRECT http://127.0.0.1:9/".to_string()));

    for (name, witness, label) in [
        ("lagging", &lagging, InclusionAssurance::WitnessDisputed),
        ("lying", &liar, InclusionAssurance::WitnessDisputed),
        ("redirecting", &redirect, InclusionAssurance::WitnessUnavailable),
    ] {
        for high in [false, true] {
            let a = reconcile(&core(&honest, Some(witness), true, high), &signed, true, name).await;
            assert!(
                matches!(a.reconciliation, ExecutionReconciliation::Unavailable { .. }),
                "{name} high={high}: {:?}",
                a.reconciliation
            );
            assert_eq!(a.inclusion_assurance, label, "{name}");
        }
    }
}

#[tokio::test]
async fn a_primary_serving_bytes_signed_by_another_key_concludes_nothing() {
    let signed = signed_by(&key(0x42));
    // Same message shape, another fee payer, a valid signature under THAT
    // key, served under the real signature's status.
    let other = signed_by(&key(0x07));
    let substituted = {
        let mut b = other.clone();
        // Keep the requested signature in slot one so the first-slot check
        // passes and the ed25519 check is what refuses it.
        b[1..65].copy_from_slice(&signed[1..65]);
        b
    };
    for (name, bytes) in [("other-key", other), ("slot-kept", substituted)] {
        let primary = cluster(serving(bytes, 777));
        for high in [false, true] {
            let a = reconcile(&core(&primary, None, false, high), &signed, true, name).await;
            assert!(a.chain_bytes_rejected.is_some(), "{name}");
            assert!(
                matches!(a.reconciliation, ExecutionReconciliation::Unavailable { .. }),
                "{name}: {:?}",
                a.reconciliation
            );
            assert_eq!(a.chain_transaction_sha256, None, "{name}");
        }
    }
}

#[tokio::test]
async fn padded_signature_slots_are_not_the_transaction() {
    let signed = signed_by(&key(0x42));
    // Declare two signatures for a message that requires one, the second
    // slot zero: the runtime refuses such a frame, and so does the binding.
    let mut padded = vec![2u8];
    padded.extend_from_slice(&signed[1..65]);
    padded.extend_from_slice(&[0u8; 64]);
    padded.extend_from_slice(&signed[65..]);
    let primary = cluster(serving(padded, 777));
    let a = reconcile(&core(&primary, None, false, false), &signed, true, "padded").await;
    assert!(a.chain_bytes_rejected.is_some());
    assert!(matches!(a.reconciliation, ExecutionReconciliation::Unavailable { .. }));
}

// ─── independence ───────────────────────────────────────────────────────────

#[test]
fn a_witness_on_the_same_host_or_domain_is_not_independent() {
    for (p, w) in [
        ("https://rpc.example.com/a", "https://rpc.example.com/b"),
        ("https://rpc.example.com", "https://RPC.EXAMPLE.COM."),
        ("https://mainnet.helius-rpc.com/?api-key=a", "https://eu.helius-rpc.com/?api-key=b"),
        ("https://a.rpc.co.uk", "https://b.rpc.co.uk"),
        ("http://127.0.0.1:8899", "http://localhost:8900"),
        ("http://[::1]:8899", "http://127.0.0.2:8899"),
        ("https://203.0.113.5", "https://[::ffff:203.0.113.5]:8443"),
        ("not a url", "https://b.example"),
    ] {
        assert!(
            !witness_independence(p, w).is_distinct(),
            "{p} / {w} judged independent"
        );
    }
    for (p, w) in [
        ("https://mainnet.helius-rpc.com", "https://api.triton.one"),
        ("https://a.co.uk", "https://b.co.uk"),
        ("https://203.0.113.5", "https://198.51.100.7"),
    ] {
        assert_eq!(witness_independence(p, w), WitnessIndependence::Distinct, "{p} / {w}");
    }
}

/// The same provider under a second API key is the same endpoint: refused
/// as a witness whichever is attached first. Two local processes on two
/// ports remain attachable (and are labelled one machine's view).
#[test]
fn the_same_provider_under_a_second_key_is_not_a_witness() {
    for (p, w) in [
        ("https://rpc.example.com/?api-key=A", "https://rpc.example.com/?api-key=B"),
        ("https://rpc.example.com/v1/A", "https://RPC.example.com:443/v2/B"),
        ("https://user:a@rpc.example.com", "https://user:b@rpc.example.com:8443/"),
    ] {
        let mut core = GraphiteCore::new();
        core.attach_rpc_client(client(p));
        assert!(core.attach_inclusion_witness(client(w)).is_err(), "{p} / {w}");

        let mut core = GraphiteCore::new();
        core.attach_inclusion_witness(client(w)).unwrap();
        assert!(core.try_attach_rpc_client(client(p)).is_err(), "{p} / {w}");
        core.attach_rpc_client(client(p));
        assert!(!core.has_inclusion_witness(), "detached: {p} / {w}");
    }
    let mut core = GraphiteCore::new();
    core.attach_rpc_client(client("http://127.0.0.1:8899"));
    core.attach_inclusion_witness(client("http://127.0.0.1:8900")).unwrap();
    assert!(!core.witness_independence().unwrap().is_distinct());
}

#[tokio::test]
async fn hosts_resolving_to_one_address_are_not_independent() {
    // `localhost` resolves to loopback; the URL check already says one
    // machine. Two different literals, one address: the resolved check
    // agrees with the URL check and never upgrades it.
    let r = graphite_core::rpc_client::witness_independence_resolved(
        "http://localhost:8899",
        "http://127.0.0.1:8900",
    )
    .await
    .unwrap();
    assert!(!r.is_distinct());
    // A host that does not resolve is an error, never a pass.
    let r = graphite_core::rpc_client::witness_independence_resolved(
        "https://198.51.100.7",
        "https://does-not-exist.invalid",
    )
    .await;
    assert!(r.is_err(), "{r:?}");
}

// ─── URL policy ─────────────────────────────────────────────────────────────

#[test]
fn metadata_link_local_and_unroutable_hosts_are_refused() {
    for endpoint in [
        "http://169.254.169.254/latest/meta-data",
        "http://[fe80::1]:8899",
        "http://[::ffff:169.254.169.254]/",
        "http://[fd00:ec2::254]/",
        "http://100.100.100.200/",
        "http://0.0.0.0:8899",
        "http://[::]:8899",
        "http://224.0.0.1/",
        "http://255.255.255.255/",
    ] {
        assert!(
            matches!(validate_endpoint(endpoint), Err(EndpointError::ForbiddenAddress(_))),
            "{endpoint}"
        );
        let err = validate_endpoint(endpoint).unwrap_err().to_string();
        assert!(!err.contains("169.254") && !err.contains("fe80"), "the address is not echoed: {err}");
    }
    for (endpoint, private) in [
        ("http://10.0.0.5:8899", true),
        ("http://192.168.1.2:8899", true),
        ("http://172.16.0.9:8899", true),
        ("http://100.64.0.1:8899", true),
        ("http://[fd12:3456::1]:8899", true),
        ("https://203.0.113.5", false),
        ("https://rpc.example.com", false),
        ("http://127.0.0.1:8899", false),
    ] {
        assert_eq!(validate_endpoint(endpoint).unwrap().private_network, private, "{endpoint}");
    }
}

/// A host NAME is judged when it resolves: the resolver every RPC client
/// connects through drops forbidden addresses and refuses a name that has
/// nothing else, and a loopback name still connects.
#[tokio::test]
async fn a_name_is_judged_when_it_resolves() {
    use reqwest::dns::Resolve;
    use std::str::FromStr;
    let resolver = graphite_core::rpc_client::GuardedResolver;
    for name in ["169.254.169.254", "0.0.0.0", "fe80::1"] {
        let r = resolver
            .resolve(reqwest::dns::Name::from_str(name).unwrap())
            .await;
        let err = r.err().unwrap_or_else(|| panic!("{name} resolved")).to_string();
        assert!(err.contains("refused"), "{name}: {err}");
    }
    let addrs: Vec<_> = resolver
        .resolve(reqwest::dns::Name::from_str("localhost").unwrap())
        .await
        .expect("localhost resolves")
        .collect();
    assert!(addrs.iter().all(|a| a.ip().is_loopback()) && !addrs.is_empty());

    let signed = signed_by(&key(0x42));
    let endpoint = cluster(serving(signed.clone(), 777)).replace("127.0.0.1", "localhost");
    let a = reconcile(&core(&endpoint, None, false, false), &signed, true, "by-name").await;
    assert_eq!(
        a.reconciliation,
        ExecutionReconciliation::ApprovedAndExecuted,
        "a loopback name connects through the guarded resolver"
    );
}
