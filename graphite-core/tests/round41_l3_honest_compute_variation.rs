//! Round 41 — L3 refused honest System transfers as `SimulationSpoofing`.
//!
//! Live mainnet run 41120603876 (2026-10-30): a Core with the census imported
//! and no typed baseline learned its L3 baseline from its own clean verdicts,
//! then refused honest 1-lamport transfers ONLY at L3 ("divergence from the
//! shape baseline", "Compute usage diverges from baseline (flagged at
//! >2.0σ)"), with L4 reporting the state diff verified.
//!
//! Cause: the shape key leaves the Compute Budget program out on purpose ("so
//! a priority fee does not split a shape"), but the figure L3 judges is the
//! whole transaction's compute, and every Compute Budget instruction costs
//! 150 CU. A System transfer is 150 CU, so honest transfers of ONE shape cost
//! 150, 300 or 450 CU by whether the wallet set no priority fee, a price, or
//! a limit and a price. The spread floor was relative (25% of the centre)
//! with an absolute floor of 1 — meant for writes and hops — so a baseline
//! learned from limit+price transfers (450 CU) judged a bare transfer
//! (150 CU) at 2.67σ, and one learned from bare transfers judged a
//! limit+price transfer (450 CU) at 8σ.
//!
//! The fix: compute's spread has an absolute floor of one Compute Budget
//! instruction (`MIN_COMPUTE_UNITS_SPREAD`, 150 CU), by the rule
//! `MIN_ABSOLUTE_SPREAD` already applies to writes and hops: one unit of
//! honest variation the baseline cannot see is a 1σ event. A priority fee's
//! two instructions added or removed stay within the 2σ band; three or more,
//! a tenfold figure, or a drift past the anchor are still refused — the
//! attack controls below. The relative floor still governs every centre
//! above 600 CU.
//!
//! The pure tests run in every leg; the pipeline tests need an RPC (`rpc`).

use graphite_core::simulation_integrity::{
    check_simulation_integrity, update_baseline, ComputeBaseline, ComputeUsage,
    SimulationIntegrityInput, SimulationIntegrityResult, COMPUTE_BUDGET_INSTRUCTION_UNITS,
    DIVERGENCE_THRESHOLD, MIN_COMPUTE_UNITS_SPREAD, MIN_RELATIVE_SPREAD, MIN_SAMPLES,
};

/// A System transfer's own compute.
const TRANSFER_UNITS: u64 = 150;

/// The most Compute Budget instructions a transaction that executes carries:
/// one each of heap frame, unit limit, unit price and loaded-data limit (the
/// runtime refuses a repeated one).
const MOST_COMPUTE_BUDGET_INSTRUCTIONS: u64 = 4;

/// What an honest transfer with `cb` Compute Budget instructions costs.
fn transfer_units(cb: u64) -> u64 {
    TRANSFER_UNITS + COMPUTE_BUDGET_INSTRUCTION_UNITS * cb
}

/// The half-width of a cheap program's band at the pipeline's threshold.
fn band() -> u64 {
    (DIVERGENCE_THRESHOLD * MIN_COMPUTE_UNITS_SPREAD) as u64
}

/// The half-width of the band of a uniform history at `centre`: the larger
/// of the two floors, at the threshold.
fn band_at(centre: u64) -> u64 {
    (DIVERGENCE_THRESHOLD * MIN_COMPUTE_UNITS_SPREAD.max(centre as f64 * MIN_RELATIVE_SPREAD))
        as u64
}

fn usage(cu: u64) -> ComputeUsage {
    ComputeUsage {
        compute_units: cu,
        account_writes: 2,
        cpi_hops: 0,
    }
}

fn judge(baseline: &ComputeBaseline, cu: u64) -> SimulationIntegrityResult {
    check_simulation_integrity(&SimulationIntegrityInput {
        program_id: "11111111111111111111111111111111".to_string(),
        simulation_usage: usage(cu),
        baseline: baseline.clone(),
        divergence_threshold: DIVERGENCE_THRESHOLD,
    })
    .expect("a mature, finite baseline judges")
}

/// A baseline learned, as the pipeline learns one, from `units` in order.
fn learned(units: &[u64]) -> ComputeBaseline {
    let mut b = ComputeBaseline::default();
    for &u in units {
        update_baseline(&mut b, u, 2, 0);
    }
    b
}

fn of_counts(counts: &[u64]) -> Vec<u64> {
    counts.iter().map(|&cb| transfer_units(cb)).collect()
}

/// The reproduction: ten honest transfers that all carry two Compute Budget
/// instructions (limit and price: 450 CU) mature the baseline, and the next
/// honest transfer, which carries none (150 CU), was flagged at 2.67σ.
#[test]
fn a_transfer_without_compute_budget_instructions_after_ten_with_two_is_not_spoofing() {
    let baseline = learned(&[transfer_units(2); MIN_SAMPLES as usize]);
    assert_eq!(baseline.sample_count, MIN_SAMPLES);
    let r = judge(&baseline, transfer_units(0));
    assert!(
        !r.flagged,
        "an honest 0-instruction transfer flagged against a 2-instruction baseline: {:?}",
        r.reason
    );
}

/// The other direction: a baseline learned from bare transfers (150 CU)
/// flagged the first transfer with a priority fee (300 or 450 CU) at 4σ / 8σ.
#[test]
fn a_transfer_with_a_priority_fee_after_ten_without_is_not_spoofing() {
    let baseline = learned(&[transfer_units(0); MIN_SAMPLES as usize]);
    for cb in 1..=2 {
        let r = judge(&baseline, transfer_units(cb));
        assert!(
            !r.flagged,
            "an honest {cb}-instruction transfer flagged against a bare-transfer baseline: {:?}",
            r.reason
        );
    }
}

/// Every honest history a shape can learn — uniform at any Compute Budget
/// count the runtime accepts, or mixed, in the order a run of real senders
/// gives them, matured and well past maturity — judges consistent every
/// transfer within two Compute Budget instructions of all its samples.
#[test]
fn every_history_accepts_a_priority_fee_added_or_removed() {
    let mut cases: Vec<(Vec<u64>, std::ops::RangeInclusive<u64>)> = Vec::new();
    for h in 0..=MOST_COMPUTE_BUDGET_INSTRUCTIONS {
        cases.push((
            vec![h; MIN_SAMPLES as usize],
            h.saturating_sub(2)..=(h + 2).min(MOST_COMPUTE_BUDGET_INSTRUCTIONS),
        ));
    }
    // Mostly limit+price, some price-only, some bare.
    cases.push((vec![2, 2, 1, 2, 2, 0, 2, 2, 1, 2], 0..=2));
    cases.push((vec![0, 0, 0, 0, 0, 0, 0, 2, 2, 2], 0..=2));
    // A long run cycling through every count of one window of three.
    for lo in 0..=2 {
        cases.push(((0..300).map(|i| lo + i % 3).collect(), lo..=lo + 2));
    }
    cases.push(((0..300).map(|i| 2 * (i % 2)).collect(), 0..=2));
    for (counts, accepted) in &cases {
        let baseline = learned(&of_counts(counts));
        for cb in accepted.clone() {
            let r = judge(&baseline, transfer_units(cb));
            assert!(
                !r.flagged,
                "{cb} Compute Budget instruction(s) flagged after counts {counts:?}: {:?}",
                r.reason
            );
        }
    }
}

/// The floor is one Compute Budget instruction, by the runtime's price for
/// one, and at the pipeline's threshold the band is a priority fee's two.
#[test]
fn the_compute_floor_is_one_compute_budget_instruction() {
    assert_eq!(COMPUTE_BUDGET_INSTRUCTION_UNITS, 150);
    assert_eq!(MIN_COMPUTE_UNITS_SPREAD, 150.0);
    assert_eq!(DIVERGENCE_THRESHOLD, 2.0);
    assert_eq!(band(), 2 * COMPUTE_BUDGET_INSTRUCTION_UNITS);
}

// ─── Attack controls ───────────────────────────────────────────────────────

/// A simulation ten times a mature baseline's compute is still flagged, and so
/// is one a single unit past the band, above or below — at every centre an
/// honest transfer can have.
#[test]
fn a_gross_divergence_from_a_mature_baseline_is_still_flagged() {
    for cb in 0..=MOST_COMPUTE_BUDGET_INSTRUCTIONS {
        let centre = transfer_units(cb);
        let baseline = learned(&[centre; MIN_SAMPLES as usize]);
        let r = judge(&baseline, centre * 10);
        assert!(r.flagged, "10x of {centre} CU passed");
        assert!(
            r.reason.as_deref().unwrap_or("").contains("Compute usage"),
            "{:?}",
            r.reason
        );
        // The band's edge, exactly, and one unit past it.
        let half = band_at(centre);
        assert!(half >= band());
        let edge = centre + half;
        assert!(!judge(&baseline, edge).flagged, "the edge of {centre}");
        assert!(
            judge(&baseline, edge + 1).flagged,
            "one unit past the band of {centre} CU passed"
        );
        if centre > half {
            assert!(!judge(&baseline, centre - half).flagged);
            assert!(
                judge(&baseline, centre - half - 1).flagged,
                "one unit below the band of {centre} CU passed"
            );
        }
    }
    // Three instructions more than a uniform history is past the band.
    let bare = learned(&[transfer_units(0); MIN_SAMPLES as usize]);
    assert!(judge(&bare, transfer_units(3)).flagged);
}

/// Above 600 CU the relative floor is the larger, so a real program's band
/// is exactly what it was: centred on 100,000 CU, flagged above 150,000.
#[test]
fn a_real_programs_band_is_unchanged() {
    let baseline = learned(&[100_000; MIN_SAMPLES as usize]);
    assert!(!judge(&baseline, 150_000).flagged);
    assert!(judge(&baseline, 150_001).flagged);
    assert!(!judge(&baseline, 50_000).flagged);
    assert!(judge(&baseline, 49_999).flagged);
    // An SPL Token transfer's centre: the relative floor already governs.
    let token = learned(&[4_645; MIN_SAMPLES as usize]);
    assert!(judge(&token, 4_645 * 10).flagged);
    // And at the crossover the two floors agree.
    let at = learned(&[600; MIN_SAMPLES as usize]);
    assert!(!judge(&at, 900).flagged);
    assert!(judge(&at, 901).flagged);
}

/// A patient attacker feeds observation after observation at the top of the
/// band, each accepted and learned, to walk a 450 CU baseline upward. The
/// anchor fixed at maturity holds: after 3,000 steps nothing past the band it
/// was first judged by passes, and a 10x simulation is still refused.
#[test]
fn a_slow_drift_cannot_walk_the_band_past_its_anchor() {
    let centre = transfer_units(2);
    let mut baseline = learned(&[centre; MIN_SAMPLES as usize]);
    let anchor_edge = centre + band();
    for step in 0..3_000 {
        // The largest value the baseline accepts now.
        let mut top = centre;
        let mut probe = 20_000u64;
        while probe > 0 {
            if !judge(&baseline, top + probe).flagged {
                top += probe;
            } else {
                probe /= 2;
            }
        }
        assert!(
            top <= anchor_edge,
            "step {step}: the band reached {top} CU, past the anchored {anchor_edge}"
        );
        update_baseline(&mut baseline, top, 2, 0);
    }
    assert!(judge(&baseline, anchor_edge + 1).flagged);
    assert!(judge(&baseline, centre * 10).flagged);
}

/// A baseline anchored before Round 41 carries a spread computed without the
/// compute floor (450 CU: 112.5). Its anchor is judged with the floor as well,
/// so a data dir written by an older build stops refusing honest transfers —
/// and the anchor still refuses a gross divergence.
#[test]
fn an_anchor_written_before_the_floor_is_judged_with_it() {
    let mut baseline = learned(&[transfer_units(2); MIN_SAMPLES as usize]);
    let anchor = baseline.anchor.as_mut().expect("anchored at maturity");
    assert_eq!(anchor.compute_units_spread, MIN_COMPUTE_UNITS_SPREAD);
    anchor.compute_units_spread = 112.5;
    let r = judge(&baseline, transfer_units(0));
    assert!(!r.flagged, "{:?}", r.reason);
    let r = judge(&baseline, transfer_units(2) * 10);
    assert!(r.flagged);
}

// ─── The pipeline, as the live runner drives it ─────────────────────────────

#[cfg(feature = "rpc")]
mod pipeline {
    use super::{transfer_units, MIN_SAMPLES};
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::rpc_client::{RpcConfig, SolanaRpcClient};
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::tx_pattern_analysis::TransactionInstruction;
    use graphite_core::verification::{
        ExecutionDecision, ExtractedParameters, GraphiteCore, LayerStatus, ProposedIntent,
        VerificationInput, VerificationResult,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const SYSTEM: &str = "11111111111111111111111111111111";
    const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
    const DESTINATION: &str = "8u8LCMQvMKrFxHbn326Ltcqv72HDPEC5FPMgPC3mXvxV";

    /// The sender of request `seq`: each request comes from its own sender,
    /// as the live runner's do (one transfer per real sender), so each is a
    /// distinct observation.
    fn payer(seq: u64) -> [u8; 32] {
        let mut seed = [0x41u8; 32];
        seed[..8].copy_from_slice(&seq.to_le_bytes());
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
    }

    fn key(b58: &str) -> Vec<u8> {
        bs58::decode(b58).into_vec().unwrap()
    }

    fn transfer_data(lamports: u64) -> Vec<u8> {
        let mut d = vec![2, 0, 0, 0];
        d.extend_from_slice(&lamports.to_le_bytes());
        d
    }

    /// The Compute Budget instructions an honest wallet adds, in the order
    /// wallets add them: limit, price, heap frame, loaded-data limit.
    fn compute_budget_ix(n: u64) -> Vec<Vec<u8>> {
        let mut limit = vec![2u8];
        limit.extend_from_slice(&200_000u32.to_le_bytes());
        let mut price = vec![3u8];
        price.extend_from_slice(&10_000u64.to_le_bytes());
        let mut heap = vec![1u8];
        heap.extend_from_slice(&(64 * 1024u32).to_le_bytes());
        let mut data_limit = vec![4u8];
        data_limit.extend_from_slice(&(64 * 1024u32).to_le_bytes());
        [limit, price, heap, data_limit]
            .into_iter()
            .take(n as usize)
            .collect()
    }

    /// What every transfer here moves: the mock cluster's post-state moves
    /// exactly this from the payer to the destination.
    const LAMPORTS: u64 = 1_000_000;

    /// An unsigned legacy transfer from sender `seq` with `cb` Compute Budget
    /// instructions before it — what the live runner builds.
    fn tx(seq: u64, cb: u64) -> Vec<u8> {
        let lamports = LAMPORTS;
        let blockhash = [0x5au8; 32];
        let mut keys = vec![payer(seq).to_vec(), key(DESTINATION), key(SYSTEM)];
        if cb > 0 {
            keys.push(key(COMPUTE_BUDGET));
        }
        let mut m = vec![1u8, 0, (keys.len() - 2) as u8, keys.len() as u8];
        for k in &keys {
            m.extend_from_slice(k);
        }
        m.extend_from_slice(&blockhash);
        let budget = compute_budget_ix(cb);
        m.push((budget.len() + 1) as u8);
        for data in &budget {
            m.extend_from_slice(&[3, 0, data.len() as u8]);
            m.extend_from_slice(data);
        }
        let data = transfer_data(lamports);
        m.extend_from_slice(&[2, 2, 0, 1, data.len() as u8]);
        m.extend_from_slice(&data);
        let mut raw = vec![1u8];
        raw.extend_from_slice(&[0u8; 64]);
        raw.extend_from_slice(&m);
        raw
    }

    fn b64(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    fn account(lamports: u64) -> String {
        format!(
            r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["{}","base64"]}}"#,
            b64(&[])
        )
    }

    fn native_program() -> String {
        format!(
            r#"{{"lamports":1,"owner":"NativeLoader1111111111111111111111111111111","executable":true,"rentEpoch":0,"data":["{}","base64"]}}"#,
            b64(&[0u8; 36])
        )
    }

    /// A mock cluster whose simulation reports `units` (shared, so a test can
    /// set what the next simulation measures).
    fn cluster(units: Arc<Mutex<u64>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body: serde_json::Value = req
                    .split("\r\n\r\n")
                    .nth(1)
                    .and_then(|b| serde_json::from_str(b).ok())
                    .unwrap_or(serde_json::Value::Null);
                let method = body["method"].as_str().unwrap_or("?").to_string();
                let slice = body["params"][1]["dataSlice"]["length"].as_u64();
                let units = *units.lock().unwrap();
                let reply = match method.as_str() {
                    "getMultipleAccounts" if slice == Some(48) => {
                        let vals: Vec<String> = body["params"][0]
                            .as_array()
                            .cloned()
                            .unwrap_or_default()
                            .iter()
                            .map(|a| {
                                if a.as_str() == Some(SYSTEM) || a.as_str() == Some(COMPUTE_BUDGET)
                                {
                                    native_program()
                                } else {
                                    "null".to_string()
                                }
                            })
                            .collect();
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1000}},"value":[{}]}}}}"#,
                            vals.join(",")
                        )
                    }
                    "getMultipleAccounts" => {
                        let count = body["params"][0].as_array().map(|a| a.len()).unwrap_or(0);
                        let vals: Vec<String> = (0..count)
                            .map(|i| account(if i == 0 { 1_000_000_000 } else { 1_000_000 }))
                            .collect();
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1000}},"value":[{}]}}}}"#,
                            vals.join(",")
                        )
                    }
                    "getAccountInfo" => format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1000}},"value":{}}}}}"#,
                        account(1_000_000_000)
                    ),
                    "simulateTransaction" => {
                        let count = body["params"][1]["accounts"]["addresses"]
                            .as_array()
                            .map(|a| a.len())
                            .unwrap_or(0);
                        let post: Vec<String> = (0..count)
                            .map(|i| account(if i == 0 { 998_995_000 } else { 2_000_000 }))
                            .collect();
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1000}},"value":{{
                                "err":null,"logs":[],"unitsConsumed":{units},"fee":5000,
                                "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                                "innerInstructions":[],"loadedAddresses":{{"writable":[],"readonly":[]}},
                                "accounts":[{}],"returnData":null}}}}}}"#,
                            post.join(",")
                        )
                    }
                    _ => r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    /// The live runner's Core: the census imported, no typed L3 baseline, an
    /// RPC attached.
    fn core(units: Arc<Mutex<u64>>) -> GraphiteCore {
        let mut core = GraphiteCore::new();
        graphite_core::census_import::import_embedded_into(&mut core)
            .expect("the embedded census imports");
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: cluster(units),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        assert!(
            core.simulation_baseline(SYSTEM).is_none(),
            "no typed baseline"
        );
        core
    }

    fn describe(seq: u64, cb: u64) -> VerificationInput {
        VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: format!("send 0.001 SOL to {DESTINATION}"),
                confidence_of_parse: 1.0,
                extracted_parameters: Some(ExtractedParameters {
                    amount: Some("0.001".to_string()),
                    destination: Some(DESTINATION.to_string()),
                    input_token: Some("SOL".to_string()),
                    ..Default::default()
                }),
            },
            program_id: SYSTEM.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            account_addresses: vec![
                bs58::encode(payer(seq)).into_string(),
                DESTINATION.to_string(),
            ],
            instruction_data: Some(transfer_data(LAMPORTS)),
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: BehaviorEvidence::default(),
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
            signed_transaction: Some(tx(seq, cb)),
            // The siblings described as the live runner describes them.
            transaction_instructions: compute_budget_ix(cb)
                .iter()
                .map(|data| TransactionInstruction {
                    program_id: COMPUTE_BUDGET.to_string(),
                    instruction_discriminator: hex::encode(&data[..data.len().min(8)]),
                    account_addresses: vec![],
                    cpi_targets: vec![],
                })
                .collect(),
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
            state_diff: None,
        }
    }

    fn l3(r: &VerificationResult) -> &graphite_core::verification::PipelineLayerResult {
        r.layers
            .iter()
            .find(|l| l.layer.starts_with("L3"))
            .expect("L3 is reported")
    }

    fn spoofing(r: &VerificationResult) -> bool {
        r.risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "SimulationSpoofing")
    }

    /// Verify a transfer with `cb` Compute Budget instructions that the
    /// simulator measures at `units`.
    async fn verify(
        core: &GraphiteCore,
        sim: &Arc<Mutex<u64>>,
        seq: u64,
        cb: u64,
        units: u64,
    ) -> VerificationResult {
        *sim.lock().unwrap() = units;
        core.verify_async(&describe(seq, cb)).await.unwrap()
    }

    /// Ten honest limit+price transfers teach the baseline; then honest
    /// transfers with a price only or no priority fee at all — the live
    /// run's refusals — are executable, judged by the shape's baseline and
    /// the program's, and so is a limit+price one again.
    #[tokio::test]
    async fn honest_transfers_with_another_compute_budget_count_are_executable() {
        let sim = Arc::new(Mutex::new(0));
        let core = core(Arc::clone(&sim));
        for i in 0..MIN_SAMPLES {
            let r = verify(&core, &sim, 1_000_000 + i, 2, transfer_units(2)).await;
            assert_eq!(
                r.decision,
                ExecutionDecision::ExecutableApproved,
                "bootstrap {i}: {}",
                r.summary
            );
        }
        let shapes = core.shape_baselines(SYSTEM);
        assert_eq!(shapes.len(), 1, "one shape, whatever the budget");
        assert_eq!(shapes[0].1.sample_count, MIN_SAMPLES, "the shape is mature");
        for (n, cb) in [0u64, 1, 2, 0, 1, 0, 2].into_iter().enumerate() {
            let r = verify(&core, &sim, 2_000_000 + n as u64, cb, transfer_units(cb)).await;
            assert!(
                !spoofing(&r),
                "{cb} Compute Budget instruction(s): {:?} / {}",
                r.risk_verdict.findings,
                l3(&r).reason
            );
            assert_eq!(l3(&r).status, LayerStatus::Passed, "{}", l3(&r).reason);
            assert_eq!(
                r.decision,
                ExecutionDecision::ExecutableApproved,
                "{cb}: {}",
                r.summary
            );
        }
    }

    /// The attack control, through the pipeline: after the same training, a
    /// transfer whose simulation reports ten times the compute — and one that
    /// reports just past the band — is refused as spoofing, and never
    /// executable, and teaches the baseline nothing.
    #[tokio::test]
    async fn a_divergent_simulation_is_still_refused() {
        let sim = Arc::new(Mutex::new(0));
        let core = core(Arc::clone(&sim));
        for i in 0..MIN_SAMPLES {
            let r = verify(&core, &sim, 3_000_000 + i, 2, transfer_units(2)).await;
            assert_eq!(
                r.decision,
                ExecutionDecision::ExecutableApproved,
                "{}",
                r.summary
            );
        }
        let before = core.simulation_baseline(SYSTEM).unwrap().sample_count;
        for (n, units) in [transfer_units(2) * 10, transfer_units(2) + 301, 1_400_000]
            .into_iter()
            .enumerate()
        {
            let r = verify(&core, &sim, 4_000_000 + n as u64, 2, units).await;
            assert!(spoofing(&r), "{units} CU: {:?}", r.risk_verdict.findings);
            assert_ne!(l3(&r).status, LayerStatus::Passed, "{}", l3(&r).reason);
            assert_ne!(
                r.decision,
                ExecutionDecision::ExecutableApproved,
                "{units} CU"
            );
            assert!(!r.executable);
        }
        assert_eq!(
            core.simulation_baseline(SYSTEM).unwrap().sample_count,
            before,
            "a flagged observation is never learned"
        );
    }
}
