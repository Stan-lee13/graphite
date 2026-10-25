//! Round 35: inner instructions as Agave's `simulateTransaction` reports them.
//!
//! Agave never answers the compiled form (`programIdIndex`, account indexes):
//! every inner instruction goes through `parse_ui_instruction`, which prints a
//! System, SPL Token, Token-2022 or ATA instruction as `{program, programId,
//! parsed, stackHeight}` and anything else as `{programId, accounts:
//! [<address>…], data, stackHeight}`. Graphite read only the compiled form, so
//! on a real RPC every transaction that made a CPI was refused as incomplete
//! ("the simulator's report of the programs this transaction called could not
//! be read"): 23 of the 200 transactions the first live mainnet run on
//! Round 34's code replayed.
//!
//! - The fixture is Agave's own output for every type `parsed_inner`
//!   rebuilds, written by `tools/inner-instruction-oracle`, which checks each
//!   rebuild against Agave's parser. Here each must rebuild to the bytes the
//!   oracle recorded.
//! - Through the RPC client, the same instruction reported compiled, parsed
//!   and partially decoded resolves to one observed instruction.
//! - End to end through `verify_async` against a loopback mock RPC that
//!   answers as Agave does: the CPI-trace rules see a sweep reported in
//!   parsed form, the gate no longer refuses a parsed report as unreadable,
//!   and a parsed instruction that is not rebuilt still leaves the verdict
//!   incomplete.

use graphite_core::parsed_inner::rebuild;

#[test]
fn every_agave_fixture_rebuilds_to_its_bytes() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/agave_parsed_inner_instructions.json"
    ))
    .expect("fixture");
    let entries = fixture.as_array().expect("array");
    let mut types = std::collections::BTreeSet::new();
    for e in entries {
        let inner = &e["inner"];
        let program = inner["programId"].as_str().unwrap();
        let (accounts, data) =
            rebuild(program, &inner["parsed"]).unwrap_or_else(|| panic!("not rebuilt: {inner}"));
        let want_accounts: Vec<String> = serde_json::from_value(e["accounts"].clone()).unwrap();
        let want_data: Vec<u8> = serde_json::from_value(e["data"].clone()).unwrap();
        assert_eq!(accounts, want_accounts, "{inner}");
        assert_eq!(data, want_data, "{inner}");
        types.insert((
            program.to_string(),
            inner["parsed"]["type"].as_str().unwrap().to_string(),
        ));
    }
    // 12 System, 31 on each token program, 3 ATA.
    assert_eq!(types.len(), 77, "{types:?}");
}

#[cfg(feature = "rpc")]
mod rpc {
    use graphite_core::confidence_engine::TrustTier;
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::rpc_client::{
        simulation_result_from_value_for_test, ObservedInnerInstruction, RpcConfig, SolanaRpcClient,
    };
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{
        ExecutionDecision, GraphiteCore, ProposedIntent, VerificationInput, VerificationResult,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const SYSTEM: &str = "11111111111111111111111111111111";
    const A: &str = "4cvyjjocbsVgYLsJGsy1UmVZHi4XYtagv38zezydqzSx";
    const B: &str = "8HBQFrsUGdm5PmwbBLKt4re6AHaDuv7aVFqzArj2hHtk";

    fn transfer_data(lamports: u64) -> Vec<u8> {
        let mut d = vec![2, 0, 0, 0];
        d.extend_from_slice(&lamports.to_le_bytes());
        d
    }

    fn simulation(inner: serde_json::Value) -> graphite_core::rpc_client::SimulationResult {
        simulation_result_from_value_for_test(&serde_json::json!({
            "err": null, "logs": [], "unitsConsumed": 1000,
            "preBalances": [1, 2, 1], "postBalances": [1, 2, 1],
            "innerInstructions": [{"index": 0, "instructions": inner}],
            "loadedAddresses": {"writable": [], "readonly": []}
        }))
        .unwrap()
    }

    /// One System transfer A → B of 7 lamports, in each form an RPC can send.
    #[test]
    fn compiled_parsed_and_partially_decoded_resolve_to_one_instruction() {
        let keys = vec![A.to_string(), B.to_string(), SYSTEM.to_string()];
        let want = ObservedInnerInstruction {
            top_level_index: 0,
            program_id_index: 2,
            accounts: vec![0, 1],
            data: transfer_data(7),
            stack_height: Some(2),
        };
        let data58 = bs58::encode(transfer_data(7)).into_string();
        for inner in [
            serde_json::json!([{"programIdIndex": 2, "accounts": [0, 1], "data": data58, "stackHeight": 2}]),
            serde_json::json!([{"program": "system", "programId": SYSTEM, "stackHeight": 2,
                "parsed": {"type": "transfer", "info": {"source": A, "destination": B, "lamports": 7}}}]),
            serde_json::json!([{"programId": SYSTEM, "accounts": [A, B], "data": data58, "stackHeight": 2}]),
        ] {
            let mut sim = simulation(inner.clone());
            sim.resolve_reported_inner(&keys);
            assert_eq!(sim.inner_program_indexes, Some(vec![2]), "{inner}");
            assert_eq!(sim.inner_instructions, Some(vec![want.clone()]), "{inner}");
        }
    }

    /// An address that is not one of the transaction's accounts: the callee
    /// set is unknown, never shorter.
    #[test]
    fn an_address_outside_the_transaction_leaves_the_report_unknown() {
        let keys = vec![A.to_string(), B.to_string()];
        let mut sim = simulation(
            serde_json::json!([{"program": "system", "programId": SYSTEM,
            "parsed": {"type": "transfer", "info": {"source": A, "destination": B, "lamports": 7}},
            "stackHeight": 2}]),
        );
        sim.resolve_reported_inner(&keys);
        assert_eq!(sim.inner_program_indexes, None);
        assert_eq!(sim.inner_instructions, None);
        // An entry in no form at all makes the whole report unknown.
        let sim = simulation(serde_json::json!([{"programId": SYSTEM, "stackHeight": 2}]));
        assert!(sim.inner_reported.is_none());
    }

    // ── end to end, against a mock RPC that answers as Agave does ──────────

    fn corpus_entry(name: &str) -> serde_json::Value {
        let raw: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/artifacts/sak_bridge_corpus.json"))
                .expect("corpus must parse");
        raw["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .unwrap()
            .clone()
    }

    fn strings(v: &serde_json::Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    }

    fn bytes(v: &serde_json::Value) -> Vec<u8> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u8)
            .collect()
    }

    fn account(lamports: u64) -> String {
        format!(
            r#"{{"lamports":{lamports},"owner":"{SYSTEM}","executable":false,"rentEpoch":0,"data":["","base64"]}}"#
        )
    }

    /// A loopback cluster whose `simulateTransaction` reports `inner`.
    fn cluster(inner: Arc<Mutex<String>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body_json: serde_json::Value = req
                    .split("\r\n\r\n")
                    .nth(1)
                    .and_then(|b| serde_json::from_str(b).ok())
                    .unwrap_or(serde_json::Value::Null);
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
                            .map(|i| account(if i == 0 { 998_995_000 } else { 2_000_000 }))
                            .collect();
                        let inner = inner.lock().unwrap().clone();
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{
                                "err":null,"logs":[],"unitsConsumed":150,"fee":5000,
                                "preBalances":[1000000000,1000000,1],"postBalances":[998995000,2000000,1],
                                "innerInstructions":{inner},"loadedAddresses":{{"writable":[],"readonly":[]}},
                                "accounts":[{}],"returnData":null}}}}}}"#,
                            post.join(",")
                        )
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

    fn core_at(endpoint: &str) -> GraphiteCore {
        let mut core = GraphiteCore::new();
        core.attach_rpc_client(SolanaRpcClient::new(RpcConfig {
            endpoint: endpoint.to_string(),
            timeout: std::time::Duration::from_secs(5),
            max_retries: 0,
            ..Default::default()
        }));
        core
    }

    /// The corpus's legacy transfer of 2,000,000 lamports, described exactly.
    fn input() -> VerificationInput {
        let e = corpus_entry("legacy_single_transfer");
        let keys = strings(&e["static_keys"]);
        VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "send SOL".to_string(),
                confidence_of_parse: 0.95,
                // Round 36 (F-003): what the request states, which the bytes carry.
                extracted_parameters: Some(graphite_core::verification::ExtractedParameters {
                    amount: Some("0.002".to_string()),
                    destination: Some(keys[1].clone()),
                    input_token: Some("SOL".to_string()),
                    ..Default::default()
                }),
            },
            program_id: SYSTEM.to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            account_addresses: vec![keys[0].clone(), keys[1].clone()],
            instruction_data: Some(transfer_data(2_000_000)),
            cpi_targets: vec![],
            // The lowest bar a fresh core's described transfer clears, so a
            // refusal is a gate, never the score (as in the gate's own test).
            wallet_profile: WalletProfile::Custom {
                min_confidence: 0.40,
                min_trust_tier: TrustTier::OfficialManifest,
            },
            behavior_evidence: BehaviorEvidence::default(),
            compute_units: 150,
            account_writes: 2,
            cpi_hops: 0,
            signed_transaction: Some(bytes(&e["raw"])),
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
            state_diff: None,
        }
    }

    async fn verify(inner: &str) -> VerificationResult {
        let state = Arc::new(Mutex::new(inner.to_string()));
        core_at(&cluster(state))
            .verify_async(&input())
            .await
            .unwrap()
    }

    fn says(r: &VerificationResult, text: &str) -> bool {
        r.summary.contains(text)
            || r.layers.iter().any(|l| l.reason.contains(text))
            || r.risk_verdict
                .findings
                .iter()
                .any(|f| f.reason.contains(text))
    }

    const UNREAD: &str =
        "the simulator's report of the programs this transaction called could not be read";

    /// Round 19's sweep (F-19-22), reported in Agave's forms: twelve System
    /// transfers under the primary over twelve distinct account sets — the
    /// six ordered pairs of the transaction's three accounts parsed (Agave's
    /// `transfer`), the six orderings of all three partially decoded (the
    /// form Agave uses for what it does not parse). Before Round 35 neither
    /// form was read, and the verdict was refused only as unreadable; now the
    /// CPI-trace rule sees the sweep and blocks it.
    #[tokio::test]
    async fn a_sweep_reported_in_agave_forms_is_seen_by_the_cpi_trace_rules() {
        let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
        let pairs: [(usize, usize); 6] = [(0, 1), (1, 0), (0, 2), (2, 0), (1, 2), (2, 1)];
        let triples: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        let mut calls: Vec<String> = Vec::new();
        for (s, d) in pairs {
            calls.push(format!(
                r#"{{"program":"system","programId":"{SYSTEM}","stackHeight":2,"parsed":{{"type":"transfer","info":{{"source":"{}","destination":"{}","lamports":1}}}}}}"#,
                keys[s], keys[d]
            ));
        }
        for t in triples {
            calls.push(format!(
                r#"{{"programId":"{SYSTEM}","accounts":["{}","{}","{}"],"data":"{}","stackHeight":2}}"#,
                keys[t[0]],
                keys[t[1]],
                keys[t[2]],
                bs58::encode(transfer_data(1)).into_string()
            ));
        }
        let r = verify(&format!(
            r#"[{{"index":0,"instructions":[{}]}}]"#,
            calls.join(",")
        ))
        .await;
        assert!(!r.approved);
        assert!(!says(&r, UNREAD), "the report was read: {}", r.summary);
        assert!(
            r.risk_verdict
                .findings
                .iter()
                .any(|f| f.reason.starts_with("observed CPI trace:")
                    && f.reason.contains("side by side")),
            "{:?}",
            r.risk_verdict.findings
        );
    }

    /// The gate (audit 2026-10-20, H1) reads a parsed report: the clean
    /// transfer with one parsed inner instruction is approved, where it was
    /// refused as unreadable. Control: the same report with a parsed instruction
    /// Graphite does not rebuild is still incomplete — the callee is known,
    /// the CPI tree is not.
    #[tokio::test]
    async fn the_simulation_gate_reads_a_parsed_report_and_still_refuses_one_it_cannot_rebuild() {
        let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
        let none = verify("[]").await;
        assert_eq!(
            none.decision,
            ExecutionDecision::ExecutableApproved,
            "{}",
            none.summary
        );

        let parsed = format!(
            r#"[{{"index":0,"instructions":[{{"program":"system","programId":"{SYSTEM}","stackHeight":2,"parsed":{{"type":"transfer","info":{{"source":"{}","destination":"{}","lamports":5}}}}}}]}}]"#,
            keys[0], keys[1]
        );
        let r = verify(&parsed).await;
        assert!(!says(&r, UNREAD), "{}", r.summary);
        // Before Round 35: Inconclusive, "could not be read".
        assert_eq!(
            r.decision,
            ExecutionDecision::ExecutableApproved,
            "{}",
            r.summary
        );
        assert!(
            !says(&r, "could not be rebuilt into the CPI tree"),
            "the tree was rebuilt: {}",
            r.summary
        );

        let unrebuilt = format!(
            r#"[{{"index":0,"instructions":[{{"program":"system","programId":"{SYSTEM}","stackHeight":2,"parsed":{{"type":"allocateWithSeed","info":{{"account":"{}","base":"{}","seed":"s","space":1,"owner":"{SYSTEM}"}}}}}}]}}]"#,
            keys[0], keys[1]
        );
        let r = verify(&unrebuilt).await;
        assert!(!r.approved);
        assert_eq!(r.decision, ExecutionDecision::Inconclusive, "{}", r.summary);
        assert!(!says(&r, UNREAD), "the callees are known: {}", r.summary);
        assert!(
            says(&r, "could not be rebuilt into the CPI tree"),
            "{}",
            r.summary
        );
    }

    /// Round 39 (core-identity, §2.3): every class of parsed inner
    /// instruction `parsed_inner` documents as NOT rebuilt leaves the verdict
    /// incomplete and never executable — not only `allocateWithSeed`. Each is
    /// the shape Agave prints for its program, beside the clean transfer the
    /// control above approves.
    #[tokio::test]
    async fn every_documented_unrebuildable_class_stays_inconclusive() {
        const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
        const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
        const STAKE: &str = "Stake11111111111111111111111111111111111111";
        const VOTE: &str = "Vote111111111111111111111111111111111111111";
        const ALT: &str = "AddressLookupTab1e1111111111111111111111111";
        const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
        let keys = strings(&corpus_entry("legacy_single_transfer")["static_keys"]);
        let (k0, k1) = (keys[0].as_str(), keys[1].as_str());
        let cases: Vec<(&str, String)> = vec![
            (
                "memo",
                format!(
                    r#"{{"program":"spl-memo","programId":"{MEMO}","stackHeight":2,"parsed":"hello"}}"#
                ),
            ),
            (
                "assignWithSeed",
                format!(
                    r#"{{"program":"system","programId":"{SYSTEM}","stackHeight":2,"parsed":{{"type":"assignWithSeed","info":{{"account":"{k1}","base":"{k0}","seed":"s","owner":"{SYSTEM}"}}}}}}"#
                ),
            ),
            (
                "transferCheckedWithFee",
                format!(
                    r#"{{"program":"spl-token-2022","programId":"{TOKEN_2022}","stackHeight":2,"parsed":{{"type":"transferCheckedWithFee","info":{{"source":"{k0}","mint":"{k1}","destination":"{k1}","authority":"{k0}","tokenAmount":{{"amount":"1","decimals":0,"uiAmount":1.0,"uiAmountString":"1"}},"feeAmount":{{"amount":"0","decimals":0,"uiAmount":0.0,"uiAmountString":"0"}}}}}}}}"#
                ),
            ),
            (
                "token-2022 extension",
                format!(
                    r#"{{"program":"spl-token-2022","programId":"{TOKEN_2022}","stackHeight":2,"parsed":{{"type":"initializeTransferFeeConfig","info":{{"mint":"{k1}","transferFeeBasisPoints":1,"maximumFee":1}}}}}}"#
                ),
            ),
            (
                "token metadata",
                format!(
                    r#"{{"program":"spl-token-2022","programId":"{TOKEN_2022}","stackHeight":2,"parsed":{{"type":"updateTokenMetadataField","info":{{"metadata":"{k1}","updateAuthority":"{k0}","field":"name","value":"x"}}}}}}"#
                ),
            ),
            (
                "stake",
                format!(
                    r#"{{"program":"stake","programId":"{STAKE}","stackHeight":2,"parsed":{{"type":"deactivate","info":{{"stakeAccount":"{k1}","clockSysvar":"SysvarC1ock11111111111111111111111111111111","stakeAuthority":"{k0}"}}}}}}"#
                ),
            ),
            (
                "vote",
                format!(
                    r#"{{"program":"vote","programId":"{VOTE}","stackHeight":2,"parsed":{{"type":"withdraw","info":{{"voteAccount":"{k1}","destination":"{k0}","withdrawAuthority":"{k0}","lamports":1}}}}}}"#
                ),
            ),
            (
                "lookup table",
                format!(
                    r#"{{"program":"address-lookup-table","programId":"{ALT}","stackHeight":2,"parsed":{{"type":"freezeLookupTable","info":{{"lookupTableAccount":"{k1}","lookupTableAuthority":"{k0}"}}}}}}"#
                ),
            ),
            (
                "loader",
                format!(
                    r#"{{"program":"bpf-upgradeable-loader","programId":"{LOADER}","stackHeight":2,"parsed":{{"type":"setAuthority","info":{{"account":"{k1}","authority":"{k0}","newAuthority":"{k0}"}}}}}}"#
                ),
            ),
        ];
        for (case, ix) in cases {
            let inner = format!(r#"[{{"index":0,"instructions":[{ix}]}}]"#);
            let r = verify(&inner).await;
            assert!(!r.approved, "{case}: approved: {}", r.summary);
            assert!(!r.executable, "{case}");
            assert_eq!(
                r.decision,
                ExecutionDecision::Inconclusive,
                "{case}: {}",
                r.summary
            );
            // The finding names the unrebuilt CPI tree; the warning names the
            // instruction Graphite did not rebuild (a Memo's parsed form has
            // no `type`, so it is named by its program alone).
            assert!(
                says(&r, "could not be rebuilt into the CPI tree")
                    || says(&r, "Graphite does not rebuild to their bytes"),
                "{case}: {}",
                r.summary
            );
        }
    }
}
