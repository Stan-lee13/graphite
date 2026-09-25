//! Round 19: the binding, parser and ownership findings of the four-part
//! audit, each pinned by the behaviour it restores.
//!
//! - F-19-04: a known program's undescribed instruction left every account but
//!   the first out of L4's diff, and its declared effects were prose L4 could
//!   not interpret — so a token debit was a warning.
//! - F-19-05: every account of an unknown program was read-only.
//! - F-19-07: empty `instruction_data` fell back to the caller's label.
//! - F-19-08: a transaction naming one account twice (the runtime's
//!   `AccountLoadedTwice`) parsed, and a lookup could resolve a static key.
//! - F-19-09: PDA seeds past the runtime's limits derived an address.
//! - F-19-11: a community manifest kept a declared tier above
//!   `OfficialManifest`.
//! - F-19-12: the CLI wrote the snapshot without the data directory's lock,
//!   and a corrupt snapshot started fresh.
//! - the durable-nonce and lookup-table hardening that came with them.

use graphite_core::account_resolution::{
    resolve_accounts, AccountResolutionInput, RealAccountMeta,
};
use graphite_core::manifest::{load_seed_manifests, ManifestRegistry};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::solana_types::{find_program_address, Pubkey, SolanaTypeError};
use graphite_core::state_diff::{DeclaredEffects, UNDESCRIBED_INSTRUCTION_EFFECTS};
use graphite_core::tx_artifact::{
    check_durable_nonce, decode_lookup_table, durable_nonce, parse_transaction, resolve_lookups,
    ArtifactParseError, LookupResolveError, NonceAccountState, LOOKUP_TABLE_META_SIZE,
};
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{GraphiteCore, LayerStatus, ProposedIntent, VerificationInput};

const SYSTEM: &str = "11111111111111111111111111111111";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

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

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

fn intent() -> ProposedIntent {
    ProposedIntent {
        intent_type: "memo".to_string(),
        raw_natural_language: "attach a memo".to_string(),
        confidence_of_parse: 0.9,
        extracted_parameters: None,
    }
}

/// The corpus frame with its empty-data memo instruction given the fee payer
/// (index 0) as its one account. The corpus memo takes none, and a request
/// can only describe an instruction that acts on at least one account.
fn memo_takes_the_payer(raw: Vec<u8>) -> Vec<u8> {
    // Instruction list: [count=2] [memo: program 3, 0 accounts, 0 data]
    // [transfer: program 2, accounts [0, 1], 12 bytes].
    let tail = [2u8, 3, 0, 0, 2, 2, 0, 1, 12];
    let pos = raw
        .windows(tail.len())
        .rposition(|w| w == tail)
        .expect("corpus instruction list");
    let mut out = raw[..pos].to_vec();
    out.extend_from_slice(&[2u8, 3, 1, 0, 0, 2, 2, 0, 1, 12]);
    out.extend_from_slice(&raw[pos + tail.len()..]);
    out
}

// ─── F-19-07 ────────────────────────────────────────────────────────────────

/// An artifact whose instruction carries ZERO bytes, described with a
/// non-empty label: the label and the bytes contradict, and L2 says so.
/// Before Round 19 the lookup fell back to the label and the verdict
/// described whatever instruction the label named.
#[test]
fn empty_data_under_a_label_is_a_contradiction() {
    let e = corpus_entry("legacy_empty_data");
    let keys = strings(&e["static_keys"]);
    let mut transfer = vec![2u8, 0, 0, 0];
    transfer.extend_from_slice(&1u64.to_le_bytes());
    let input = VerificationInput {
        proposed_intent: intent(),
        program_id: MEMO.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "0a0b0c0d".to_string(),
        // The memo instruction's one account, as the frame names it.
        account_addresses: vec![keys[0].clone()],
        instruction_data: Some(vec![]),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(memo_takes_the_payer(bytes(&e["raw"]))),
        transaction_instructions: vec![TransactionInstruction {
            program_id: SYSTEM.to_string(),
            instruction_discriminator: hex::encode(&transfer),
            account_addresses: vec![keys[0].clone(), keys[1].clone()],
            cpi_targets: vec![],
        }],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    };
    let r = GraphiteCore::new().verify(&input).unwrap();
    let l2 = r.layers.iter().find(|l| l.layer.starts_with("L2")).unwrap();
    assert_eq!(l2.status, LayerStatus::Failed, "{}", l2.reason);
    assert!(l2.reason.contains("longer than itself"), "{}", l2.reason);
    assert!(!r.approved);
}

// ─── F-19-08 ────────────────────────────────────────────────────────────────

/// The transfer with its destination key overwritten by the fee payer's: a
/// frame sanitize accepts and the bank refuses (`AccountLoadedTwice`).
#[test]
fn a_frame_naming_one_account_twice_is_not_a_transaction() {
    let e = corpus_entry("legacy_single_transfer");
    let raw = bytes(&e["raw"]);
    let keys = strings(&e["static_keys"]);
    let payer = bs58::decode(&keys[0]).into_vec().unwrap();
    let dest = bs58::decode(&keys[1]).into_vec().unwrap();
    let pos = raw
        .windows(32)
        .position(|w| w == dest.as_slice())
        .expect("destination key in frame");
    let mut dup = raw.clone();
    dup[pos..pos + 32].copy_from_slice(&payer);
    match parse_transaction(&dup) {
        Err(ArtifactParseError::DuplicateAccountKey { first, second, .. }) => {
            assert_eq!((first, second), (0, 1));
        }
        other => panic!("expected DuplicateAccountKey, got {other:?}"),
    }
    assert!(parse_transaction(&raw).is_ok(), "the original parses");
}

/// A lookup table whose entries include one of the message's static keys: the
/// resolved account set holds that account twice, and resolution refuses.
#[test]
fn a_lookup_that_resolves_a_static_key_is_refused() {
    let e = corpus_entry("v0_real_lookup_table");
    let m = parse_transaction(&bytes(&e["raw"])).expect("v0 corpus parses");
    let lookup = m.lookups.first().expect("the corpus uses a table");
    let needed = lookup
        .writable_indexes
        .iter()
        .chain(lookup.readonly_indexes.iter())
        .copied()
        .max()
        .unwrap() as usize
        + 1;
    let table_with = |entries: Vec<[u8; 32]>| {
        let mut data = vec![0u8; LOOKUP_TABLE_META_SIZE];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
        for e in entries {
            data.extend_from_slice(&e);
        }
        data
    };
    let distinct: Vec<[u8; 32]> = (0..needed).map(|i| [i as u8 + 100; 32]).collect();
    let mut tables = std::collections::HashMap::new();
    tables.insert(lookup.table.clone(), table_with(distinct.clone()));
    assert!(
        resolve_lookups(&m, &tables).is_ok(),
        "distinct entries resolve"
    );

    let payer: [u8; 32] = bs58::decode(&m.static_keys[0])
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    let mut colliding = distinct;
    for i in lookup
        .writable_indexes
        .iter()
        .chain(lookup.readonly_indexes.iter())
    {
        colliding[*i as usize] = payer;
    }
    tables.insert(lookup.table.clone(), table_with(colliding));
    match resolve_lookups(&m, &tables) {
        Err(LookupResolveError::DuplicateAccount { address }) => {
            assert_eq!(address, m.static_keys[0])
        }
        other => panic!("expected DuplicateAccount, got {other:?}"),
    }
}

/// A lookup "table" whose type tag is not the initialized-table variant.
#[test]
fn an_account_that_is_not_an_initialized_table_is_refused() {
    let mut data = vec![0u8; LOOKUP_TABLE_META_SIZE + 32];
    data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        decode_lookup_table("T", &data),
        Err(LookupResolveError::NotALookupTable { tag: 0, .. })
    ));
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(decode_lookup_table("T", &data).unwrap().len(), 1);
}

// ─── durable nonce ──────────────────────────────────────────────────────────

/// The runtime treats a transaction as nonce-based only when the nonce
/// account is writable; a read-only nonce account is refused by the on-chain
/// check even when value and authority match.
#[test]
fn a_read_only_nonce_account_is_not_a_nonce_transaction() {
    let e = corpus_entry("legacy_durable_nonce");
    let m = parse_transaction(&bytes(&e["raw"])).unwrap();
    let mut declared = durable_nonce(&m).expect("the corpus entry is nonce-based");
    assert!(
        declared.nonce_account_writable,
        "the corpus marks it writable"
    );
    let state = NonceAccountState {
        authority: declared.nonce_authority.clone().unwrap(),
        nonce_value: declared.nonce_value.clone(),
    };
    assert!(check_durable_nonce(&declared, &state).is_ok());
    declared.nonce_account_writable = false;
    let err = check_durable_nonce(&declared, &state).unwrap_err();
    assert!(err.contains("read-only"), "{err}");
}

// ─── F-19-09 ────────────────────────────────────────────────────────────────

#[test]
fn pda_seeds_past_the_runtime_limits_derive_nothing() {
    let program = Pubkey::from_base58(SYSTEM).unwrap();
    let long = [7u8; 33];
    assert!(matches!(
        find_program_address(&[&long], &program),
        Err(SolanaTypeError::SeedLimit(_))
    ));
    let one = [1u8; 1];
    let sixteen: Vec<&[u8]> = (0..16).map(|_| &one[..]).collect();
    assert!(matches!(
        find_program_address(&sixteen, &program),
        Err(SolanaTypeError::SeedLimit(_))
    ));
    let fifteen: Vec<&[u8]> = (0..15).map(|_| &one[..]).collect();
    assert!(find_program_address(&fifteen, &program).is_ok());
    assert!(find_program_address(&[&[9u8; 32]], &program).is_ok());
}

// ─── F-19-04 / F-19-05 ──────────────────────────────────────────────────────

/// An instruction the manifest does not describe promises nothing, and that
/// is an interpretable promise: a debit contradicts it.
#[test]
fn an_undescribed_instruction_declares_no_effects_rather_than_unreadable_ones() {
    let e = DeclaredEffects::parse(&[UNDESCRIBED_INSTRUCTION_EFFECTS.to_string()]);
    assert!(e.is_interpretable());
    assert!(!e.is_silent());
    assert!(!e.debit && !e.credit && !e.authority && !e.delegate);
    let prose = DeclaredEffects::parse(&["Protocol-level state changes".to_string()]);
    assert!(!prose.is_interpretable(), "prose is still prose");
}

/// An unknown program's accounts carry the transaction's own privileges, and
/// without them are all observed.
#[test]
fn an_unknown_programs_accounts_are_not_all_read_only() {
    let registry = load_seed_manifests();
    let a = "GM4eCsQuaLNXApYz6YYUQVMxajTaJ7dB4TbroFGBaou9".to_string();
    let b = "8u8LCMQvMKrFxHbn326Ltcqv72HDPEC5FPMgPC3mXvxV".to_string();
    let unknown = "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS".to_string();
    let with_metas = resolve_accounts(
        &AccountResolutionInput {
            program_id: unknown.clone(),
            instruction_discriminator: "01".to_string(),
            account_addresses: vec![a.clone(), b.clone()],
            instruction_data: Some(vec![1]),
            real_account_metas: vec![
                RealAccountMeta {
                    is_signer: true,
                    is_writable: true,
                },
                RealAccountMeta {
                    is_signer: false,
                    is_writable: false,
                },
            ],
        },
        &registry,
    )
    .unwrap();
    let flags: Vec<(bool, bool)> = with_metas
        .resolved_accounts
        .iter()
        .map(|r| (r.is_signer, r.is_writable))
        .collect();
    assert_eq!(flags, vec![(true, true), (false, false)]);
    let without = resolve_accounts(
        &AccountResolutionInput {
            program_id: unknown,
            instruction_discriminator: "01".to_string(),
            account_addresses: vec![a, b],
            instruction_data: Some(vec![1]),
            real_account_metas: vec![],
        },
        &registry,
    )
    .unwrap();
    assert!(
        without.resolved_accounts.iter().all(|r| r.is_writable),
        "an account whose privileges are unknown is observed"
    );
}

// ─── F-19-11 ────────────────────────────────────────────────────────────────

#[test]
fn a_community_manifest_cannot_declare_its_own_tier() {
    let seed = load_seed_manifests();
    let mut manifest = seed.get(SYSTEM).expect("system manifest").clone();
    manifest.protocol.program_id = "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS".to_string();
    manifest.trust_tier = "BattleTested".to_string();
    let mut registry = ManifestRegistry::new();
    assert_eq!(registry.merge_community(std::slice::from_ref(&manifest)), 1);
    assert_eq!(
        registry
            .get(&manifest.protocol.program_id)
            .unwrap()
            .trust_tier,
        "OfficialManifest"
    );
}

// ─── F-19-12 ────────────────────────────────────────────────────────────────

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "graphite-r19-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// One writer per data directory: a second `open_data_dir` is refused while
/// the first core lives, and read-only opens neither lock nor delete a live
/// writer's temp files.
#[test]
fn a_data_directory_has_one_writer() {
    let dir = temp_dir("owner");
    let writer = GraphiteCore::open_data_dir(dir.clone()).expect("first writer");
    writer
        .quarantine_program(SYSTEM, "incident")
        .expect("quarantine");
    let err = GraphiteCore::open_data_dir(dir.clone()).expect_err("a second writer is refused");
    assert!(err.contains("another Graphite process"), "{err}");

    let in_flight = dir.join("semantic_graph.json.tmp.99999.0");
    std::fs::write(&in_flight, b"{}").unwrap();
    let reader = GraphiteCore::open_data_dir_read_only(&dir).expect("readers are not refused");
    assert_eq!(
        reader.quarantined_programs().len(),
        1,
        "the reader sees the quarantine"
    );
    assert!(
        in_flight.exists(),
        "a reader never deletes a writer's temp file"
    );

    drop(writer);
    let again = GraphiteCore::open_data_dir(dir.clone()).expect("free once the writer is gone");
    assert!(
        !in_flight.exists(),
        "the next writer clears stale temp files"
    );
    assert_eq!(
        again.quarantined_programs().len(),
        1,
        "and the quarantine is durable"
    );
    drop(again);
    std::fs::remove_dir_all(&dir).ok();
}

/// A snapshot that cannot be read is an error, never a silent fresh start
/// that lifts every quarantine.
#[test]
fn a_corrupt_snapshot_is_refused_not_replaced() {
    let dir = temp_dir("corrupt");
    std::fs::write(dir.join("semantic_graph.json"), b"{ not json").unwrap();
    let err = GraphiteCore::open_data_dir(dir.clone()).expect_err("refused");
    assert!(err.contains("corrupt"), "{err}");
    let err = GraphiteCore::open_data_dir_read_only(&dir).expect_err("refused");
    assert!(err.contains("corrupt"), "{err}");
    assert_eq!(
        std::fs::read(dir.join("semantic_graph.json")).unwrap(),
        b"{ not json",
        "the evidence is left where it was"
    );
    std::fs::remove_dir_all(&dir).ok();
}
