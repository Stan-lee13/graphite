//! Round 19 (F-19-V1): Solana v1 transactions (SIMD-0385).
//!
//! v1 is roughly a sixth of live mainnet traffic (3,302 of the 19,458
//! transactions in `tools/mainnet-sample/mainnet_sample.json`), and until this
//! round Graphite refused every one by name. The parser is the security
//! boundary, so accepting the format is only half of the work; the other half
//! is refusing every v1 frame the runtime refuses. These tests build v1 frames
//! by hand — the layout is `solana-message` 5.0 `v1/message.rs`, the frame
//! `solana-transaction` 5.0 `SchemaRead for VersionedTransaction` — and check:
//!
//! - a valid v1 transfer reads as the runtime reads it: keys, privileges,
//!   instructions, the lifetime specifier as the blockhash, the config values;
//! - the signed-over bytes are the frame minus its trailing signatures,
//!   version prefix included, proven with a real ed25519 signature;
//! - every frame helper finds the signatures at the END of a v1 frame;
//! - every runtime refusal has a case, and the size bound is the format's:
//!   4096 bytes for v1, 1232 for legacy and v0.
//!
//! The byte-level differential proof against the agave crates themselves is
//! `tools/runtime-oracle`.

use ed25519_dalek::Signer;
use graphite_core::tx_artifact::{
    artifact_sha256_of_signed, bound_artifact_sha256, durable_nonce, filled_signature_slots,
    max_frame_bytes, message_bytes, parse_transaction, simulation_identity, unsigned_artifact,
    ArtifactParseError, SignatureBindingError, V1Config, V1Violation, MAX_TRANSACTION_BYTES,
    MAX_V1_TRANSACTION_BYTES, V1_PREFIX,
};
use sha2::{Digest, Sha256};

fn payer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
}

fn second_signer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x43u8; 32])
}

fn b58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

const RECIPIENT: [u8; 32] = [7u8; 32];
/// The System program is the all-zero key.
const SYSTEM: [u8; 32] = [0u8; 32];
const LIFETIME: [u8; 32] = [9u8; 32];

/// A v1 frame, field by field, so a test can break exactly one of them.
#[derive(Clone)]
struct V1 {
    header: [u8; 3],
    /// `None`: the mask the config values imply. `Some`: written verbatim,
    /// with the config values still written from `config`.
    mask: Option<u32>,
    config: V1Config,
    lifetime: [u8; 32],
    keys: Vec<[u8; 32]>,
    /// (program index, account indexes, data)
    instructions: Vec<(u8, Vec<u8>, Vec<u8>)>,
    /// `None`: `header[0]` zero slots. `Some(n)`: n zero slots.
    slots: Option<usize>,
}

impl V1 {
    /// A System transfer of 1,000,000 lamports from the payer, with a
    /// priority fee and a compute-unit limit in the header rather than in
    /// ComputeBudget instructions.
    fn transfer() -> Self {
        let mut data = vec![2u8, 0, 0, 0];
        data.extend_from_slice(&1_000_000u64.to_le_bytes());
        V1 {
            header: [1, 0, 1],
            mask: None,
            config: V1Config {
                priority_fee: Some(5_000),
                compute_unit_limit: Some(200_000),
                loaded_accounts_data_size_limit: None,
                heap_size: None,
            },
            lifetime: LIFETIME,
            keys: vec![payer().verifying_key().to_bytes(), RECIPIENT, SYSTEM],
            instructions: vec![(2, vec![0, 1], data)],
            slots: None,
        }
    }

    fn implied_mask(&self) -> u32 {
        let c = &self.config;
        let mut m = 0;
        if c.priority_fee.is_some() {
            m |= 0b11;
        }
        if c.compute_unit_limit.is_some() {
            m |= 0b100;
        }
        if c.loaded_accounts_data_size_limit.is_some() {
            m |= 0b1000;
        }
        if c.heap_size.is_some() {
            m |= 0b1_0000;
        }
        m
    }

    /// The signed-over bytes: `0x81` then the message body.
    fn message(&self) -> Vec<u8> {
        let mut out = vec![V1_PREFIX];
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.mask.unwrap_or(self.implied_mask()).to_le_bytes());
        out.extend_from_slice(&self.lifetime);
        out.push(self.instructions.len() as u8);
        out.push(self.keys.len() as u8);
        for k in &self.keys {
            out.extend_from_slice(k);
        }
        let c = &self.config;
        if let Some(v) = c.priority_fee {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in [
            c.compute_unit_limit,
            c.loaded_accounts_data_size_limit,
            c.heap_size,
        ]
        .into_iter()
        .flatten()
        {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for (program, accounts, data) in &self.instructions {
            out.push(*program);
            out.push(accounts.len() as u8);
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        for (_, accounts, data) in &self.instructions {
            out.extend_from_slice(accounts);
            out.extend_from_slice(data);
        }
        out
    }

    /// The whole frame, signature slots zeroed and LAST, with no count.
    fn frame(&self) -> Vec<u8> {
        let mut out = self.message();
        let slots = self.slots.unwrap_or(self.header[0] as usize);
        out.resize(out.len() + 64 * slots, 0);
        out
    }
}

/// A legacy frame: `[1][64 zero][1,0,1][3 keys][blockhash][1 ix]`.
fn legacy_transfer(data: &[u8]) -> Vec<u8> {
    let mut out = vec![1u8];
    out.resize(65, 0);
    out.extend_from_slice(&[1, 0, 1, 3]);
    out.extend_from_slice(&payer().verifying_key().to_bytes());
    out.extend_from_slice(&RECIPIENT);
    out.extend_from_slice(&SYSTEM);
    out.extend_from_slice(&LIFETIME);
    out.extend_from_slice(&[1, 2, 2, 0, 1]);
    let mut n = data.len();
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
    out.extend_from_slice(data);
    out
}

fn refused(frame: &[u8]) -> ArtifactParseError {
    parse_transaction(frame).expect_err("the runtime refuses this frame, so must Graphite")
}

fn v1_refusal(frame: &[u8]) -> V1Violation {
    match refused(frame) {
        ArtifactParseError::V1Refused(v) => v,
        other => panic!("expected a v1 rule, got {other}"),
    }
}

// ─── Reading a valid v1 transaction ──────────────────────────────────────────

#[test]
fn a_v1_transfer_reads_as_the_runtime_reads_it() {
    let frame = V1::transfer().frame();
    let m = parse_transaction(&frame).expect("a valid v1 transfer parses");
    let payer = b58(&payer().verifying_key().to_bytes());
    assert_eq!(m.version, Some(1));
    assert_eq!(
        m.static_keys,
        vec![payer.clone(), b58(&RECIPIENT), b58(&SYSTEM)]
    );
    assert_eq!(m.fee_payer, payer);
    assert_eq!(m.signers, vec![payer.clone()]);
    // Header [1, 0, 1]: the payer signs and writes, the recipient writes,
    // the System program (the one readonly-unsigned key) does not.
    assert_eq!(m.writable, vec![payer.clone(), b58(&RECIPIENT)]);
    assert_eq!(m.recent_blockhash, b58(&LIFETIME), "the lifetime specifier");
    assert!(
        m.lookups.is_empty() && !m.has_lookup_accounts(),
        "v1 has no lookup tables"
    );
    assert_eq!(m.instructions.len(), 1);
    let ix = &m.instructions[0];
    assert_eq!(ix.program_id, "11111111111111111111111111111111");
    assert_eq!(ix.account_indexes, vec![0, 1]);
    assert_eq!(ix.accounts, vec![Some(payer), Some(b58(&RECIPIENT))]);
    assert!(!ix.has_unresolved_accounts());
    assert_eq!(&ix.data[..4], &[2, 0, 0, 0]);
    assert_eq!(&ix.data[4..], &1_000_000u64.to_le_bytes());
    assert_eq!(
        m.v1_config,
        Some(V1Config {
            priority_fee: Some(5_000),
            compute_unit_limit: Some(200_000),
            loaded_accounts_data_size_limit: None,
            heap_size: None,
        })
    );
}

#[test]
fn every_config_value_is_read_from_its_own_position() {
    // Distinct values in every field, so a value read from its neighbour's
    // position cannot pass.
    let mut tx = V1::transfer();
    tx.config = V1Config {
        priority_fee: Some(0x0102_0304_0506_0708),
        compute_unit_limit: Some(1_400_000),
        loaded_accounts_data_size_limit: Some(65_536),
        heap_size: Some(256 * 1024),
    };
    let m = parse_transaction(&tx.frame()).expect("all five mask bits");
    assert_eq!(m.v1_config, Some(tx.config));

    // Each field alone.
    for config in [
        V1Config {
            compute_unit_limit: Some(77),
            ..Default::default()
        },
        V1Config {
            loaded_accounts_data_size_limit: Some(88),
            ..Default::default()
        },
        V1Config {
            heap_size: Some(32 * 1024),
            ..Default::default()
        },
        V1Config::default(),
    ] {
        let mut tx = V1::transfer();
        tx.config = config;
        let m = parse_transaction(&tx.frame()).expect("one config field");
        assert_eq!(m.v1_config, Some(config));
    }
}

#[test]
fn legacy_and_v0_carry_no_v1_config() {
    let m = parse_transaction(&legacy_transfer(&[2, 0, 0, 0])).expect("legacy");
    assert_eq!(m.version, None);
    assert_eq!(m.v1_config, None);
}

#[test]
fn a_v1_durable_nonce_transaction_is_recognised() {
    let mut tx = V1::transfer();
    tx.keys = vec![
        payer().verifying_key().to_bytes(),
        [5u8; 32], // nonce account, writable
        SYSTEM,
    ];
    tx.instructions = vec![(2, vec![1, 0, 0], vec![4, 0, 0, 0])];
    let m = parse_transaction(&tx.frame()).expect("v1 nonce transaction");
    let nonce = durable_nonce(&m).expect("instruction 0 advances a nonce");
    assert_eq!(nonce.nonce_account, b58(&[5u8; 32]));
    assert_eq!(nonce.nonce_value, b58(&LIFETIME));
    assert!(nonce.nonce_account_writable && nonce.authority_is_signer);
}

// ─── Where v1 keeps its signatures ──────────────────────────────────────────

/// The signed-over bytes are the frame minus its trailing signatures, the
/// `0x81` prefix included — what `VersionedMessage::serialize()` produces
/// and the SDK signs. Proven with a real signature: `bound_artifact_sha256`
/// verifies it over `message_bytes` under the fee payer's key.
#[test]
fn a_real_signature_over_message_bytes_binds_the_v1_frame() {
    let tx = V1::transfer();
    let unsigned = tx.frame();
    let msg = message_bytes(&unsigned).expect("message");
    assert_eq!(msg, tx.message().as_slice());
    assert_eq!(msg[0], V1_PREFIX, "the prefix is signed over");
    assert_eq!(msg.len(), unsigned.len() - 64);

    let sig = payer().sign(msg).to_bytes();
    let mut signed = unsigned.clone();
    let n = signed.len();
    signed[n - 64..].copy_from_slice(&sig);

    let digest = bound_artifact_sha256(&signed, &b58(&sig)).expect("binds");
    assert_eq!(digest, artifact_sha256_of_signed(&signed).unwrap());
    assert_eq!(digest, hex::encode(Sha256::digest(&unsigned)));

    // Another signature is another transaction.
    let other = payer().sign(b"something else").to_bytes();
    assert_eq!(
        bound_artifact_sha256(&signed, &b58(&other)),
        Err(SignatureBindingError::FirstSlotDiffers)
    );
    // The same slot over different instruction bytes does not verify.
    let mut tampered = signed.clone();
    let data_at = tx.message().len() - 1;
    tampered[data_at] ^= 1;
    assert!(matches!(
        bound_artifact_sha256(&tampered, &b58(&sig)),
        Err(SignatureBindingError::SignatureDoesNotVerify { .. })
    ));
    // A signature over the body WITHOUT the prefix is not the runtime's
    // signature, and does not bind.
    let wrong = payer().sign(&msg[1..]).to_bytes();
    let mut wrong_signed = unsigned.clone();
    wrong_signed[n - 64..].copy_from_slice(&wrong);
    assert!(matches!(
        bound_artifact_sha256(&wrong_signed, &b58(&wrong)),
        Err(SignatureBindingError::SignatureDoesNotVerify { .. })
    ));
}

#[test]
fn the_fee_payers_signature_is_the_first_trailing_slot() {
    let mut tx = V1::transfer();
    tx.header = [2, 1, 1];
    tx.keys = vec![
        payer().verifying_key().to_bytes(),
        second_signer().verifying_key().to_bytes(),
        SYSTEM,
    ];
    tx.instructions = vec![(2, vec![0, 1], vec![2, 0, 0, 0])];
    let unsigned = tx.frame();
    let msg = tx.message();
    let payer_sig = payer().sign(&msg).to_bytes();
    let other_sig = second_signer().sign(&msg).to_bytes();
    let mut signed = unsigned.clone();
    let at = msg.len();
    signed[at..at + 64].copy_from_slice(&payer_sig);
    signed[at + 64..at + 128].copy_from_slice(&other_sig);
    assert!(bound_artifact_sha256(&signed, &b58(&payer_sig)).is_ok());
    assert_eq!(
        bound_artifact_sha256(&signed, &b58(&other_sig)),
        Err(SignatureBindingError::FirstSlotDiffers),
        "the second signer's signature is not the transaction id"
    );
}

#[test]
fn unsigned_artifact_zeroes_the_trailing_slots_and_nothing_else() {
    let mut tx = V1::transfer();
    tx.header = [2, 1, 1];
    tx.keys = vec![
        payer().verifying_key().to_bytes(),
        second_signer().verifying_key().to_bytes(),
        SYSTEM,
    ];
    tx.instructions = vec![(2, vec![0, 1], vec![2, 0, 0, 0])];
    let unsigned = tx.frame();
    assert_eq!(filled_signature_slots(&unsigned).unwrap(), 0);
    assert_eq!(unsigned_artifact(&unsigned).unwrap(), unsigned);

    let msg = tx.message();
    let mut signed = unsigned.clone();
    // Only the SECOND slot filled: counted, and zeroed, at the end.
    signed[msg.len() + 64..].copy_from_slice(&second_signer().sign(&msg).to_bytes());
    assert_eq!(filled_signature_slots(&signed).unwrap(), 1);
    signed[msg.len()..msg.len() + 64].copy_from_slice(&payer().sign(&msg).to_bytes());
    assert_eq!(filled_signature_slots(&signed).unwrap(), 2);
    assert_eq!(unsigned_artifact(&signed).unwrap(), unsigned);
    assert_eq!(
        artifact_sha256_of_signed(&signed).unwrap(),
        hex::encode(Sha256::digest(&unsigned))
    );
    // A v1 frame's first 64 bytes are its message, not a slot: a filled
    // header must not be counted or zeroed as a signature.
    assert_ne!(&unsigned_artifact(&signed).unwrap()[..64], &[0u8; 64][..]);
}

#[test]
fn the_simulation_identity_ignores_lifetime_and_signatures_and_nothing_else() {
    let tx = V1::transfer();
    let id = simulation_identity(&tx.frame()).unwrap();

    let mut other_lifetime = tx.clone();
    other_lifetime.lifetime = [0xAB; 32];
    assert_eq!(
        simulation_identity(&other_lifetime.frame()).unwrap(),
        id,
        "the simulator replaces the lifetime specifier"
    );

    let mut signed = tx.frame();
    let n = signed.len();
    signed[n - 64..].copy_from_slice(&payer().sign(&tx.message()).to_bytes());
    assert_eq!(
        simulation_identity(&signed).unwrap(),
        id,
        "a signature is not executed"
    );

    let mut other_amount = tx.clone();
    other_amount.instructions[0].2[4] ^= 1;
    assert_ne!(simulation_identity(&other_amount.frame()).unwrap(), id);

    let mut other_fee = tx.clone();
    other_fee.config.priority_fee = Some(5_001);
    assert_ne!(
        simulation_identity(&other_fee.frame()).unwrap(),
        id,
        "the config values are executed under, so they are part of the identity"
    );
    let mut other_limit = tx.clone();
    other_limit.config.compute_unit_limit = Some(199_999);
    assert_ne!(simulation_identity(&other_limit.frame()).unwrap(), id);

    let mut malformed = tx.frame();
    malformed.push(0);
    assert!(simulation_identity(&malformed).is_err());
}

#[test]
fn every_helper_refuses_a_v1_frame_it_cannot_parse_rather_than_guess() {
    let mut frame = V1::transfer().frame();
    frame.push(0);
    assert!(message_bytes(&frame).is_err());
    assert!(unsigned_artifact(&frame).is_err());
    assert!(filled_signature_slots(&frame).is_err());
    assert!(artifact_sha256_of_signed(&frame).is_err());
    assert!(bound_artifact_sha256(&frame, &b58(&[1u8; 64])).is_err());
}

// ─── The size bound is the format's ─────────────────────────────────────────

#[test]
fn a_1500_byte_v1_frame_is_accepted_and_a_1500_byte_legacy_frame_is_not() {
    let mut tx = V1::transfer();
    let base = tx.frame().len();
    tx.instructions[0].2.resize(12 + 1500 - base, 0xEE);
    let v1 = tx.frame();
    assert_eq!(v1.len(), 1500);
    let m = parse_transaction(&v1).expect("v1 exists to carry this");
    assert_eq!(m.instructions[0].data.len(), 12 + 1500 - base);
    assert_eq!(max_frame_bytes(&v1), MAX_V1_TRANSACTION_BYTES);
    assert!(message_bytes(&v1).is_ok() && unsigned_artifact(&v1).is_ok());

    let base = legacy_transfer(&[]).len();
    let legacy = legacy_transfer(&vec![0xEE; 1500 - base - 1]);
    assert_eq!(legacy.len(), 1500);
    assert_eq!(max_frame_bytes(&legacy), MAX_TRANSACTION_BYTES);
    assert_eq!(
        refused(&legacy),
        ArtifactParseError::TooLarge {
            len: 1500,
            max: 1232
        }
    );
}

#[test]
fn the_v1_bound_is_exactly_4096_bytes() {
    let mut tx = V1::transfer();
    let base = tx.frame().len();
    tx.instructions[0].2.resize(12 + 4096 - base, 0);
    let at_max = tx.frame();
    assert_eq!(at_max.len(), 4096);
    parse_transaction(&at_max).expect("4096 bytes is MAX_TRANSACTION_SIZE");

    tx.instructions[0].2.push(0);
    let over = tx.frame();
    assert_eq!(over.len(), 4097);
    let too_large = ArtifactParseError::TooLarge {
        len: 4097,
        max: 4096,
    };
    assert_eq!(refused(&over), too_large);
    assert_eq!(message_bytes(&over), Err(too_large.clone()));
    assert_eq!(unsigned_artifact(&over), Err(too_large.clone()));
    assert_eq!(filled_signature_slots(&over), Err(too_large));
}

// ─── Every runtime refusal ──────────────────────────────────────────────────

/// The runtime refuses every other high-bit first byte ("invalid transaction
/// discriminator"). Graphite reads one as the start of a 128-plus signature
/// count, which no 1232-byte frame holds, so it is refused too — and a
/// valid v1 frame under another prefix is never read as v1.
#[test]
fn only_0x81_starts_a_v1_frame() {
    for first in [0x80u8, 0x82, 0x83, 0xC0, 0xFF] {
        let mut frame = V1::transfer().frame();
        frame[0] = first;
        let err = refused(&frame);
        assert!(
            !matches!(err, ArtifactParseError::V1Refused(_)),
            "{first:#x} was read as a v1 frame: {err}"
        );
        assert!(message_bytes(&frame).is_err() && unsigned_artifact(&frame).is_err());
        assert!(filled_signature_slots(&frame).is_err());
        assert_eq!(max_frame_bytes(&frame), MAX_TRANSACTION_BYTES);
    }
}

#[test]
fn a_v1_message_behind_a_signature_count_is_not_a_v1_frame() {
    // `[count][slots][0x81 ...]`: the runtime's decoder takes the legacy/v0
    // path on the count and then refuses the v1 message it finds there.
    let tx = V1::transfer();
    let mut frame = vec![1u8];
    frame.resize(65, 0);
    frame.extend_from_slice(&tx.message());
    let err = refused(&frame);
    assert_eq!(err, ArtifactParseError::UnsupportedVersion(1));
    assert!(
        !err.to_string().contains("not implemented"),
        "the message no longer says v1 is unimplemented: {err}"
    );
    // A version past 1 behind a signature count is refused by name too.
    frame[65] = 0x82;
    assert_eq!(refused(&frame), ArtifactParseError::UnsupportedVersion(2));
}

#[test]
fn a_config_mask_the_decoder_cannot_round_trip_is_refused() {
    for bit in 5..32 {
        let mut tx = V1::transfer();
        tx.mask = Some(tx.implied_mask() | (1u32 << bit));
        assert!(
            matches!(
                v1_refusal(&tx.frame()),
                V1Violation::ConfigMaskUnknownBits { .. }
            ),
            "bit {bit}"
        );
    }
    for half in [0b01u32, 0b10] {
        let mut tx = V1::transfer();
        tx.config.priority_fee = None;
        tx.mask = Some(half | 0b100);
        assert!(matches!(
            v1_refusal(&tx.frame()),
            V1Violation::ConfigMaskPartialPriorityFee { .. }
        ));
    }
}

#[test]
fn more_than_twelve_signatures_is_refused() {
    let signers: Vec<[u8; 32]> = (0..13u8).map(|i| [0x10 + i; 32]).collect();
    let mut tx = V1::transfer();
    tx.header = [13, 0, 1];
    tx.keys = signers.clone();
    tx.keys.push(SYSTEM);
    tx.instructions = vec![(13, vec![0], vec![])];
    assert_eq!(
        v1_refusal(&tx.frame()),
        V1Violation::TooManySignatures { count: 13, max: 12 }
    );
    // Twelve is the limit, not past it.
    tx.header = [12, 0, 1];
    tx.keys.remove(12);
    tx.instructions = vec![(12, vec![0], vec![])];
    let m = parse_transaction(&tx.frame()).expect("twelve signers");
    assert_eq!(m.signers.len(), 12);
}

#[test]
fn more_than_sixty_four_addresses_is_refused() {
    let mut tx = V1::transfer();
    tx.keys = (0..65u8).map(|i| [i.wrapping_add(0x40); 32]).collect();
    tx.keys[0] = payer().verifying_key().to_bytes();
    assert_eq!(
        v1_refusal(&tx.frame()),
        V1Violation::TooManyAddresses { count: 65, max: 64 }
    );
    tx.keys.pop();
    parse_transaction(&tx.frame()).expect("sixty-four addresses");
}

#[test]
fn more_than_sixty_four_instructions_is_refused() {
    let mut tx = V1::transfer();
    tx.instructions = vec![(2, vec![], vec![]); 65];
    assert_eq!(
        v1_refusal(&tx.frame()),
        V1Violation::TooManyInstructions { count: 65, max: 64 }
    );
    tx.instructions.pop();
    parse_transaction(&tx.frame()).expect("sixty-four instructions");
}

#[test]
fn an_impossible_header_is_refused() {
    for header in [
        [1u8, 0, 3], // signers + readonly-unsigned > addresses
        [4, 0, 0],   // more signers than addresses
        [1, 1, 1],   // no writable signer
        [0, 0, 0],   // no signer at all
        [2, 3, 0],   // readonly-signed past the signers
    ] {
        let mut tx = V1::transfer();
        tx.header = header;
        assert!(
            matches!(
                refused(&tx.frame()),
                ArtifactParseError::ImpossibleHeader { .. }
            ),
            "{header:?}"
        );
    }
}

#[test]
fn a_duplicate_address_is_refused() {
    let mut tx = V1::transfer();
    tx.keys[1] = tx.keys[0];
    assert!(matches!(
        refused(&tx.frame()),
        ArtifactParseError::DuplicateAccountKey {
            first: 0,
            second: 1,
            ..
        }
    ));
}

#[test]
fn a_heap_size_outside_the_runtime_rule_is_refused() {
    for heap_size in [
        0,
        1024,
        31 * 1024,
        32 * 1024 + 1,
        33 * 1024 - 1,
        257 * 1024,
        u32::MAX,
    ] {
        let mut tx = V1::transfer();
        tx.config.heap_size = Some(heap_size);
        assert_eq!(
            v1_refusal(&tx.frame()),
            V1Violation::InvalidHeapSize { heap_size },
            "{heap_size}"
        );
    }
    for heap_size in [32 * 1024, 33 * 1024, 256 * 1024] {
        let mut tx = V1::transfer();
        tx.config.heap_size = Some(heap_size);
        parse_transaction(&tx.frame()).unwrap_or_else(|e| panic!("{heap_size}: {e}"));
    }
}

#[test]
fn program_and_account_indexes_are_checked() {
    let mut tx = V1::transfer();
    tx.instructions[0].0 = 3;
    assert!(matches!(
        refused(&tx.frame()),
        ArtifactParseError::ProgramIndexOutOfRange {
            program_index: 3,
            ..
        }
    ));
    let mut tx = V1::transfer();
    tx.instructions[0].0 = 0;
    assert_eq!(
        refused(&tx.frame()),
        ArtifactParseError::ProgramIsFeePayer { index: 0 }
    );
    let mut tx = V1::transfer();
    tx.instructions[0].1 = vec![0, 3];
    assert!(matches!(
        refused(&tx.frame()),
        ArtifactParseError::AccountIndexOutOfRange {
            account_index: 3,
            ..
        }
    ));
}

#[test]
fn the_signature_array_must_be_complete_and_nothing_may_follow_it() {
    let tx = V1::transfer();
    let full = tx.frame();

    // One byte short of the last slot.
    assert!(matches!(
        refused(&full[..full.len() - 1]),
        ArtifactParseError::LengthExceedsInput {
            what: "signatures",
            ..
        }
    ));
    // No slots at all: the count is the header's, not the frame's.
    let mut none = tx.clone();
    none.slots = Some(0);
    assert!(matches!(
        refused(&none.frame()),
        ArtifactParseError::LengthExceedsInput {
            what: "signatures",
            ..
        }
    ));
    // An extra slot is trailing bytes: the runtime reads exactly the
    // header's count and nothing after it.
    let mut extra = tx.clone();
    extra.slots = Some(2);
    assert_eq!(
        refused(&extra.frame()),
        ArtifactParseError::TrailingBytes { trailing: 64 }
    );
    let mut trailing = full.clone();
    trailing.push(0);
    assert_eq!(
        refused(&trailing),
        ArtifactParseError::TrailingBytes { trailing: 1 }
    );
}

#[test]
fn every_truncation_of_a_v1_frame_is_refused() {
    let mut tx = V1::transfer();
    tx.config.loaded_accounts_data_size_limit = Some(1);
    tx.config.heap_size = Some(64 * 1024);
    let full = tx.frame();
    parse_transaction(&full).expect("the untruncated frame");
    for len in 0..full.len() {
        assert!(
            parse_transaction(&full[..len]).is_err(),
            "a {len}-byte prefix of a {}-byte frame parsed",
            full.len()
        );
        assert!(message_bytes(&full[..len]).is_err(), "{len}");
    }
}

// ─── Real mainnet v1 traffic ────────────────────────────────────────────────

/// Every v1 transaction in the Round 18 mainnet sample executed on mainnet,
/// so every one must parse, and its real fee-payer signature must verify
/// over `message_bytes` — the strongest available evidence that the
/// signed-over slice is the runtime's. Ignored because the sample is a
/// 23 MB fetched file; run with
/// `cargo test --test round19_v1_transactions -- --ignored --nocapture`.
#[test]
#[ignore = "reads tools/mainnet-sample/mainnet_sample.json"]
fn every_mainnet_v1_transaction_in_the_sample_parses_and_binds() {
    use base64::Engine as _;
    use std::collections::BTreeMap;
    let path = std::env::var("GRAPHITE_MAINNET_SAMPLE").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tools/mainnet-sample/mainnet_sample.json"
        )
        .to_string()
    });
    let raw: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")),
    )
    .expect("sample JSON");
    let rows = raw["rows"].as_array().expect("rows");

    let mut total = 0usize;
    let mut accepted = 0usize;
    let mut over_packet = 0usize;
    let mut bound = 0usize;
    let mut refused_by: BTreeMap<String, usize> = BTreeMap::new();
    let mut bind_failed: BTreeMap<String, usize> = BTreeMap::new();
    let mut masks: BTreeMap<u32, usize> = BTreeMap::new();
    for row in rows {
        if row["version"].as_str() != Some("1") && row["version"].as_u64() != Some(1) {
            continue;
        }
        total += 1;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(row["b64"].as_str().expect("b64"))
            .expect("base64");
        if bytes.len() > MAX_TRANSACTION_BYTES {
            over_packet += 1;
        }
        match parse_transaction(&bytes) {
            Err(e) => {
                let label = format!("{e:?}");
                let label = label.split(['{', ' ']).next().unwrap_or("?").to_string();
                *refused_by.entry(label).or_default() += 1;
            }
            Ok(m) => {
                accepted += 1;
                assert_eq!(m.version, Some(1));
                let c = m.v1_config.expect("v1 config");
                let mut mask = 0;
                if c.priority_fee.is_some() {
                    mask |= 0b11;
                }
                if c.compute_unit_limit.is_some() {
                    mask |= 0b100;
                }
                if c.loaded_accounts_data_size_limit.is_some() {
                    mask |= 0b1000;
                }
                if c.heap_size.is_some() {
                    mask |= 0b1_0000;
                }
                *masks.entry(mask).or_default() += 1;
                let n = m.signers.len();
                assert_eq!(filled_signature_slots(&bytes).unwrap(), n);
                assert!(simulation_identity(&bytes).is_ok());
                let first = &bytes[bytes.len() - 64 * n..bytes.len() - 64 * n + 64];
                match bound_artifact_sha256(&bytes, &b58(first)) {
                    Ok(_) => bound += 1,
                    Err(e) => *bind_failed.entry(format!("{e}")).or_default() += 1,
                }
            }
        }
    }
    println!(
        "[mainnet v1] {total} v1 transactions, {over_packet} larger than 1232 bytes; \
         {accepted} accepted, {} refused; {bound} bound by their real fee-payer signature",
        total - accepted
    );
    println!("[mainnet v1] refused by reason: {refused_by:?}");
    println!("[mainnet v1] binding failures: {bind_failed:?}");
    println!("[mainnet v1] config masks among accepted: {masks:?}");
    assert!(total > 0, "the sample holds no v1 transactions");
    assert_eq!(
        accepted, total,
        "an executed transaction was refused: {refused_by:?}"
    );
    assert_eq!(bound, accepted, "{bind_failed:?}");
}

// ─── The pipeline, not only the parser ──────────────────────────────────────

use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::TransactionInstruction;
use graphite_core::verification::{
    GraphiteCore, LayerStatus, ProposedIntent, VerificationInput, VerificationScope,
};

const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

fn v1_input(tx: &V1, siblings: Vec<TransactionInstruction>) -> VerificationInput {
    let (_, accounts, data) = tx.instructions[0].clone();
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "send SOL".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: b58(&SYSTEM),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: hex::encode(&data[..4]),
        account_addresses: accounts
            .iter()
            .map(|i| b58(&tx.keys[*i as usize]))
            .collect(),
        instruction_data: Some(data),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: Some(tx.frame()),
        transaction_instructions: siblings,
        cpi_trace: None,
        uses_versioned_transaction: true,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn layer(
    r: &graphite_core::verification::VerificationResult,
    prefix: &str,
) -> (LayerStatus, String) {
    let l = r
        .layers
        .iter()
        .find(|l| l.layer.starts_with(prefix))
        .expect("layer");
    (l.status, l.reason.clone())
}

/// A v1 transfer goes through the whole pipeline bound to its bytes: the
/// described instruction is located in the frame, and a request that says
/// the transaction is versioned is not reported as misdescribing it (the
/// check used to mean "v0").
#[test]
fn a_v1_transfer_is_verified_bound_to_its_bytes() {
    let tx = V1::transfer();
    let r = GraphiteCore::new()
        .verify(&v1_input(&tx, vec![]))
        .expect("verified");
    let (l2, why) = layer(&r, "L2");
    assert_ne!(l2, LayerStatus::Failed, "{why}");
    assert!(
        matches!(r.scope, VerificationScope::ArtifactBound { .. }),
        "{:?}",
        r.scope
    );
    assert!(
        !r.risk_verdict
            .findings
            .iter()
            .any(|f| f.reason.contains("does not describe these bytes")),
        "{:?}",
        r.risk_verdict.findings
    );
    let warned = format!("{:?}", r);
    assert!(
        !warned.contains("does not describe these bytes"),
        "{warned}"
    );
}

/// The size gate in front of the pipeline is the frame's own bound. A
/// 1,500-byte v1 transaction — most real ones are over a packet — used to be
/// refused as larger than PACKET_DATA_SIZE before it was parsed.
#[test]
fn a_v1_transaction_larger_than_a_packet_reaches_the_pipeline() {
    let mut tx = V1::transfer();
    let memo = bs58::decode(MEMO).into_vec().unwrap();
    let mut memo_key = [0u8; 32];
    memo_key.copy_from_slice(&memo);
    tx.keys.push(memo_key);
    tx.instructions.push((3, vec![], vec![b'x'; 16]));
    let base = tx.frame().len();
    tx.instructions[1].2.resize(16 + 1500 - base, b'x');
    assert_eq!(tx.frame().len(), 1500);
    let siblings = vec![TransactionInstruction {
        program_id: MEMO.to_string(),
        instruction_discriminator: hex::encode(&tx.instructions[1].2[..8]),
        account_addresses: vec![],
        cpi_targets: vec![],
    }];
    let r = GraphiteCore::new()
        .verify(&v1_input(&tx, siblings))
        .expect("a 1,500-byte v1 frame is inside its format's bound");
    let (l2, why) = layer(&r, "L2");
    assert_ne!(l2, LayerStatus::Failed, "{why}");
    assert!(matches!(r.scope, VerificationScope::ArtifactBound { .. }));

    // The same bound still holds for legacy: 1,233 bytes is refused up front.
    let legacy = legacy_transfer(&vec![0u8; 1233 - legacy_transfer(&[]).len()]);
    let mut input = v1_input(&V1::transfer(), vec![]);
    input.signed_transaction = Some(legacy);
    input.uses_versioned_transaction = false;
    let err = GraphiteCore::new()
        .verify(&input)
        .expect_err("legacy over a packet");
    assert!(format!("{err}").contains("PACKET_DATA_SIZE"), "{err}");
}

/// The cross-language v1 vector: the same signed 232-byte v1 frame and its
/// digest are pinned in the TypeScript SDK (`transaction-digest.test.ts`)
/// and the Go SDK (`digest_test.go`). Here the Core's own functions produce
/// the value, so the three implementations are held to one answer.
#[test]
fn the_cross_language_v1_digest_vector_is_the_cores_answer() {
    let frame = hex::decode(concat!(
        "8101000107000000090909090909090909090909090909090909090909090909",
        "0909090909090909010301010101010101010101010101010101010101010101",
        "0101010101010101010107070707070707070707070707070707070707070707",
        "0707070707070707070700000000000000000000000000000000000000000000",
        "000000000000000000008813000000000000400d030002020c00000102000000",
        "40420f0000000000abababababababababababababababababababababababab",
        "abababababababababababababababababababababababababababababababab",
        "abababababababab"
    ))
    .unwrap();
    assert_eq!(frame.len(), 232);
    let m = parse_transaction(&frame).expect("the vector is a valid v1 frame");
    assert_eq!(m.version, Some(1));
    assert_eq!(filled_signature_slots(&frame).unwrap(), 1);
    let digest = hex::encode(Sha256::digest(unsigned_artifact(&frame).unwrap()));
    assert_eq!(
        digest,
        "761b1f93c15a9758ff5885294853d3df69445aeb84a27392ad9a833eaeeb337b"
    );
    assert_eq!(artifact_sha256_of_signed(&frame).unwrap(), digest);
}
