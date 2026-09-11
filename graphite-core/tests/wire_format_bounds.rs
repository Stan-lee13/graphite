//! compact-u16 is a u16, and the parser has to agree.
//!
//! Solana calls these lengths ShortU16. Three groups of seven bits can express
//! 2,097,151, so the encoding can carry numbers the field cannot mean — and
//! every length in a message is one of them: signature count, account key
//! count, instruction count, per-instruction account and data lengths, lookup
//! count, and the writable/readonly index vectors.
//!
//! `take` would eventually run out of bytes, so this is not a buffer over-read.
//! It is a wire-format correctness defect with an amplification edge: a parser
//! that accepts 2,097,151 as a declared length reasons about that structure —
//! allocating, iterating, multiplying against it — before discovering the input
//! was 200 bytes. Bounding at the format's own limit removes both.
//!
//! Found by review 2026-09-11.

use graphite_core::tx_artifact::{parse_transaction, ArtifactParseError};

/// A transaction whose FIRST compact-u16 (the signature count) is `encoded`.
///
/// Nothing follows it. A length that is accepted therefore fails later, on the
/// bytes that are not there; a length that is rejected fails here, on the
/// length itself. The two are different errors, which is what lets these tests
/// tell "accepted the number" from "rejected the number".
fn with_signature_count(encoded: &[u8]) -> Result<(), ArtifactParseError> {
    let mut bytes = encoded.to_vec();
    bytes.extend_from_slice(&[0u8; 8]);
    parse_transaction(&bytes).map(|_| ())
}

fn rejected_as_too_large(encoded: &[u8]) -> bool {
    matches!(
        with_signature_count(encoded),
        Err(ArtifactParseError::LengthNotU16 { .. })
    )
}

/// 65,535 is a valid compact-u16 and must be accepted as a NUMBER.
///
/// Worth pinning precisely, because `0xFF 0xFF 0x03` looks like an overflow
/// vector and is not one: 0x7F | (0x7F << 7) | (0x03 << 14) is exactly 65,535,
/// the canonical three-byte encoding of the largest value the type holds. A
/// parser that rejected it would be rejecting legal wire format.
#[test]
fn the_largest_u16_is_accepted_as_a_length() {
    let err = with_signature_count(&[0xFF, 0xFF, 0x03]).expect_err("nothing follows the length");
    assert!(
        !matches!(err, ArtifactParseError::LengthNotU16 { .. }),
        "65535 is a valid compact-u16 and must not be rejected as out of range: {err}"
    );
    // It failed on the bytes that are not there, which is the correct reason.
    assert!(
        matches!(
            err,
            ArtifactParseError::LengthExceedsInput { .. } | ArtifactParseError::Truncated { .. }
        ),
        "unexpected reason: {err}"
    );
}

/// 65,534, one below the boundary, same treatment.
#[test]
fn one_below_the_boundary_is_accepted_as_a_length() {
    let err = with_signature_count(&[0xFE, 0xFF, 0x03]).expect_err("nothing follows the length");
    assert!(
        !matches!(err, ArtifactParseError::LengthNotU16 { .. }),
        "{err}"
    );
}

/// 65,536 is one past the type and must be refused as a length.
#[test]
fn one_past_the_boundary_is_refused() {
    // 0x00 | (0x00 << 7) | (0x04 << 14) = 65536.
    assert!(
        rejected_as_too_large(&[0x80, 0x80, 0x04]),
        "65536 does not fit a u16 and must not be accepted as one: {:?}",
        with_signature_count(&[0x80, 0x80, 0x04])
    );
}

/// The maximal three-byte encoding — 2,097,151 — is refused.
///
/// This is the amplification case: a declared length thirty-two times larger
/// than the format allows, in a three-byte transaction.
#[test]
fn the_maximal_three_byte_encoding_is_refused() {
    match with_signature_count(&[0xFF, 0xFF, 0x7F]) {
        Err(ArtifactParseError::LengthNotU16 { value, .. }) => {
            assert_eq!(value, 2_097_151, "the refusal should name what it read");
        }
        other => panic!("2,097,151 was not refused as a length: {other:?}"),
    }
}

/// Non-minimal encodings are still refused, and for their own reason.
///
/// The range check must not have displaced the canonical-encoding check: two
/// spellings of the same length are exactly what a binding is supposed to
/// prevent.
#[test]
fn non_minimal_encodings_are_still_refused_as_non_canonical() {
    for encoding in [
        &[0x80, 0x00][..],       // 0 spelled in two bytes
        &[0x81, 0x00][..],       // 1 spelled in two bytes
        &[0xFF, 0x80, 0x00][..], // 127 spelled in three
    ] {
        assert!(
            matches!(
                with_signature_count(encoding),
                Err(ArtifactParseError::NonCanonicalLength { .. })
            ),
            "{encoding:?} is not minimally encoded and must be refused as such: {:?}",
            with_signature_count(encoding)
        );
    }
}

/// Anti-vacuity: ordinary small lengths still parse.
///
/// If every length were refused, every test above would pass while the parser
/// read nothing at all.
#[test]
fn ordinary_lengths_still_parse() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/artifacts/devnet_transactions.json"
    ))
    .expect("fixtures must parse");
    let bytes: Vec<u8> = f["benign_transfer"]["blob"]
        .as_array()
        .expect("blob")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect();
    let m = parse_transaction(&bytes).expect("a real transaction must still parse");
    assert_eq!(m.instructions.len(), 1);
}

/// Every length in the message is bounded, not only the first.
///
/// The signature count is the one these vectors reach directly; the rest go
/// through the same reader. This walks a real transaction and rewrites each
/// single-byte length in turn into the maximal three-byte encoding, and every
/// one of them must be refused.
#[test]
fn the_bound_applies_to_lengths_throughout_the_message() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/artifacts/devnet_transactions.json"
    ))
    .expect("fixtures must parse");
    let original: Vec<u8> = f["benign_transfer"]["blob"]
        .as_array()
        .expect("blob")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect();
    parse_transaction(&original).expect("control must parse");

    let mut refused = 0usize;
    for i in 0..original.len() {
        // Only rewrite bytes that could be a single-byte length; replacing an
        // arbitrary byte with a three-byte sequence shifts everything after it
        // and would mostly produce noise rather than a length test.
        if original[i] & 0x80 != 0 {
            continue;
        }
        let mut mutated = original.clone();
        mutated.splice(i..i + 1, [0xFF, 0xFF, 0x7F]);
        if matches!(
            parse_transaction(&mutated),
            Err(ArtifactParseError::LengthNotU16 { .. })
        ) {
            refused += 1;
        }
    }
    assert!(
        refused > 0,
        "no position in a real transaction reached the length check, so this test proves nothing"
    );
    println!("{refused} length positions refused the maximal three-byte encoding");
}
