package graphite

// Whole-transaction binding: is THIS the transaction Graphite approved?
//
// Round 19 (F-19-C3). ContentHash (auditbind.go) binds one instruction —
// program, discriminator, accounts, data, CPI targets. It cannot see the fee
// payer, the blockhash, the signer set, the header, or any other instruction
// in the transaction, so an appended drain passes it untouched. An
// artifact-bound verdict carries something stronger: Scope.TransactionSHA256,
// the SHA-256 of the exact bytes Graphite was shown. Until now neither SDK
// gave a caller a way to check it, so every integration either skipped the
// check or wrote its own parser for Solana's wire format.
//
// VerifyTransactionDigest is that check. It accepts the unsigned artifact you
// sent, or the signed bytes you are about to submit: every signature slot is
// zeroed before hashing, exactly as the Core's unsigned_artifact does, so
// signing — which changes only the slots — does not change the digest, and
// anything else does. Checking the SIGNED bytes is the stronger use: it covers
// the window between the check and the signature.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// MaxTransactionBytes is the largest serialized transaction the network
// accepts: PACKET_DATA_SIZE = 1280 − 40 − 8. Mirrors MAX_TRANSACTION_BYTES in
// graphite-core/src/tx_artifact.rs.
const MaxTransactionBytes = 1232

// V1Prefix is the first byte of a v1 frame (SIMD-0385), and
// MaxV1TransactionBytes its size bound. Mirror V1_PREFIX /
// MAX_V1_TRANSACTION_BYTES in graphite-core/src/tx_artifact.rs. A v1 frame is
// 0x81, the message, then num_required_signatures × 64 signature bytes LAST,
// with no count in front of them.
const (
	V1Prefix              = 0x81
	MaxV1TransactionBytes = 4096
	v1MaxSignatures       = 12
)

// ReadSignatureCount reads the compact-u16 signature count at the front of a
// serialized transaction and returns it with the offset of the first slot.
//
// Strict, and deliberately the Core's rules: at most three bytes, the third
// must terminate, minimally encoded (a multi-byte form whose last group is
// zero is a second spelling of a shorter number), and no larger than a u16.
// Two parsers of one wire format that accept different languages would let
// one frame mean two things.
func ReadSignatureCount(tx []byte) (count int, offset int, err error) {
	for group := 0; group < 3; group++ {
		if offset >= len(tx) {
			return 0, 0, fmt.Errorf("%w: truncated signature count. ABORTING", ErrAuditBind)
		}
		b := tx[offset]
		offset++
		bits := int(b & 0x7f)
		count |= bits << (7 * group)
		if b&0x80 == 0 {
			if group > 0 && bits == 0 {
				return 0, 0, fmt.Errorf(
					"%w: signature count is not minimally encoded — two spellings of one length. ABORTING",
					ErrAuditBind)
			}
			if count > 0xffff {
				return 0, 0, fmt.Errorf("%w: signature count %d does not fit a u16. ABORTING", ErrAuditBind, count)
			}
			return count, offset, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: signature count continues past its third byte. ABORTING", ErrAuditBind)
}

// TransactionDigest returns the lowercase-hex SHA-256 of a serialized
// transaction with every signature slot zeroed — the value the Core reports
// as Scope.TransactionSHA256 for the unsigned artifact it was shown.
func TransactionDigest(tx []byte) (string, error) {
	if len(tx) > 0 && tx[0] == V1Prefix {
		return v1Digest(tx)
	}
	if len(tx) > MaxTransactionBytes {
		return "", fmt.Errorf("%w: transaction is %d bytes; a Solana transaction is at most %d. ABORTING",
			ErrAuditBind, len(tx), MaxTransactionBytes)
	}
	count, offset, err := ReadSignatureCount(tx)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", fmt.Errorf(
			"%w: the transaction declares no signatures; every Solana transaction has a fee payer. ABORTING",
			ErrAuditBind)
	}
	end := offset + count*64
	if end >= len(tx) {
		return "", fmt.Errorf(
			"%w: %d signature slot(s) run past (or up to the end of) a %d-byte transaction; there is no message to bind. ABORTING",
			ErrAuditBind, count, len(tx))
	}
	unsigned := make([]byte, len(tx))
	copy(unsigned, tx)
	for i := offset; i < end; i++ {
		unsigned[i] = 0
	}
	sum := sha256.Sum256(unsigned)
	return hex.EncodeToString(sum[:]), nil
}

// v1Digest is the digest of a v1 frame: its trailing
// num_required_signatures × 64 bytes zeroed (Round 19). It does not parse the
// message and does not need to: the Core refuses a v1 frame whose message does
// not end exactly where those slots begin, so it never approved one, and a
// digest matching an approval can only be of bytes identical to the approved
// frame outside the slots. What can be checked cheaply is still checked, so a
// malformed frame fails here rather than as a mismatch.
func v1Digest(tx []byte) (string, error) {
	if len(tx) > MaxV1TransactionBytes {
		return "", fmt.Errorf("%w: v1 transaction is %d bytes; a v1 transaction is at most %d. ABORTING",
			ErrAuditBind, len(tx), MaxV1TransactionBytes)
	}
	if len(tx) < 2 || tx[1] == 0 || int(tx[1]) > v1MaxSignatures {
		return "", fmt.Errorf("%w: v1 header must declare 1 to %d required signatures. ABORTING",
			ErrAuditBind, v1MaxSignatures)
	}
	count := int(tx[1])
	start := len(tx) - count*64
	// 0x81, the 3-byte header, the 4-byte config mask and the 32-byte
	// lifetime come before any signature.
	if start < 40 {
		return "", fmt.Errorf("%w: %d trailing signature slot(s) do not fit a %d-byte v1 frame. ABORTING",
			ErrAuditBind, count, len(tx))
	}
	unsigned := make([]byte, len(tx))
	copy(unsigned, tx)
	for i := start; i < len(unsigned); i++ {
		unsigned[i] = 0
	}
	sum := sha256.Sum256(unsigned)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyTransactionDigest returns nil only when tx is the transaction an
// APPROVED, ARTIFACT-BOUND verdict was issued for. Call it immediately before
// signing (on the unsigned bytes) or before submitting (on the signed bytes).
//
// It fails closed on everything it cannot establish: a nil result, Approved
// false, a nil or descriptive Scope, a TransactionSHA256 that is missing or
// not 64 lowercase hex characters, and a malformed frame. An error, never a
// bool, so a forgotten negation cannot turn it into a pass.
func VerifyTransactionDigest(tx []byte, result *VerificationResult) error {
	if result == nil {
		return fmt.Errorf("%w: no verification result. ABORTING", ErrAuditBind)
	}
	if !result.Approved {
		return fmt.Errorf("%w: the verdict is not an approval — a blocked result binds nothing. ABORTING", ErrAuditBind)
	}
	if result.Scope == nil {
		return fmt.Errorf(
			"%w: the verdict carries no scope, so whether it was bound to transaction bytes is unknown (servers before 2026-09-08). ABORTING",
			ErrAuditBind)
	}
	if result.Scope.Kind != "artifact_bound" {
		return fmt.Errorf(
			"%w: the verdict's scope is %q, not artifact_bound: Graphite was not shown a transaction, so no transaction can be bound to it. ABORTING",
			ErrAuditBind, result.Scope.Kind)
	}
	approved := result.Scope.TransactionSHA256
	if !isLowerHex64(approved) {
		return fmt.Errorf(
			"%w: Scope.TransactionSHA256 is missing or is not 64 lowercase hex characters. ABORTING", ErrAuditBind)
	}
	computed, err := TransactionDigest(tx)
	if err != nil {
		return err
	}
	if computed != approved {
		return fmt.Errorf(
			"%w: transaction digest mismatch (computed %s, approved %s). These are not the bytes Graphite verified. ABORTING",
			ErrAuditBind, computed, approved)
	}
	return nil
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
