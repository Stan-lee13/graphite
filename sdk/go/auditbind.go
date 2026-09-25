package graphite

// AuditBind — TOCTOU binding between what Graphite verified and what you submit.
//
// Graphite verifies a transaction BEFORE it is signed. Between that approval
// and the moment the transaction actually reaches the chain there is a window
// in which the instruction can still be mutated — by a compromised RPC proxy,
// a malicious wallet adapter, or a race inside the agent's own pipeline.
// Verification that is not bound to the submitted bytes protects nothing
// against that window.
//
// ContentHash on a VerificationResult is the binding key: a deterministic hash
// over exactly the transaction inputs (never the verification outcome, so a
// client can reproduce it before submitting). Recompute it from the
// instruction you are about to send and compare; any mutation changes the hash
// and VerifyContentHash returns an error.
//
// WHY THIS EXISTS (2026-09-05 SDK audit): this logic previously existed only
// inside the TypeScript SolanaAgentKit integration, so every Go consumer
// either shipped an open TOCTOU window or reinvented the hash. That
// reinvention is exactly where it went wrong before — an earlier TypeScript
// encoding never matched the Rust byte stream, so the check could never pass.
// The byte layout below is pinned against the Rust core by the vectors in
// auditbind_test.go, which are the same values the TypeScript suite asserts.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrAuditBind is returned (wrapped) whenever the transaction about to be
// submitted is not the one Graphite verified. Use errors.Is to detect it.
var ErrAuditBind = errors.New("auditbind")

// AuditBindParams is the exact projection the Rust core hashes. Field ORDER is
// part of the contract — the hash is over concatenated bytes, not a keyed
// structure.
type AuditBindParams struct {
	// ProgramID is the base58 program id.
	ProgramID string
	// InstructionDiscriminator is the hex discriminator.
	InstructionDiscriminator string
	// AccountAddresses are base58 addresses in instruction order.
	AccountAddresses []string
	// InstructionData is the raw instruction data (nil or empty when none).
	InstructionData []byte
	// CPITargets are base58 CPI target program ids.
	CPITargets []string
}

// ComputeContentHash reproduces the Rust core's deterministic content_hash
// (graphite-core/src/verification.rs::generate_audit_id).
//
// FRAMED encoding (Round 17, F-16-09): SHA-256 over
//
//	"graphite-content-hash-v2\x00"
//	|| len(ProgramID) || ProgramID
//	|| len(disc) || disc
//	|| count(accounts) || (len(addr) || addr)...
//	|| len(data) || data                  (absent data is length 0)
//	|| count(CPITargets) || (len(t) || t)...
//
// every length a u32 little-endian, truncated to the first 16 hex characters.
// The bare concatenation it replaces let [A, B] with no data and [A] with
// data = bytes(B) hash identically. Both sides must agree on the exact byte
// sequence or this check is worthless — see auditbind_test.go for the pinned
// cross-language vectors.
func ComputeContentHash(p AuditBindParams) string {
	h := sha256.New()
	u32 := func(n int) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(n))
		h.Write(b[:])
	}
	field := func(b []byte) {
		u32(len(b))
		h.Write(b)
	}
	h.Write([]byte("graphite-content-hash-v2\x00"))
	field([]byte(p.ProgramID))
	field([]byte(p.InstructionDiscriminator))
	u32(len(p.AccountAddresses))
	for _, addr := range p.AccountAddresses {
		field([]byte(addr))
	}
	field(p.InstructionData)
	u32(len(p.CPITargets))
	for _, t := range p.CPITargets {
		field([]byte(t))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// VerifyContentHash checks a transaction projection against the approved
// content_hash. It returns an error (wrapping ErrAuditBind) on any mismatch.
//
// Call it after checking result.Approved and immediately before signing or
// submitting. Returning an error rather than a bool is deliberate: a bool
// invites `if ok {}` with a forgotten negation, which would fail open.
func VerifyContentHash(tx AuditBindParams, contentHash string) error {
	// Fail closed on the wrong field: AuditTrailID is prefixed "gr-" and is
	// NOT client-reproducible (it mixes in the verification outcome and a
	// sequence number). Silently "checking" it would mean never detecting a
	// mutation at all, so this is an error, not a skip.
	if strings.HasPrefix(contentHash, "gr-") {
		return fmt.Errorf(
			"%w: received audit_trail_id instead of content_hash — the TOCTOU check "+
				"cannot be performed. Pass result.ContentHash. ABORTING", ErrAuditBind)
	}
	if contentHash == "" {
		return fmt.Errorf(
			"%w: empty content_hash — the TOCTOU check cannot be performed. ABORTING",
			ErrAuditBind)
	}
	computed := ComputeContentHash(tx)
	if computed != contentHash {
		return fmt.Errorf(
			"%w: hash mismatch (computed %s, approved %s). The transaction changed "+
				"between verification and submission. ABORTING",
			ErrAuditBind, computed, contentHash)
	}
	return nil
}

// ProjectionFromInstruction builds the hash projection from a real
// instruction's raw bytes, with the discriminator taken as the first 8 bytes
// of the data, hex-encoded — the Anchor convention.
//
// That is wrong for every native program: System instructions carry a 4-byte
// tag and SPL Token a 1-byte one, so for a System transfer this yields
// `0200000040420f00` (the tag plus half the lamport amount) and a hash that can
// never match the Core's. Use ProjectionFromInstructionWithDiscriminator for
// anything that is not an Anchor program.
func ProjectionFromInstruction(programID string, data []byte, accounts []string) AuditBindParams {
	n := len(data)
	if n > 8 {
		n = 8
	}
	var instructionData []byte
	if len(data) > 0 {
		instructionData = data
	}
	return AuditBindParams{
		ProgramID:                programID,
		InstructionDiscriminator: hex.EncodeToString(data[:n]),
		AccountAddresses:         accounts,
		InstructionData:          instructionData,
	}
}

// ProjectionFromInstructionWithDiscriminator builds the hash projection with
// the discriminator EXACTLY as it was sent to Graphite as
// instruction_discriminator — required for native programs.
//
// Round 19 (F-19-C4): the SolanaAgentKit integration's version, ported. The
// SDK had kept the 8-byte-only derivation after the integration fixed it, so a
// Go caller binding a native-program instruction either could not pass the
// check at all or reconstructed the projection by hand — the
// snapshot-instead-of-live-object pattern that opened the TOCTOU window the
// integration closed.
//
// GFX-001 (2026-09-17 forensic audit), carried over with it: the declared
// discriminator must be a prefix of the data it claims to describe. A label
// that is not is a projection of a different instruction, and the Core fails
// L2 on the same contradiction. Case and a 0x prefix are tolerated in the
// comparison; the projection keeps the string as given, because it must
// reproduce what was sent.
func ProjectionFromInstructionWithDiscriminator(programID, discriminator string, data []byte, accounts []string) (AuditBindParams, error) {
	declared := strings.ToLower(discriminator)
	if strings.HasPrefix(declared, "0x") {
		declared = declared[2:]
	}
	actual := hex.EncodeToString(data)
	if declared != "" && !strings.HasPrefix(actual, declared) {
		shown := actual
		if len(shown) > 32 {
			shown = shown[:32] + "…"
		}
		return AuditBindParams{}, fmt.Errorf(
			"%w: declared discriminator %s is not a prefix of this instruction's data (%s). "+
				"The label and the bytes describe different instructions. ABORTING",
			ErrAuditBind, declared, shown)
	}
	var instructionData []byte
	if len(data) > 0 {
		instructionData = data
	}
	return AuditBindParams{
		ProgramID:                programID,
		InstructionDiscriminator: discriminator,
		AccountAddresses:         accounts,
		InstructionData:          instructionData,
	}, nil
}

// VerifyInstruction verifies a real instruction payload against the approved
// content_hash, deriving the discriminator from the first 8 data bytes (the
// Anchor convention). For native programs use
// VerifyInstructionWithDiscriminator.
func VerifyInstruction(programID string, data []byte, accounts []string, contentHash string) error {
	return VerifyContentHash(ProjectionFromInstruction(programID, data, accounts), contentHash)
}

// VerifyInstructionWithDiscriminator verifies a real instruction payload
// against the approved content_hash using the discriminator exactly as it was
// sent to Graphite (Round 19, F-19-C4). Refuses a discriminator that is not a
// prefix of the data (GFX-001).
func VerifyInstructionWithDiscriminator(programID, discriminator string, data []byte, accounts []string, contentHash string) error {
	p, err := ProjectionFromInstructionWithDiscriminator(programID, discriminator, data, accounts)
	if err != nil {
		return err
	}
	return VerifyContentHash(p, contentHash)
}
