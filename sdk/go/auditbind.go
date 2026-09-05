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
// SHA-256 over the concatenated UTF-8 bytes of
//
//	ProgramID || InstructionDiscriminator || each account address
//	  || raw instruction data (if any) || each CPI target
//
// truncated to the first 16 hex characters (the first 8 bytes of the digest).
// Both sides must agree on the exact byte sequence or this check is worthless
// — see auditbind_test.go for the pinned cross-language vectors.
func ComputeContentHash(p AuditBindParams) string {
	h := sha256.New()
	h.Write([]byte(p.ProgramID))
	h.Write([]byte(p.InstructionDiscriminator))
	for _, addr := range p.AccountAddresses {
		h.Write([]byte(addr))
	}
	if len(p.InstructionData) > 0 {
		h.Write(p.InstructionData)
	}
	for _, t := range p.CPITargets {
		h.Write([]byte(t))
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
// instruction's raw bytes. The discriminator is the first 8 bytes of the
// instruction data, hex-encoded — matching how the core derives it.
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

// VerifyInstruction verifies a real instruction payload against the approved
// content_hash. Convenience wrapper over ProjectionFromInstruction +
// VerifyContentHash.
func VerifyInstruction(programID string, data []byte, accounts []string, contentHash string) error {
	return VerifyContentHash(ProjectionFromInstruction(programID, data, accounts), contentHash)
}
