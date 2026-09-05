package graphite

// Cross-language parity + misuse tests for the Go SDK's AuditBind.
//
// The mechanism is worthless unless this implementation reproduces the Rust
// core's content_hash byte for byte. The vectors below are pinned against the
// Rust algorithm (graphite-core/src/verification.rs::generate_audit_id) and
// are the SAME values asserted by the TypeScript suites — if any of the three
// implementations drifts, one of these fails.

import (
	"errors"
	"testing"
)

const (
	systemProgram         = "11111111111111111111111111111111"
	transferDiscriminator = "02000000"
	fromAddr              = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
	toAddr                = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"
	attackerAddr          = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7"
)

func TestContentHashMatchesRustVectorNoDataNoCPI(t *testing.T) {
	got := ComputeContentHash(AuditBindParams{
		ProgramID:                systemProgram,
		InstructionDiscriminator: transferDiscriminator,
		AccountAddresses:         []string{fromAddr, toAddr},
	})
	// sha256(program || disc || from || to)[0..16]
	if want := "afb61d8865b4cb68"; got != want {
		t.Fatalf("cross-language hash drift: got %s, want %s", got, want)
	}
}

func TestContentHashMatchesRustVectorWithDataAndCPI(t *testing.T) {
	got := ComputeContentHash(AuditBindParams{
		ProgramID:                systemProgram,
		InstructionDiscriminator: transferDiscriminator,
		AccountAddresses:         []string{fromAddr},
		InstructionData:          []byte{1, 2, 3},
		CPITargets:               []string{"cpiA"},
	})
	// sha256(program || disc || from || bytes(1,2,3) || "cpiA")[0..16]
	if want := "87751f34a0f8a590"; got != want {
		t.Fatalf("cross-language hash drift: got %s, want %s", got, want)
	}
}

func TestVerifyAcceptsExactVerifiedTransaction(t *testing.T) {
	tx := AuditBindParams{
		ProgramID:                systemProgram,
		InstructionDiscriminator: transferDiscriminator,
		AccountAddresses:         []string{fromAddr, toAddr},
	}
	if err := VerifyContentHash(tx, ComputeContentHash(tx)); err != nil {
		t.Fatalf("the exact verified transaction must pass: %v", err)
	}
}

// ── The attacks this exists to stop ────────────────────────────────────────

func TestMutationsAreCaught(t *testing.T) {
	base := AuditBindParams{
		ProgramID:                systemProgram,
		InstructionDiscriminator: transferDiscriminator,
		AccountAddresses:         []string{fromAddr, toAddr},
		InstructionData:          []byte{2, 0, 0, 0, 100, 0, 0, 0},
	}
	approved := ComputeContentHash(base)

	mutations := map[string]AuditBindParams{
		"destination swapped to an attacker address": func() AuditBindParams {
			m := base
			m.AccountAddresses = []string{fromAddr, attackerAddr}
			return m
		}(),
		"transfer amount inflated": func() AuditBindParams {
			m := base
			m.InstructionData = []byte{2, 0, 0, 0, 255, 255, 255, 255}
			return m
		}(),
		"accounts reordered (source/destination swapped)": func() AuditBindParams {
			m := base
			m.AccountAddresses = []string{toAddr, fromAddr}
			return m
		}(),
		"program id substituted": func() AuditBindParams {
			m := base
			m.ProgramID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
			return m
		}(),
		"extra account appended": func() AuditBindParams {
			m := base
			m.AccountAddresses = []string{fromAddr, toAddr, attackerAddr}
			return m
		}(),
		"CPI target injected": func() AuditBindParams {
			m := base
			m.CPITargets = []string{"evilProgram"}
			return m
		}(),
	}

	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			err := VerifyContentHash(mutated, approved)
			if err == nil {
				t.Fatalf("mutation was NOT caught — this is the TOCTOU window: %s", name)
			}
			if !errors.Is(err, ErrAuditBind) {
				t.Fatalf("error must wrap ErrAuditBind so callers can branch: %v", err)
			}
		})
	}
}

// ── Misuse must fail closed, never silently pass ───────────────────────────

func TestAuditTrailIDIsRejectedRatherThanNoOping(t *testing.T) {
	tx := AuditBindParams{
		ProgramID:                systemProgram,
		InstructionDiscriminator: transferDiscriminator,
		AccountAddresses:         []string{fromAddr, toAddr},
	}
	err := VerifyContentHash(tx, "gr-622ce548dab9f32d-00000000")
	if err == nil {
		t.Fatal("audit_trail_id is not client-reproducible — accepting it would mean never detecting a mutation")
	}
	if !errors.Is(err, ErrAuditBind) {
		t.Fatalf("error must wrap ErrAuditBind: %v", err)
	}
}

func TestEmptyContentHashIsRejected(t *testing.T) {
	tx := AuditBindParams{
		ProgramID:                systemProgram,
		InstructionDiscriminator: transferDiscriminator,
		AccountAddresses:         []string{fromAddr, toAddr},
	}
	if err := VerifyContentHash(tx, ""); err == nil {
		t.Fatal("an empty content_hash must abort, not pass")
	}
}

// ── Instruction-level binding ──────────────────────────────────────────────

func TestProjectionFromInstructionDerivesDiscriminator(t *testing.T) {
	data := []byte{2, 0, 0, 0, 232, 118, 72, 23}
	p := ProjectionFromInstruction(systemProgram, data, []string{fromAddr, toAddr})
	if p.InstructionDiscriminator != "02000000e8764817" {
		t.Fatalf("discriminator mismatch: %s", p.InstructionDiscriminator)
	}
	if p.ProgramID != systemProgram || len(p.AccountAddresses) != 2 {
		t.Fatalf("projection mismatch: %+v", p)
	}
}

func TestVerifyInstructionBindsExactSubmittedInstruction(t *testing.T) {
	data := []byte{2, 0, 0, 0, 232, 118, 72, 23}
	accounts := []string{fromAddr, toAddr}
	approved := ComputeContentHash(ProjectionFromInstruction(systemProgram, data, accounts))

	if err := VerifyInstruction(systemProgram, data, accounts, approved); err != nil {
		t.Fatalf("the exact instruction must verify: %v", err)
	}
	tampered := []string{fromAddr, attackerAddr}
	if err := VerifyInstruction(systemProgram, data, tampered, approved); err == nil {
		t.Fatal("a tampered account list must abort")
	}
}

// A short instruction (fewer than 8 data bytes) must not panic on the
// discriminator slice — a panic here would be a DoS in the caller's signing
// path, reached with entirely ordinary input.
func TestShortAndEmptyInstructionDataDoNotPanic(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {1}, {1, 2, 3}} {
		p := ProjectionFromInstruction(systemProgram, data, []string{fromAddr})
		approved := ComputeContentHash(p)
		if err := VerifyContentHash(p, approved); err != nil {
			t.Fatalf("round-trip failed for %d data bytes: %v", len(data), err)
		}
	}
}
