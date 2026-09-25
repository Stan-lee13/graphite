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
	// framed v2: domain || len-prefixed program, disc, [from, to], empty data, no CPI
	if want := "48c65c638aceb5de"; got != want {
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
	// framed v2: domain || len-prefixed program, disc, [from], bytes(1,2,3), ["cpiA"]
	if want := "dd8569c46af7e6c0"; got != want {
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

// ── Native programs: an explicit discriminator (Round 19, F-19-C4) ─────────

// transfer1M is a real System transfer of 1_000_000 lamports: u32 LE 2, then
// u64 LE amount.
var transfer1M = []byte{2, 0, 0, 0, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0}

// The third cross-language vector, pinned in the SolanaAgentKit suite
// (toctou-signing-boundary.test.ts) and the TypeScript SDK (auditbind.test.ts)
// as the hash graphite-core computes for this System transfer, framed v2.
func TestContentHashMatchesRustVectorNativeTransfer(t *testing.T) {
	p, err := ProjectionFromInstructionWithDiscriminator(systemProgram, transferDiscriminator, transfer1M, []string{fromAddr, toAddr})
	if err != nil {
		t.Fatal(err)
	}
	if p.InstructionDiscriminator != transferDiscriminator {
		t.Fatalf("an explicit discriminator must win over the 8-byte guess: %s", p.InstructionDiscriminator)
	}
	// framed v2: domain || len-prefixed program, disc 02000000, [from, to], 12 data bytes, no CPI
	if got, want := ComputeContentHash(p), "6d302e018b2b91ce"; got != want {
		t.Fatalf("cross-language hash drift: got %s, want %s", got, want)
	}
	if err := VerifyInstructionWithDiscriminator(systemProgram, transferDiscriminator, transfer1M, []string{fromAddr, toAddr}, "6d302e018b2b91ce"); err != nil {
		t.Fatalf("the native transfer must verify against the Core's hash: %v", err)
	}
	// The Anchor 8-byte guess reads half the amount into the discriminator.
	guessed := ProjectionFromInstruction(systemProgram, transfer1M, []string{fromAddr, toAddr})
	if guessed.InstructionDiscriminator != "0200000040420f00" || ComputeContentHash(guessed) == "6d302e018b2b91ce" {
		t.Fatalf("the 8-byte fallback has silently changed meaning: %+v", guessed)
	}
}

func TestSPLTokenOneByteDiscriminatorBinds(t *testing.T) {
	const splToken = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	// TransferChecked: tag 12, u64 amount, u8 decimals.
	data := []byte{12, 0x10, 0x27, 0, 0, 0, 0, 0, 0, 6}
	approved := ComputeContentHash(AuditBindParams{
		ProgramID:                splToken,
		InstructionDiscriminator: "0c",
		AccountAddresses:         []string{fromAddr, toAddr},
		InstructionData:          data,
	})
	if err := VerifyInstructionWithDiscriminator(splToken, "0c", data, []string{fromAddr, toAddr}, approved); err != nil {
		t.Fatalf("a 1-byte SPL Token discriminator must bind: %v", err)
	}
	if err := VerifyInstruction(splToken, data, []string{fromAddr, toAddr}, approved); err == nil {
		t.Fatal("the 8-byte guess cannot reproduce a native program's hash")
	}
}

// GFX-001 (2026-09-17 forensic audit): an explicit discriminator that is not a
// prefix of the data describes a different instruction.
func TestDiscriminatorThatIsNotADataPrefixIsRefused(t *testing.T) {
	const splToken = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	setAuthority := append([]byte{0x06, 0x02, 0x01}, make([]byte, 32)...)
	if _, err := ProjectionFromInstructionWithDiscriminator(splToken, "ff", setAuthority, []string{fromAddr}); !errors.Is(err, ErrAuditBind) {
		t.Fatalf("a mismatched label must be refused, got %v", err)
	}
	if err := VerifyInstructionWithDiscriminator(systemProgram, "03000000", transfer1M, []string{fromAddr, toAddr}, "6d302e018b2b91ce"); !errors.Is(err, ErrAuditBind) {
		t.Fatalf("a mismatched label must be refused before hashing, got %v", err)
	}
	if _, err := ProjectionFromInstructionWithDiscriminator(systemProgram, "02000000", []byte{2}, []string{fromAddr}); err == nil {
		t.Fatal("a discriminator longer than the data cannot be its prefix")
	}
	// Case and a 0x prefix are normalised for the comparison; the projection
	// keeps the string as sent, because it must reproduce what Graphite hashed.
	p, err := ProjectionFromInstructionWithDiscriminator(splToken, "0x06", setAuthority, []string{fromAddr})
	if err != nil || p.InstructionDiscriminator != "0x06" {
		t.Fatalf("0x06 over a 0x06-prefixed payload must pass unchanged: %+v, %v", p, err)
	}
}
