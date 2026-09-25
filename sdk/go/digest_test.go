package graphite

// Round 19 (F-19-C3): VerifyTransactionDigest against fixed vectors.
//
// The vector is the SolanaAgentKit bridge's real artifact — the bytes in
// graphite-core/fixtures/artifacts/sak_bridge_artifact.json, whose
// transaction_sha256 the Rust Core asserts. The TypeScript SDK pins the same
// bytes and the same digest (sdk/typescript/src/transaction-digest.test.ts).

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const (
	fixtureMessageHex = "0100020479b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664274ed6b26805d2fe" +
		"8d060529ee9a2f28763b6976d9c5fd1dee38ff36b3b769390000000000000000000000000000000000000000" +
		"0000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000" +
		"00000000000000000000000000000000000000000000000000000000000000000303000502400d0300030009" +
		"03e803000000000000020200010c0200000080841e0000000000"
	fixtureSHA256       = "c9a8ca018072273203dfae99ef91a6e03b0edd3ffc9153aba7bae814df269661"
	fixtureSignedSHA256 = "68982d9a0ae17ff538108df9084a3b79c577f09ce446ebb3934ce05b7cbd295b"
)

func fixtureTx(t *testing.T) []byte {
	t.Helper()
	msg, err := hex.DecodeString(fixtureMessageHex)
	if err != nil {
		t.Fatal(err)
	}
	tx := append([]byte{0x01}, make([]byte, 64)...)
	return append(tx, msg...)
}

func approvedFor(sha string) *VerificationResult {
	return &VerificationResult{
		Approved: true,
		Scope:    &VerificationScope{Kind: "artifact_bound", TransactionSHA256: sha},
	}
}

func TestTransactionDigestFixedVector(t *testing.T) {
	tx := fixtureTx(t)
	if len(tx) != 267 {
		t.Fatalf("fixture is %d bytes, want 267", len(tx))
	}
	got, err := TransactionDigest(tx)
	if err != nil {
		t.Fatal(err)
	}
	if got != fixtureSHA256 {
		t.Fatalf("digest drift: got %s, want %s (the Rust Core's fixture value)", got, fixtureSHA256)
	}
	if err := VerifyTransactionDigest(tx, approvedFor(fixtureSHA256)); err != nil {
		t.Fatalf("the approved transaction must bind: %v", err)
	}
}

func TestTransactionDigestAcceptsTheSignedBytesOfTheApprovedTransaction(t *testing.T) {
	signed := fixtureTx(t)
	for i := 1; i < 65; i++ {
		signed[i] = 0xab
	}
	raw := sha256.Sum256(signed)
	if hex.EncodeToString(raw[:]) != fixtureSignedSHA256 {
		t.Fatalf("signed-variant vector drift: %x", raw)
	}
	if err := VerifyTransactionDigest(signed, approvedFor(fixtureSHA256)); err != nil {
		t.Fatalf("signing changes only the slots; the digest must still bind: %v", err)
	}
}

func TestTransactionDigestCatchesAnyMessageChange(t *testing.T) {
	for _, index := range []int{65, 66, 100, 200, 266} {
		tx := fixtureTx(t)
		tx[index] ^= 0x01
		err := VerifyTransactionDigest(tx, approvedFor(fixtureSHA256))
		if !errors.Is(err, ErrAuditBind) || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("byte %d mutated: want a digest mismatch, got %v", index, err)
		}
	}
	longer := append(fixtureTx(t), 0)
	if err := VerifyTransactionDigest(longer, approvedFor(fixtureSHA256)); err == nil {
		t.Fatal("an appended byte must not bind")
	}
}

func TestTransactionDigestFailsClosedOnVerdictsThatBindNothing(t *testing.T) {
	tx := fixtureTx(t)
	cases := map[string]*VerificationResult{
		"nil":              nil,
		"blocked":          {Approved: false, Scope: &VerificationScope{Kind: "artifact_bound", TransactionSHA256: fixtureSHA256}},
		"no scope":         {Approved: true},
		"descriptive":      {Approved: true, Scope: &VerificationScope{Kind: "descriptive"}},
		"digest missing":   {Approved: true, Scope: &VerificationScope{Kind: "artifact_bound"}},
		"digest uppercase": approvedFor(strings.ToUpper(fixtureSHA256)),
		"digest truncated": approvedFor(fixtureSHA256[:16]),
		"other digest":     approvedFor(strings.Repeat("00", 32)),
	}
	for name, r := range cases {
		if err := VerifyTransactionDigest(tx, r); !errors.Is(err, ErrAuditBind) {
			t.Errorf("%s: must be refused with ErrAuditBind, got %v", name, err)
		}
	}
}

func TestSignatureCountIsParsedStrictly(t *testing.T) {
	msg, _ := hex.DecodeString(fixtureMessageHex)
	slot := make([]byte, 64)
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	refuse := map[string][]byte{
		"non-minimal":       cat([]byte{0x81, 0x00}, slot, msg),
		"past third byte":   {0x80, 0x80, 0x80, 0x01},
		"larger than u16":   {0xff, 0xff, 0x7f},
		"empty":             {},
		"no signatures":     cat([]byte{0x00}, msg),
		"slots run past":    cat([]byte{0x02}, slot, slot),
		"over packet limit": cat([]byte{0x01}, make([]byte, 1232)),
	}
	for name, tx := range refuse {
		if _, err := TransactionDigest(tx); !errors.Is(err, ErrAuditBind) {
			t.Errorf("%s: must be refused, got %v", name, err)
		}
	}
	// The non-minimal count is refused by the count reader itself; as a whole
	// frame, 0x81 first is the v1 marker (Round 19) and is refused above for
	// declaring no signers.
	if _, _, err := ReadSignatureCount(cat([]byte{0x81, 0x00}, slot)); err == nil ||
		!strings.Contains(err.Error(), "minimally encoded") {
		t.Errorf("non-minimal count: got %v", err)
	}
	count, offset, err := ReadSignatureCount([]byte{0xff, 0xff, 0x03})
	if err != nil || count != 0xffff || offset != 3 {
		t.Fatalf("largest legal three-byte count: got %d/%d/%v", count, offset, err)
	}
}

// Round 19: the v1 vector pinned in graphite-core
// (tests/round19_v1_transactions.rs::the_cross_language_v1_digest_vector_is_the_cores_answer)
// and in the TypeScript SDK. 232 bytes, signed: one 0xAB-filled trailing slot.
const v1FrameHex = "8101000107000000090909090909090909090909090909090909090909090909" +
	"0909090909090909010301010101010101010101010101010101010101010101" +
	"0101010101010101010107070707070707070707070707070707070707070707" +
	"0707070707070707070700000000000000000000000000000000000000000000" +
	"000000000000000000008813000000000000400d030002020c00000102000000" +
	"40420f0000000000abababababababababababababababababababababababab" +
	"abababababababababababababababababababababababababababababababab" +
	"abababababababab"

const v1SHA256 = "761b1f93c15a9758ff5885294853d3df69445aeb84a27392ad9a833eaeeb337b"

func v1Frame(t *testing.T) []byte {
	b, err := hex.DecodeString(v1FrameHex)
	if err != nil || len(b) != 232 {
		t.Fatalf("v1 vector: %d bytes, %v", len(b), err)
	}
	return b
}

func TestV1DigestZeroesTheTrailingSlotsAsTheCoreDoes(t *testing.T) {
	frame := v1Frame(t)
	got, err := TransactionDigest(frame)
	if err != nil || got != v1SHA256 {
		t.Fatalf("got %s, %v; want %s", got, err, v1SHA256)
	}
	res := &VerificationResult{Approved: true, Scope: &VerificationScope{Kind: "artifact_bound", TransactionSHA256: v1SHA256}}
	if err := VerifyTransactionDigest(frame, res); err != nil {
		t.Fatalf("the signed v1 frame must bind: %v", err)
	}
	frame[len(frame)-65] ^= 1
	if err := VerifyTransactionDigest(frame, res); !errors.Is(err, ErrAuditBind) {
		t.Fatalf("a change outside the slots must not bind: %v", err)
	}
}

func TestV1FramesTheRuntimeCouldNotAcceptAreRefused(t *testing.T) {
	noSigners := v1Frame(t)
	noSigners[1] = 0
	tooMany := v1Frame(t)
	tooMany[1] = 13
	huge := make([]byte, 4097)
	huge[0], huge[1] = 0x81, 1
	for name, tx := range map[string][]byte{
		"no signers": noSigners, "13 signers": tooMany,
		"slots do not fit": {0x81, 1, 0, 1}, "over 4096": huge,
	} {
		if _, err := TransactionDigest(tx); !errors.Is(err, ErrAuditBind) {
			t.Errorf("%s: must be refused, got %v", name, err)
		}
	}
}
