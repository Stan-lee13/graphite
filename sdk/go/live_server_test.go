//go:build liveserver

// Real-server conformance for the Go SDK.
//
// The existing tests use httptest handlers, which prove the client speaks its
// own idea of the protocol. They cannot catch the case that actually breaks an
// integration: the SDK and the Rust server disagreeing about a field name, a
// type, or what a verdict means. This suite talks to a running Graphite.
//
//	go test -tags liveserver ./...
//
// with GRAPHITE_URL and GRAPHITE_API_KEY set. Skipped otherwise, so the default
// suite stays hermetic.
package graphite

import (
	"os"
	"testing"
)

func liveClient(t *testing.T) *Client {
	t.Helper()
	url := os.Getenv("GRAPHITE_URL")
	if url == "" {
		t.Skip("GRAPHITE_URL not set — skipping real-server conformance")
	}
	return NewClientWithAPIKey(url, os.Getenv("GRAPHITE_API_KEY"))
}

func transferInput(dest string) *VerificationInput {
	return &VerificationInput{
		ProposedIntent: ProposedIntent{
			IntentType:         "transfer",
			RawNaturalLanguage: "send SOL",
			ConfidenceOfParse:  0.95,
		},
		ProgramID:                "11111111111111111111111111111111",
		ProtocolVersion:          "1.0.0",
		InstructionDiscriminator: "02000000",
		AccountAddresses:         []string{"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", dest},
		WalletProfile:            "Gaming",
		ComputeUnits:             150,
		AccountWrites:            2,
		CPIHops:                  0,
	}
}

// The server is reachable and reports itself healthy.
func TestLiveHealth(t *testing.T) {
	c := liveClient(t)
	if err := c.Health(); err != nil {
		t.Fatalf("health failed against a real server: %v", err)
	}
}

// A verdict deserializes completely. A field the SDK silently drops is how an
// integration ends up gating on a zero value.
func TestLiveVerifyDeserializesEveryFieldTheGateNeeds(t *testing.T) {
	c := liveClient(t)
	r, err := c.Verify(transferInput("8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"))
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if r.ContentHash == "" {
		t.Error("content_hash is empty — AuditBind cannot bind the transaction without it")
	}
	if r.AuditTrailID == "" {
		t.Error("audit_trail_id is empty")
	}
	if len(r.Layers) != 8 {
		t.Errorf("expected 8 layer reports, got %d", len(r.Layers))
	}
	if r.Confidence <= 0 {
		t.Errorf("confidence did not deserialize: %v", r.Confidence)
	}
	if r.PolicyVerdict == "" {
		t.Error("policy_verdict is empty")
	}
	// The invariant the schema calls load-bearing.
	if (r.PolicyVerdict == "Approved") != r.Approved {
		t.Errorf("policy_verdict %q contradicts approved=%v", r.PolicyVerdict, r.Approved)
	}
}

// The SDK must carry a BLOCK through as a block. A client that reads a
// rejection as an error and retries, or as a zero value and proceeds, is worse
// than no client.
func TestLiveBlockedVerdictSurvivesTheRoundTrip(t *testing.T) {
	c := liveClient(t)
	// A transfer to the System Program: unspendable destination.
	r, err := c.Verify(transferInput("11111111111111111111111111111111"))
	if err != nil {
		t.Fatalf("a blocked verdict must come back as a result, not a transport error: %v", err)
	}
	if r.Approved {
		t.Fatal("the server blocks this transaction; the SDK reported approved")
	}
	if r.RiskVerdict.Status != "Blocked" {
		t.Errorf("risk status did not deserialize: %q", r.RiskVerdict.Status)
	}
	found := false
	for _, f := range r.RiskVerdict.Findings {
		if f.Pattern == "UnspendableDestination" {
			found = true
		}
	}
	if !found {
		t.Errorf("risk findings did not deserialize: %+v", r.RiskVerdict.Findings)
	}
}

// The Go AuditBind must reproduce the Rust core's content_hash for the same
// transaction. If the two languages disagree, the TOCTOU check either never
// passes or never fails — both useless.
func TestLiveAuditBindAgreesWithTheServer(t *testing.T) {
	c := liveClient(t)
	in := transferInput("8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR")
	r, err := c.Verify(in)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	local := ComputeContentHash(AuditBindParams{
		ProgramID:                in.ProgramID,
		InstructionDiscriminator: in.InstructionDiscriminator,
		AccountAddresses:         in.AccountAddresses,
	})
	if local != r.ContentHash {
		t.Fatalf("cross-language hash mismatch: go=%s rust=%s", local, r.ContentHash)
	}
}

// Auth is enforced on the real path, not just in a mock.
func TestLiveMissingAPIKeyIsRejected(t *testing.T) {
	url := os.Getenv("GRAPHITE_URL")
	if url == "" {
		t.Skip("GRAPHITE_URL not set")
	}
	if os.Getenv("GRAPHITE_API_KEY") == "" {
		t.Skip("server has no API key configured; nothing to enforce")
	}
	anon := NewClient(url)
	if _, err := anon.Verify(transferInput("8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR")); err == nil {
		t.Fatal("an unauthenticated verify succeeded against a keyed server")
	}
}
