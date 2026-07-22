package graphite

import (
	"encoding/json"
	"testing"
)

func TestClientCreation(t *testing.T) {
	client := NewClient("http://localhost:8080")
	if client.BaseURL != "http://localhost:8080" {
		t.Errorf("expected BaseURL http://localhost:8080, got %s", client.BaseURL)
	}
	if client.HTTPClient == nil {
		t.Error("HTTPClient should not be nil")
	}
	if client.HTTPClient.Timeout.Seconds() != 30 {
		t.Errorf("expected 30s timeout, got %v", client.HTTPClient.Timeout)
	}
}

func TestVerificationInputSerialization(t *testing.T) {
	input := &VerificationInput{
		ProposedIntent: ProposedIntent{
			IntentType:          "transfer",
			RawNaturalLanguage:  "Transfer 1 SOL",
			ConfidenceOfParse:   0.95,
		},
		ProgramID:                "11111111111111111111111111111111",
		ProtocolVersion:          "1.0.0",
		InstructionDiscriminator: "02000000",
		AccountAddresses:          []string{"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"},
		WalletProfile:             "Standard",
		ComputeUnits:              150,
		AccountWrites:             2,
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundtrip VerificationInput
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if roundtrip.ProgramID != input.ProgramID {
		t.Error("ProgramID roundtrip mismatch")
	}
	if roundtrip.ProposedIntent.IntentType != input.ProposedIntent.IntentType {
		t.Error("IntentType roundtrip mismatch")
	}
}

func TestVerificationResultDeserialization(t *testing.T) {
	jsonStr := `{
		"approved": true,
		"confidence": 0.85,
		"trust_tier": "OfficialManifest",
		"risk_verdict": {
			"status": "Clear",
			"findings": []
		},
		"policy_verdict": "Approved",
		"audit_trail_id": "gr-abc12345-00000001",
		"protocol_name": "System Program",
		"instruction_name": "Transfer",
		"manifest_found": true,
		"unknown_protocol": false,
		"summary": "protocol=System Program confidence=0.8500 risk=Clear approved=yes sim=ok"
	}`

	var result VerificationResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !result.Approved {
		t.Error("expected approved=true")
	}
	if result.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", result.Confidence)
	}
	if result.TrustTier != "OfficialManifest" {
		t.Errorf("expected trust_tier OfficialManifest, got %s", result.TrustTier)
	}
	if result.RiskVerdict.Status != "Clear" {
		t.Error("expected risk status Clear")
	}
	if result.ManifestFound != true {
		t.Error("expected manifest_found=true")
	}
}

func TestVerificationResultWithRiskFindings(t *testing.T) {
	jsonStr := `{
		"approved": false,
		"confidence": 0.15,
		"trust_tier": "Unknown",
		"risk_verdict": {
			"status": "Blocked",
			"findings": [
				{"pattern": "Drainer", "reason": "Account drain detected"},
				{"pattern": "AuthorityHijack", "reason": "SetAuthority detected"}
			]
		},
		"policy_verdict": "Denied",
		"audit_trail_id": "gr-xyz789-00000002",
		"protocol_name": "Unknown",
		"instruction_name": "Unknown",
		"manifest_found": false,
		"unknown_protocol": true,
		"simulation_flagged": true,
		"simulation_divergence": 3.5,
		"summary": "protocol=Unknown confidence=0.1500 risk=Blocked approved=no sim=flagged"
	}`

	var result VerificationResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if result.Approved {
		t.Error("expected approved=false")
	}
	if len(result.RiskVerdict.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.RiskVerdict.Findings))
	}
	if result.RiskVerdict.Findings[0].Pattern != "Drainer" {
		t.Error("first finding should be Drainer")
	}
	if result.SimulationFlagged == nil || !*result.SimulationFlagged {
		t.Error("expected simulation_flagged=true")
	}
	if result.SimulationDivergence == nil || *result.SimulationDivergence != 3.5 {
		t.Error("expected simulation_divergence=3.5")
	}
}

func TestHealthCheck(t *testing.T) {
	// Test against a non-existent server — should get an error
	client := NewClient("http://localhost:9999")
	err := client.Health()
	if err == nil {
		t.Error("expected error for non-existent server")
	}
}
