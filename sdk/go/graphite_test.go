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
		InstructionData:           ByteArray{0x02, 0x00, 0x00, 0x00},
		WalletProfile:             WalletProfileStandard,
		BehaviorEvidence: BehaviorEvidence{
			HasSignedManifest:      false,
			CommunityVerifiedCount: 5,
			BattleTestedTxCount:    50000,
			SimulationMatchCount:   100,
		},
		ComputeUnits:              150,
		AccountWrites:             2,
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Verify instruction_data is serialized as array, NOT base64
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}
	instrData, ok := raw["instruction_data"].([]interface{})
	if !ok {
		t.Fatalf("expected instruction_data to be a JSON array, got %T: %v", raw["instruction_data"], raw["instruction_data"])
	}
	if len(instrData) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(instrData))
	}
	if instrData[0] != float64(0x02) {
		t.Errorf("expected first byte 0x02, got %v", instrData[0])
	}

	// Verify behavior_evidence is present
	behEv, ok := raw["behavior_evidence"].(map[string]interface{})
	if !ok {
		t.Fatal("expected behavior_evidence to be a JSON object")
	}
	if behEv["community_verified_count"] != float64(5) {
		t.Errorf("expected community_verified_count=5, got %v", behEv["community_verified_count"])
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
	if len(roundtrip.InstructionData) != 4 || roundtrip.InstructionData[0] != 0x02 {
		t.Error("InstructionData roundtrip mismatch")
	}
	if roundtrip.BehaviorEvidence.CommunityVerifiedCount != 5 {
		t.Error("BehaviorEvidence roundtrip mismatch")
	}
}

func TestVerificationInputWithSimulationBaseline(t *testing.T) {
	input := &VerificationInput{
		ProposedIntent: ProposedIntent{
			IntentType:         "swap",
			RawNaturalLanguage: "Swap 1 SOL for USDC",
			ConfidenceOfParse:  0.9,
		},
		ProgramID:                "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
		InstructionDiscriminator: "e517cb977ae3ad2a",
		AccountAddresses:         []string{"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"},
		WalletProfile:            WalletProfileStandard,
		BehaviorEvidence: BehaviorEvidence{
			HasSignedManifest:      true,
			CommunityVerifiedCount: 10,
			BattleTestedTxCount:    100000,
			SimulationMatchCount:   500,
		},
		ComputeUnits: 200000,
		AccountWrites: 5,
		CPIHops:       3,
		SimulationBaseline: &SimulationBaseline{
			MeanComputeUnits: 150000,
			StdComputeUnits:  20000,
			SampleCount:      500,
		},
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	simBase, ok := raw["simulation_baseline"].(map[string]interface{})
	if !ok {
		t.Fatal("expected simulation_baseline to be present as JSON object")
	}
	if simBase["sample_count"] != float64(500) {
		t.Errorf("expected sample_count=500, got %v", simBase["sample_count"])
	}

	var roundtrip VerificationInput
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if roundtrip.SimulationBaseline == nil {
		t.Fatal("expected SimulationBaseline after roundtrip")
	}
	if roundtrip.SimulationBaseline.SampleCount != 500 {
		t.Errorf("expected sample_count=500, got %d", roundtrip.SimulationBaseline.SampleCount)
	}
}

func TestByteArraySerialization(t *testing.T) {
	// Empty byte array
	empty := ByteArray{}
	data, _ := json.Marshal(empty)
	if string(data) != "[]" {
		t.Errorf("expected [], got %s", string(data))
	}

	// Non-empty byte array — must be [0, 1, 2, ...] NOT base64
	ba := ByteArray{0, 1, 2, 255}
	data, _ = json.Marshal(ba)
	if string(data) != "[0,1,2,255]" {
		t.Errorf("expected [0,1,2,255], got %s", string(data))
	}

	// Roundtrip
	var roundtrip ByteArray
	json.Unmarshal(data, &roundtrip)
	if len(roundtrip) != 4 || roundtrip[3] != 255 {
		t.Error("ByteArray roundtrip failed")
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
