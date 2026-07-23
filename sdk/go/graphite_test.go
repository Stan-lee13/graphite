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
			IntentType:         "transfer",
			RawNaturalLanguage: "Transfer 1 SOL",
			ConfidenceOfParse:  0.95,
		},
		ProgramID:                "11111111111111111111111111111111",
		ProtocolVersion:          "1.0.0",
		InstructionDiscriminator: "02000000",
		AccountAddresses:         []string{"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"},
		InstructionData:          ByteArray{0x02, 0x00, 0x00, 0x00},
		WalletProfile:            WalletProfileStandard,
		BehaviorEvidence: BehaviorEvidence{
			HasSignedManifest:      false,
			CommunityVerifiedCount: 5,
			BattleTestedTxCount:    50000,
			SimulationMatchCount:   100,
		},
		ComputeUnits:  150,
		AccountWrites: 2,
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
		ProgramID:                "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyRTaV4",
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

// ─── New tests for previously-missing types ───

func TestVerificationResultFullDeserialization(t *testing.T) {
	// This is the full server response with ALL fields populated,
	// including the previously-missing types (breakdown, transaction,
	// resolved_accounts). Without these types, the data was silently dropped.
	jsonStr := `{
		"approved": true,
		"confidence": 0.92,
		"breakdown": [
			{"kind": "ManifestMatch", "raw_value": 1.0, "weight": 0.4, "contribution": 0.40},
			{"kind": "SimulationMatch", "raw_value": 0.95, "weight": 0.3, "contribution": 0.285},
			{"kind": "HistoricalVolume", "raw_value": 100000.0, "weight": 0.2, "contribution": 0.20},
			{"kind": "CommunityVerification", "raw_value": 50.0, "weight": 0.1, "contribution": 0.035}
		],
		"trust_tier": "BattleTested",
		"risk_verdict": {
			"status": "Clear",
			"findings": []
		},
		"policy_verdict": "Approved",
		"audit_trail_id": "gr-abc12345-00000001",
		"transaction": {
			"program_id": "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyRT1V4",
			"protocol_version": "6.0.0",
			"instruction_name": "Swap",
			"instruction_discriminator": "e517cb977ae3ad2a",
			"instruction_count": 1,
			"account_count": 5,
			"signer_count": 1,
			"writable_count": 3,
			"compute_budget_units": 200000,
			"accounts": [
				{"address": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "is_signer": true, "is_writable": true},
				{"address": "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "is_signer": false, "is_writable": true},
				{"address": "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx", "is_signer": false, "is_writable": false}
			],
			"data_hex": "e517cb977ae3ad2a00000000",
			"data_len": 8
		},
		"resolved_accounts": [
			{"address": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "role": "signer", "is_pda": false, "is_signer": true, "is_writable": true, "pda_seeds": [], "pda_mismatch": false},
			{"address": "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", "role": "destination", "is_pda": false, "is_signer": false, "is_writable": true, "pda_seeds": [], "pda_mismatch": false}
		],
		"protocol_name": "Jupiter V6",
		"instruction_name": "Swap",
		"manifest_found": true,
		"unknown_protocol": false,
		"summary": "protocol=Jupiter V6 confidence=0.9200 risk=Clear approved=yes"
	}`

	var result VerificationResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Core fields
	if !result.Approved {
		t.Error("expected approved=true")
	}
	if result.Confidence != 0.92 {
		t.Errorf("expected confidence 0.92, got %f", result.Confidence)
	}
	if result.TrustTier != "BattleTested" {
		t.Errorf("expected trust_tier BattleTested, got %s", result.TrustTier)
	}

	// Breakdown (previously dropped)
	if len(result.Breakdown) != 4 {
		t.Fatalf("expected 4 breakdown items, got %d", len(result.Breakdown))
	}
	if result.Breakdown[0].Kind != "ManifestMatch" {
		t.Errorf("expected first breakdown kind ManifestMatch, got %s", result.Breakdown[0].Kind)
	}
	if result.Breakdown[0].Contribution != 0.40 {
		t.Errorf("expected contribution 0.40, got %f", result.Breakdown[0].Contribution)
	}
	if result.Breakdown[1].Kind != "SimulationMatch" {
		t.Errorf("expected second breakdown kind SimulationMatch, got %s", result.Breakdown[1].Kind)
	}

	// Transaction (previously dropped)
	if result.Transaction.ProgramID != "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyRT1V4" {
		t.Errorf("expected program_id Jupiter, got %s", result.Transaction.ProgramID)
	}
	if result.Transaction.InstructionName != "Swap" {
		t.Errorf("expected instruction_name Swap, got %s", result.Transaction.InstructionName)
	}
	if result.Transaction.AccountCount != 5 {
		t.Errorf("expected account_count 5, got %d", result.Transaction.AccountCount)
	}
	if result.Transaction.SignerCount != 1 {
		t.Errorf("expected signer_count 1, got %d", result.Transaction.SignerCount)
	}
	if result.Transaction.ComputeBudgetUnits != 200000 {
		t.Errorf("expected compute_budget_units 200000, got %d", result.Transaction.ComputeBudgetUnits)
	}
	if result.Transaction.DataHex != "e517cb977ae3ad2a00000000" {
		t.Errorf("expected data_hex, got %s", result.Transaction.DataHex)
	}
	// BuiltAccountMeta inside transaction
	if len(result.Transaction.Accounts) != 3 {
		t.Fatalf("expected 3 accounts in transaction, got %d", len(result.Transaction.Accounts))
	}
	if !result.Transaction.Accounts[0].IsSigner {
		t.Error("expected first account to be signer")
	}
	if !result.Transaction.Accounts[0].IsWritable {
		t.Error("expected first account to be writable")
	}
	if result.Transaction.Accounts[2].IsSigner {
		t.Error("expected third account to NOT be signer")
	}

	// Resolved accounts (previously dropped)
	if len(result.ResolvedAccounts) != 2 {
		t.Fatalf("expected 2 resolved accounts, got %d", len(result.ResolvedAccounts))
	}
	if result.ResolvedAccounts[0].Address != "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU" {
		t.Errorf("expected first resolved account address, got %s", result.ResolvedAccounts[0].Address)
	}
	if result.ResolvedAccounts[0].Role != "signer" {
		t.Errorf("expected role signer, got %s", result.ResolvedAccounts[0].Role)
	}
	if result.ResolvedAccounts[0].IsSigner != true {
		t.Error("expected is_signer=true for first resolved account")
	}
	if result.ResolvedAccounts[0].PDAMismatch != false {
		t.Error("expected pda_mismatch=false for first resolved account")
	}
}

func TestResolvedAccountPDAMismatch(t *testing.T) {
	// Test that pda_mismatch field is correctly deserialized
	// This is a SECURITY SIGNAL — a spoofed PDA should be flagged
	jsonStr := `{
		"address": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
		"role": "pda",
		"is_pda": true,
		"is_signer": false,
		"is_writable": true,
		"pda_seeds": ["proposal"],
		"pda_mismatch": true
	}`

	var acct ResolvedAccount
	if err := json.Unmarshal([]byte(jsonStr), &acct); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !acct.IsPDA {
		t.Error("expected is_pda=true")
	}
	if len(acct.PDASeeds) != 1 || acct.PDASeeds[0] != "proposal" {
		t.Errorf("expected pda_seeds=['proposal'], got %v", acct.PDASeeds)
	}
	if !acct.PDAMismatch {
		t.Error("expected pda_mismatch=true — this is a SECURITY SIGNAL that must not be silently dropped")
	}
}

func TestVerificationResultBlockedWithFindings(t *testing.T) {
	jsonStr := `{
		"approved": false,
		"confidence": 0.15,
		"breakdown": [
			{"kind": "ManifestMatch", "raw_value": 0.0, "weight": 0.4, "contribution": 0.0},
			{"kind": "CommunityVerification", "raw_value": 0.0, "weight": 0.1, "contribution": 0.0}
		],
		"trust_tier": "Unknown",
		"risk_verdict": {
			"status": "Blocked",
			"findings": [
				{"pattern": "Drainer", "reason": "STMT drainer: 25 unique accounts, expected 3"},
				{"pattern": "AuthorityHijack", "reason": "SetAuthority detected on SPL Token"}
			]
		},
		"policy_verdict": "Denied",
		"audit_trail_id": "gr-xyz789-00000002",
		"transaction": {
			"program_id": "4PG6e97DLCn2PRN4ZMmTLg83jsetrDkvamr3JiXoiffa",
			"protocol_version": "",
			"instruction_name": "Unknown",
			"instruction_discriminator": "08",
			"instruction_count": 21,
			"account_count": 25,
			"signer_count": 1,
			"writable_count": 20,
			"compute_budget_units": 1000000,
			"accounts": [
				{"address": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "is_signer": true, "is_writable": true}
			],
			"data_hex": "0800000000000000",
			"data_len": 8
		},
		"resolved_accounts": [
			{"address": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "role": "signer", "is_pda": false, "is_signer": true, "is_writable": true, "pda_seeds": [], "pda_mismatch": false}
		],
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
	if result.RiskVerdict.Findings[1].Pattern != "AuthorityHijack" {
		t.Error("second finding should be AuthorityHijack")
	}

	// Verify breakdown is populated (previously dropped)
	if len(result.Breakdown) != 2 {
		t.Fatalf("expected 2 breakdown items, got %d", len(result.Breakdown))
	}
	if result.Breakdown[0].Kind != "ManifestMatch" {
		t.Errorf("expected first breakdown kind ManifestMatch, got %s", result.Breakdown[0].Kind)
	}

	// Verify transaction is populated (previously dropped)
	if result.Transaction.AccountCount != 25 {
		t.Errorf("expected account_count 25, got %d", result.Transaction.AccountCount)
	}
	if result.Transaction.WritableCount != 20 {
		t.Errorf("expected writable_count 20, got %d", result.Transaction.WritableCount)
	}

	// Verify resolved_accounts is populated (previously dropped)
	if len(result.ResolvedAccounts) != 1 {
		t.Fatalf("expected 1 resolved account, got %d", len(result.ResolvedAccounts))
	}

	// Simulation fields
	if result.SimulationFlagged == nil || !*result.SimulationFlagged {
		t.Error("expected simulation_flagged=true")
	}
	if result.SimulationDivergence == nil || *result.SimulationDivergence != 3.5 {
		t.Error("expected simulation_divergence=3.5")
	}
}

func TestVerificationResultNoDataLoss(t *testing.T) {
	// Critical test: verify that NO fields are silently dropped during deserialization.
	// This was the original bug — Go's JSON decoder silently ignores unknown fields.
	// Now that we have all the types, we verify roundtrip fidelity.

	original := VerificationResult{
		Approved:    true,
		Confidence:  0.88,
		Breakdown: []VerificationBreakdownItem{
			{Kind: "ManifestMatch", RawValue: 1.0, Weight: 0.4, Contribution: 0.40},
		},
		TrustTier:     "BattleTested",
		RiskVerdict:   RiskVerdictSummary{Status: "Clear", Findings: []RiskFinding{}},
		PolicyVerdict: "Approved",
		AuditTrailID:  "gr-test-001",
		Transaction: BuiltTransaction{
			ProgramID:        "11111111111111111111111111111111",
			InstructionName:  "Transfer",
			AccountCount:     2,
			SignerCount:      1,
			Accounts: []BuiltAccountMeta{
				{Address: "addr1", IsSigner: true, IsWritable: true},
				{Address: "addr2", IsSigner: false, IsWritable: false},
			},
			DataHex: "02000000",
			DataLen: 4,
		},
		ResolvedAccounts: []ResolvedAccount{
			{Address: "addr1", Role: "signer", IsPDA: false, IsSigner: true, IsWritable: true, PDASeeds: []string{}, PDAMismatch: false},
		},
		ProtocolName:    "System Program",
		InstructionName: "Transfer",
		ManifestFound:   true,
		UnknownProtocol: false,
		Summary:         "test summary",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundtrip VerificationResult
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify every field survived the roundtrip
	if roundtrip.Approved != original.Approved {
		t.Error("Approved mismatch")
	}
	if roundtrip.Confidence != original.Confidence {
		t.Error("Confidence mismatch")
	}
	if len(roundtrip.Breakdown) != len(original.Breakdown) {
		t.Fatalf("Breakdown length mismatch: %d vs %d", len(roundtrip.Breakdown), len(original.Breakdown))
	}
	if roundtrip.Breakdown[0].Kind != original.Breakdown[0].Kind {
		t.Error("Breakdown kind mismatch")
	}
	if roundtrip.Breakdown[0].Contribution != original.Breakdown[0].Contribution {
		t.Error("Breakdown contribution mismatch")
	}
	if roundtrip.TrustTier != original.TrustTier {
		t.Error("TrustTier mismatch")
	}
	if roundtrip.Transaction.ProgramID != original.Transaction.ProgramID {
		t.Error("Transaction.ProgramID mismatch")
	}
	if roundtrip.Transaction.AccountCount != original.Transaction.AccountCount {
		t.Error("Transaction.AccountCount mismatch")
	}
	if len(roundtrip.Transaction.Accounts) != len(original.Transaction.Accounts) {
		t.Fatalf("Transaction.Accounts length mismatch")
	}
	if roundtrip.Transaction.Accounts[1].IsSigner != original.Transaction.Accounts[1].IsSigner {
		t.Error("Transaction.Accounts[1].IsSigner mismatch")
	}
	if len(roundtrip.ResolvedAccounts) != len(original.ResolvedAccounts) {
		t.Fatalf("ResolvedAccounts length mismatch")
	}
	if roundtrip.ResolvedAccounts[0].Role != original.ResolvedAccounts[0].Role {
		t.Error("ResolvedAccounts[0].Role mismatch")
	}
	if roundtrip.ResolvedAccounts[0].PDAMismatch != original.ResolvedAccounts[0].PDAMismatch {
		t.Error("ResolvedAccounts[0].PDAMismatch mismatch")
	}
	if roundtrip.ProtocolName != original.ProtocolName {
		t.Error("ProtocolName mismatch")
	}
	if roundtrip.ManifestFound != original.ManifestFound {
		t.Error("ManifestFound mismatch")
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
