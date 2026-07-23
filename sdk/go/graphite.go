// Package graphite provides a Go SDK for the Graphite transaction verification engine.
//
// Graphite verifies that Solana transactions constructed by AI agents actually
// do what was declared, with a falsifiable confidence score.
//
// Usage:
//   client := graphite.NewClient("http://localhost:8080")
//   result, err := client.Verify(input)
//
// This SDK communicates with the Graphite Core HTTP server (Rust/axum).
// It does NOT make any security decisions — all verification happens in Core.
package graphite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Client is the Graphite Core HTTP client.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a new Graphite client pointing at the Core server.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ProposedIntent is the natural language intent declaration.
type ProposedIntent struct {
	IntentType          string               `json:"intent_type"`
	RawNaturalLanguage  string               `json:"raw_natural_language"`
	ConfidenceOfParse  float64              `json:"confidence_of_parse"`
	ExtractedParameters *ExtractedParameters `json:"extracted_parameters,omitempty"`
}

// ExtractedParameters holds parsed intent data.
type ExtractedParameters struct {
	InputToken  string `json:"input_token,omitempty"`
	OutputToken string `json:"output_token,omitempty"`
	Amount      string `json:"amount,omitempty"`
	SlippageBPS *int64 `json:"slippage_bps,omitempty"`
}

// BehaviorEvidence is the on-chain behavioral evidence for the program.
type BehaviorEvidence struct {
	HasSignedManifest      bool `json:"has_signed_manifest"`
	CommunityVerifiedCount int  `json:"community_verified_count"`
	BattleTestedTxCount    int  `json:"battle_tested_tx_count"`
	SimulationMatchCount   int  `json:"simulation_match_count"`
}

// SimulationBaseline is the historical compute usage baseline for a program.
type SimulationBaseline struct {
	MeanComputeUnits float64 `json:"mean_compute_units"`
	StdComputeUnits  float64 `json:"std_compute_units"`
	SampleCount      uint64  `json:"sample_count"`
}

// ByteArray is a []byte that marshals as a JSON array of integers, NOT base64.
// This is critical: Rust's serde expects Vec<u8> as [0, 1, 2, ...], not as a base64 string.
type ByteArray []byte

// MarshalJSON encodes the byte slice as a JSON array of unsigned 8-bit integers.
func (b ByteArray) MarshalJSON() ([]byte, error) {
	if len(b) == 0 {
		return []byte("[]"), nil
	}
	result := make([]byte, 0, len(b)*4+2)
	result = append(result, '[')
	for i, v := range b {
		if i > 0 {
			result = append(result, ',')
		}
		result = strconv.AppendUint(result, uint64(v), 10)
	}
	result = append(result, ']')
	return result, nil
}

// UnmarshalJSON decodes a JSON array of integers back to a byte slice.
func (b *ByteArray) UnmarshalJSON(data []byte) error {
	var arr []interface{}
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	result := make(ByteArray, 0, len(arr))
	for _, v := range arr {
		f, ok := v.(float64)
		if !ok {
			return fmt.Errorf("ByteArray: expected number, got %T", v)
		}
		if f < 0 || f > 255 {
			return fmt.Errorf("ByteArray: value %v out of byte range", f)
		}
		result = append(result, byte(f))
	}
	*b = result
	return nil
}

// WalletProfile is the risk tolerance profile for policy evaluation.
type WalletProfile string

const (
	WalletProfileConservative WalletProfile = "Conservative"
	WalletProfileStandard      WalletProfile = "Standard"
	WalletProfilePermissive    WalletProfile = "Permissive"
	WalletProfileEnterprise    WalletProfile = "Enterprise"
)

// VerificationInput is the full input to the verification pipeline.
// This struct MUST match the Rust server's VerificationInput exactly.
type VerificationInput struct {
	ProposedIntent          ProposedIntent       `json:"proposed_intent"`
	ProgramID                string               `json:"program_id"`
	ProtocolVersion          string               `json:"protocol_version"`
	InstructionDiscriminator string               `json:"instruction_discriminator"`
	AccountAddresses        []string             `json:"account_addresses"`
	InstructionData         ByteArray             `json:"instruction_data,omitempty"`
	CPITargets              []string             `json:"cpi_targets,omitempty"`
	WalletProfile           WalletProfile        `json:"wallet_profile"`
	BehaviorEvidence        BehaviorEvidence     `json:"behavior_evidence"`
	ComputeUnits            uint64               `json:"compute_units"`
	AccountWrites           uint32               `json:"account_writes"`
	CPIHops                 uint32               `json:"cpi_hops"`
	SimulationBaseline      *SimulationBaseline  `json:"simulation_baseline,omitempty"`
}

// ─── Result types (must match Rust VerificationResult exactly) ───

// VerificationResult is the output of the verification pipeline.
type VerificationResult struct {
	Approved             bool                       `json:"approved"`
	Confidence           float64                    `json:"confidence"`
	Breakdown            []VerificationBreakdownItem `json:"breakdown"`
	TrustTier            string                     `json:"trust_tier"`
	RiskVerdict          RiskVerdictSummary         `json:"risk_verdict"`
	PolicyVerdict        string                     `json:"policy_verdict"`
	AuditTrailID         string                     `json:"audit_trail_id"`
	Transaction          BuiltTransaction           `json:"transaction"`
	ResolvedAccounts     []ResolvedAccount          `json:"resolved_accounts"`
	ProtocolName         string                     `json:"protocol_name"`
	InstructionName      string                     `json:"instruction_name"`
	ManifestFound        bool                       `json:"manifest_found"`
	UnknownProtocol      bool                       `json:"unknown_protocol"`
	SimulationFlagged    *bool                      `json:"simulation_flagged,omitempty"`
	SimulationDivergence *float64                   `json:"simulation_divergence,omitempty"`
	Summary              string                     `json:"summary"`
}

// VerificationBreakdownItem is a single confidence signal contribution.
type VerificationBreakdownItem struct {
	Kind        string  `json:"kind"`
	RawValue    float64 `json:"raw_value"`
	Weight      float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
}

// BuiltTransaction is the decoded transaction structure.
type BuiltTransaction struct {
	ProgramID             string             `json:"program_id"`
	ProtocolVersion       string             `json:"protocol_version"`
	InstructionName       string             `json:"instruction_name"`
	InstructionDiscriminator string          `json:"instruction_discriminator"`
	InstructionCount      int               `json:"instruction_count"`
	AccountCount          int               `json:"account_count"`
	SignerCount           int               `json:"signer_count"`
	WritableCount         int               `json:"writable_count"`
	ComputeBudgetUnits    uint64            `json:"compute_budget_units"`
	Accounts              []BuiltAccountMeta `json:"accounts"`
	DataHex               string            `json:"data_hex"`
	DataLen               int               `json:"data_len"`
}

// BuiltAccountMeta is a single account in a built transaction.
type BuiltAccountMeta struct {
	Address    string `json:"address"`
	IsSigner   bool   `json:"is_signer"`
	IsWritable bool   `json:"is_writable"`
}

// ResolvedAccount is a resolved account with PDA verification status.
type ResolvedAccount struct {
	Address     string   `json:"address"`
	Role        string   `json:"role"`
	IsPDA       bool     `json:"is_pda"`
	IsSigner    bool     `json:"is_signer"`
	IsWritable  bool     `json:"is_writable"`
	PDASeeds    []string `json:"pda_seeds"`
	PDAMismatch bool     `json:"pda_mismatch"`
}

// RiskVerdictSummary is the risk assessment result.
type RiskVerdictSummary struct {
	Status   string        `json:"status"`
	Findings []RiskFinding `json:"findings"`
}

// RiskFinding is a single risk detection.
type RiskFinding struct {
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
}

// ─── Client methods ───

// Verify sends a verification request to the Graphite Core server.
func (c *Client) Verify(input *VerificationInput) (*VerificationResult, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}

	resp, err := c.HTTPClient.Post(
		c.BaseURL+"/verify",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result VerificationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

// Health checks if the Core server is running.
func (c *Client) Health() error {
	resp, err := c.HTTPClient.Get(c.BaseURL + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: status %d", resp.StatusCode)
	}
	return nil
}

// ListManifests returns all loaded protocol manifests.
func (c *Client) ListManifests() ([]map[string]interface{}, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + "/manifests")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var manifests []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&manifests); err != nil {
		return nil, err
	}
	return manifests, nil
}
