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
	ConfidenceOfParse   float64              `json:"confidence_of_parse"`
	ExtractedParameters *ExtractedParameters `json:"extracted_parameters,omitempty"`
}

// ExtractedParameters holds parsed intent data.
type ExtractedParameters struct {
	InputToken  string `json:"input_token,omitempty"`
	OutputToken string `json:"output_token,omitempty"`
	Amount      string `json:"amount,omitempty"`
	SlippageBPS *int64 `json:"slippage_bps,omitempty"`
}

// VerificationInput is the full input to the verification pipeline.
type VerificationInput struct {
	ProposedIntent          ProposedIntent `json:"proposed_intent"`
	ProgramID               string         `json:"program_id"`
	ProtocolVersion         string         `json:"protocol_version"`
	InstructionDiscriminator string       `json:"instruction_discriminator"`
	AccountAddresses        []string       `json:"account_addresses"`
	InstructionData         []byte         `json:"instruction_data,omitempty"`
	CPITargets              []string       `json:"cpi_targets,omitempty"`
	WalletProfile           string         `json:"wallet_profile"`
	ComputeUnits            uint64         `json:"compute_units"`
	AccountWrites           uint32         `json:"account_writes"`
	CPIHops                 uint32         `json:"cpi_hops"`
}

// VerificationResult is the output of the verification pipeline.
type VerificationResult struct {
	Approved              bool               `json:"approved"`
	Confidence            float64            `json:"confidence"`
	TrustTier             string             `json:"trust_tier"`
	RiskVerdict           RiskVerdictSummary `json:"risk_verdict"`
	PolicyVerdict         string             `json:"policy_verdict"`
	AuditTrailID          string             `json:"audit_trail_id"`
	ProtocolName          string             `json:"protocol_name"`
	InstructionName       string             `json:"instruction_name"`
	ManifestFound         bool               `json:"manifest_found"`
	UnknownProtocol       bool               `json:"unknown_protocol"`
	SimulationFlagged     *bool              `json:"simulation_flagged,omitempty"`
	SimulationDivergence  *float64           `json:"simulation_divergence,omitempty"`
	Summary               string             `json:"summary"`
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
