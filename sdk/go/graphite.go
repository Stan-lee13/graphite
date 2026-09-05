// Package graphite provides a Go SDK for the Graphite transaction verification engine.
//
// Graphite verifies that Solana transactions constructed by AI agents actually
// do what was declared, with a falsifiable confidence score.
//
// Gating a transaction safely — the complete pattern. Every step matters; the
// short version that omits them is how integrations end up insecure.
//
//	client := graphite.NewClientWithAPIKey("https://graphite.internal", apiKey)
//
//	result, err := client.Verify(input)
//	if err != nil {
//	    // A transport error, timeout, or non-200 means VERIFICATION DID NOT
//	    // HAPPEN. It is never an implicit pass — abort.
//	    return fmt.Errorf("graphite verification unavailable: %w", err)
//	}
//
//	// Approved is the ONLY field to gate execution on. Everything else —
//	// Confidence, PolicyVerdict, RiskVerdict — is evidence for audit and
//	// explanation, not a decision.
//	if !result.Approved {
//	    return fmt.Errorf("blocked by Graphite: %s", result.Summary)
//	}
//
//	// Bind what was verified to what you are about to submit. Graphite
//	// verifies BEFORE signing, so without this the instruction can still be
//	// mutated in between (compromised RPC proxy, malicious wallet adapter, a
//	// race in your own pipeline) and the verification would not have covered
//	// the bytes that actually execute.
//	if err := graphite.VerifyInstruction(programID, data, accounts, result.ContentHash); err != nil {
//	    return err // mutated between verification and submission — do not sign
//	}
//
//	// ...only now sign and submit.
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
	// APIKey is the Bearer token for a secured Core server (GRAPHITE_API_KEY).
	// When non-empty, Verify and ListManifests send
	// `Authorization: Bearer <APIKey>`. /health stays open by design.
	APIKey string
}

// NewClient creates a new Graphite client pointing at the Core server
// (no API key — for keyless dev deployments).
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewClientWithAPIKey creates a client for a secured Core deployment. The key
// is sent as `Authorization: Bearer <key>` on every authenticated request.
func NewClientWithAPIKey(baseURL, apiKey string) *Client {
	c := NewClient(baseURL)
	c.APIKey = apiKey
	return c
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

// BehaviorEvidence is the on-chain behavioral evidence for the program.
type BehaviorEvidence struct {
	HasSignedManifest      bool `json:"has_signed_manifest"`
	CommunityVerifiedCount int  `json:"community_verified_count"`
	BattleTestedTxCount    int  `json:"battle_tested_tx_count"`
	SimulationMatchCount   int  `json:"simulation_match_count"`
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
	WalletProfileTreasury   WalletProfile = "Treasury"
	WalletProfileTradingBot WalletProfile = "TradingBot"
	WalletProfileGaming     WalletProfile = "Gaming"
	WalletProfileEnterprise WalletProfile = "Enterprise"
)

// VerificationInput is the full input to the verification pipeline.
// This struct MUST match the Rust server's VerificationInput exactly.
type VerificationInput struct {
	ProposedIntent           ProposedIntent   `json:"proposed_intent"`
	ProgramID                string           `json:"program_id"`
	ProtocolVersion          string           `json:"protocol_version"`
	InstructionDiscriminator string           `json:"instruction_discriminator"`
	AccountAddresses         []string         `json:"account_addresses"`
	InstructionData          ByteArray        `json:"instruction_data,omitempty"`
	CPITargets               []string         `json:"cpi_targets,omitempty"`
	WalletProfile            WalletProfile    `json:"wallet_profile"`
	BehaviorEvidence         BehaviorEvidence `json:"behavior_evidence"`
	ComputeUnits             uint64           `json:"compute_units"`
	AccountWrites            uint32           `json:"account_writes"`
	CPIHops                  uint32           `json:"cpi_hops"`
	// SignedTransaction is the optional fully-signed transaction blob (JSON
	// array of bytes, NOT base64 — serde Vec<u8>). The Core simulates this
	// exact blob for the most accurate L3 result.
	SignedTransaction ByteArray `json:"signed_transaction,omitempty"`
	// TransactionInstructions is the Phase 2 COMPLETE instruction list (2+
	// entries trigger multi-instruction mass-drain pattern analysis).
	TransactionInstructions []TransactionInstruction `json:"transaction_instructions,omitempty"`
	// CpiTrace is the Phase 2 hierarchical CPI trace tree of the primary
	// instruction (depth 0 = root).
	CpiTrace *CpiTraceNode `json:"cpi_trace,omitempty"`
	// UsesVersionedTransaction declares (P1, 2026-09-05) that the underlying
	// transaction is a versioned (v0) message resolving one or more accounts
	// through Address Lookup Tables. Graphite cannot detect this itself —
	// when true, surfaces a non-blocking warning that ALT-resolved accounts
	// were not independently verified. Never reduces confidence or blocks.
	UsesVersionedTransaction bool `json:"uses_versioned_transaction,omitempty"`
	// LookupTableCount is the number of distinct Address Lookup Tables
	// referenced, if known. Purely informational.
	LookupTableCount uint32 `json:"lookup_table_count,omitempty"`
	// RealAccountMetas holds the REAL per-account signer/writable bits from
	// the actual transaction, in the same order as AccountAddresses, when
	// the caller has them (P1, 2026-09-05). Cross-checked against the
	// manifest's declared expectations — see ResolvedAccount.PrivilegeMismatch.
	// Omitted/empty (the common case) means "not supplied": nothing is
	// flagged, never silently assumed to match. A length mismatch against
	// AccountAddresses is treated the same way (fail-safe).
	RealAccountMetas []RealAccountMeta `json:"real_account_metas,omitempty"`
	// Simulation baselines are TRUSTED SERVER STATE (earned via RPC-verified
	// usage or seeded by the operator) — never sent from the client.
}

// RealAccountMeta is the real per-account signer/writable bits from an
// actual transaction. Mirrors graphite-core/src/account_resolution.rs
// RealAccountMeta.
type RealAccountMeta struct {
	IsSigner   bool `json:"is_signer"`
	IsWritable bool `json:"is_writable"`
}

// TransactionInstruction is a single compiled instruction in a transaction
// message (Phase 2 multi-instruction analysis). Mirrors
// graphite-core/src/tx_pattern_analysis.rs TransactionInstruction.
type TransactionInstruction struct {
	ProgramID                string   `json:"program_id"`
	InstructionDiscriminator string   `json:"instruction_discriminator,omitempty"`
	AccountAddresses         []string `json:"account_addresses,omitempty"`
	CPITargets               []string `json:"cpi_targets,omitempty"`
}

// CpiTraceNode is a node in the hierarchical CPI trace tree (depth 0 = root).
// Mirrors graphite-core/src/tx_pattern_analysis.rs CpiTraceNode.
type CpiTraceNode struct {
	ProgramID                string         `json:"program_id"`
	InstructionDiscriminator string         `json:"instruction_discriminator,omitempty"`
	Depth                    uint32         `json:"depth"`
	AccountAddresses         []string       `json:"account_addresses,omitempty"`
	Children                 []CpiTraceNode `json:"children,omitempty"`
}

// ─── Result types (must match Rust VerificationResult exactly) ───

// VerificationResult is the output of the verification pipeline.
type VerificationResult struct {
	Approved         bool                        `json:"approved"`
	Confidence       float64                     `json:"confidence"`
	Breakdown        []VerificationBreakdownItem `json:"breakdown"`
	TrustTier        string                      `json:"trust_tier"`
	RiskVerdict      RiskVerdictSummary          `json:"risk_verdict"`
	PolicyVerdict    string                      `json:"policy_verdict"`
	AuditTrailID     string                      `json:"audit_trail_id"`
	ContentHash      string                      `json:"content_hash"`
	Transaction      BuiltTransaction            `json:"transaction"`
	ResolvedAccounts []ResolvedAccount           `json:"resolved_accounts"`
	ProtocolName     string                      `json:"protocol_name"`
	InstructionName  string                      `json:"instruction_name"`
	ManifestFound    bool                        `json:"manifest_found"`
	UnknownProtocol  bool                        `json:"unknown_protocol"`
	// ManifestVersion is the version label of the protocol manifest this result
	// was checked against (nil for unknown protocols). Constitution G7 — lets a
	// consumer confirm which manifest version produced the verification.
	ManifestVersion      *string               `json:"manifest_version,omitempty"`
	SimulationFlagged    *bool                 `json:"simulation_flagged,omitempty"`
	SimulationDivergence *float64              `json:"simulation_divergence,omitempty"`
	Summary              string                `json:"summary"`
	Layers               []PipelineLayerResult `json:"layers,omitempty"`
}

// PipelineLayerResult tracks the status of each layer in the 8-layer pipeline.
// Status is the tri-state truth (passed | failed | inconclusive); Passed is
// derived from it (only "passed" yields true) — GAP-2026-08-06-3.
type PipelineLayerResult struct {
	Layer  string `json:"layer"`
	Passed bool   `json:"passed"`
	Status string `json:"status,omitempty"`
	Reason string `json:"reason"`
}

// VerificationBreakdownItem is a single confidence signal contribution.
type VerificationBreakdownItem struct {
	Kind         string  `json:"kind"`
	RawValue     float64 `json:"raw_value"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
}

// BuiltTransaction is the decoded transaction structure.
type BuiltTransaction struct {
	ProgramID                string             `json:"program_id"`
	ProtocolVersion          string             `json:"protocol_version"`
	InstructionName          string             `json:"instruction_name"`
	InstructionDiscriminator string             `json:"instruction_discriminator"`
	InstructionCount         int                `json:"instruction_count"`
	AccountCount             int                `json:"account_count"`
	SignerCount              int                `json:"signer_count"`
	WritableCount            int                `json:"writable_count"`
	ComputeBudgetUnits       uint64             `json:"compute_budget_units"`
	Accounts                 []BuiltAccountMeta `json:"accounts"`
	DataHex                  string             `json:"data_hex"`
	DataLen                  int                `json:"data_len"`
}

// BuiltAccountMeta is a single account in a built transaction.
type BuiltAccountMeta struct {
	Address    string `json:"address"`
	IsSigner   bool   `json:"is_signer"`
	IsWritable bool   `json:"is_writable"`
}

// AccountIdentity describes how an account's identity is verified: "Pda"
// (re-derived from the manifest's seed template), "Constant" (matched
// against a manifest-declared fixed address), or "Unverified" (genuinely
// externally-determined — no PDA formula, no fixed constant). Mirrors
// graphite-core/src/account_resolution.rs AccountIdentity.
type AccountIdentity string

const (
	AccountIdentityPda        AccountIdentity = "Pda"
	AccountIdentityConstant   AccountIdentity = "Constant"
	AccountIdentityUnverified AccountIdentity = "Unverified"
)

// ResolvedAccount is a resolved account with identity verification status.
type ResolvedAccount struct {
	Address     string          `json:"address"`
	Role        string          `json:"role"`
	IsPDA       bool            `json:"is_pda"`
	IsSigner    bool            `json:"is_signer"`
	IsWritable  bool            `json:"is_writable"`
	PDASeeds    []string        `json:"pda_seeds"`
	Identity    AccountIdentity `json:"identity"`
	PDAMismatch bool            `json:"pda_mismatch"`
	// ExpectedAddressMismatch is true if a manifest-declared expected_address
	// constant (e.g. the SPL Token program) does not match the provided
	// address — an attacker substituting a lookalike program.
	ExpectedAddressMismatch bool `json:"expected_address_mismatch"`
	// PrivilegeMismatch is true (P1, 2026-09-05) if a caller-supplied
	// RealAccountMeta for this position disagrees with the manifest's
	// declared expectation in a security-relevant direction: a required
	// signer that the real transaction did not sign, or a manifest-readonly
	// slot the real transaction marks writable (privilege escalation). The
	// reverse (more-restrictive) directions are never flagged, and absence
	// of RealAccountMetas leaves this honestly false ("not checked").
	PrivilegeMismatch bool `json:"privilege_mismatch"`
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

// ProtocolManifest is a protocol manifest served by Core's /manifests endpoint.
// Field parity with the TypeScript SDK's ProtocolManifest interface and the
// Rust ProtocolManifest struct (graphite-core/src/manifest.rs).
type ProtocolManifest struct {
	GraphiteManifestVersion string                `json:"graphite_manifest_version"`
	Protocol                ManifestProtocol      `json:"protocol"`
	Version                 ManifestVersion       `json:"version"`
	Instructions            []ManifestInstruction `json:"instructions"`
	TrustTier               string                `json:"trust_tier"`
}

// ManifestProtocol identifies the program a manifest describes.
type ManifestProtocol struct {
	Name      string `json:"name"`
	ProgramID string `json:"program_id"`
	Website   string `json:"website,omitempty"`
	Github    string `json:"github,omitempty"`
	Category  string `json:"category,omitempty"`
}

// ManifestVersion is the version label of a protocol manifest.
type ManifestVersion struct {
	Label              string  `json:"label"`
	EffectiveFromSlot  uint64  `json:"effective_from_slot"`
	PreviousVersionRef *string `json:"previous_version_ref,omitempty"`
}

// ManifestInstruction is a single instruction definition in a manifest.
type ManifestInstruction struct {
	Name                 string                `json:"name"`
	Discriminator        string                `json:"discriminator"`
	Accounts             []ManifestAccountRole `json:"accounts"`
	ExpectedStateChanges []string              `json:"expected_state_changes"`
	AllowedCPIs          []string              `json:"allowed_cpis"`
	RiskRules            []string              `json:"risk_rules"`
}

// ManifestAccountRole is a single account role definition in a manifest.
type ManifestAccountRole struct {
	Name       string   `json:"name"`
	Role       string   `json:"role"`
	IsWritable bool     `json:"is_writable"`
	IsSigner   bool     `json:"is_signer"`
	PDASeeds   []string `json:"pda_seeds,omitempty"`
}

// ─── Client methods ───

// Verify sends a verification request to the Graphite Core server.
func (c *Client) Verify(input *VerificationInput) (*VerificationResult, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/verify", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)

	resp, err := c.HTTPClient.Do(req)
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

// ListManifests returns all loaded protocol manifests, typed.
func (c *Client) ListManifests() ([]ProtocolManifest, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/manifests", nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var manifests []ProtocolManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifests); err != nil {
		return nil, err
	}
	return manifests, nil
}

// setAuth attaches the Bearer API key when one is configured.
func (c *Client) setAuth(req *http.Request) {
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
}
