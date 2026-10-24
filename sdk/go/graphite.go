// Package graphite provides a Go SDK for the Graphite transaction verification engine.
//
// Graphite verifies that Solana transactions constructed by AI agents actually
// do what was declared, with a falsifiable confidence score.
//
// Gating a transaction safely — the complete pattern. Every step matters; the
// short version that omits them is how integrations end up insecure.
//
// Graphite verifies BEFORE signing, so what you send it is the transaction
// serialized with every signature slot empty (64 zero bytes each) — the
// unsigned artifact. The Core answers 400 to an artifact whose slots are
// filled: signed bytes mean the signing already happened. Round 19 (F-19-C3)
// rewrote this pattern around VerifyTransactionDigest, which binds the WHOLE
// transaction — fee payer, blockhash, signer set, header and every
// instruction — where VerifyInstruction binds one instruction and cannot see
// an appended one.
//
//	client := graphite.NewClientWithAPIKey("https://graphite.internal", apiKey)
//
//	unsigned := tx.SerializeUnsigned() // your library's serializer, slots zeroed
//	input.SignedTransaction = unsigned  // the field name predates the rule: UNSIGNED bytes
//	result, err := client.Verify(input)
//	if err != nil {
//	    // A transport error, timeout, refused base URL, or non-200 means
//	    // VERIFICATION DID NOT HAPPEN. It is never an implicit pass — abort.
//	    return fmt.Errorf("graphite verification unavailable: %w", err)
//	}
//
//	// IsExecutable is the gate (Round 30, G-01). Approved says the pipeline
//	// did not refuse; it never said the transaction may be signed — a Core
//	// without an RPC simulates nothing and its approvals carry
//	// not_simulated. IsExecutable recomputes the Core's rule from the
//	// verdict (approved, artifact-bound, simulated, nothing unobserved but
//	// the two inherent residuals, no failed layer) and requires the
//	// server's Decision to agree. Confidence, PolicyVerdict and RiskVerdict
//	// are evidence for audit and explanation, never a gate.
//	if !result.IsExecutable() {
//	    return fmt.Errorf("not executable (%s): %s", result.Decision, result.Summary)
//	}
//
//	// A deployment that has deliberately accepted a residual BY NAME (the
//	// bridge reads GRAPHITE_ACCEPT_UNOBSERVED) makes that decision in its
//	// own code, on an analysis_only approval, and logs it — IsExecutable
//	// never does:
//	//
//	//   codes, ok := result.NonInherentUnobserved()
//	//   if !ok { return errors.New("residuals without codes; refusing") }
//	//   for _, c := range codes { if !accepted[c] { return ... } }
//
//	// Bind the verdict to the exact transaction. VerifyTransactionDigest
//	// refuses anything but an approved, artifact-bound verdict (a nil or
//	// descriptive Scope is unknown, not safe), then recomputes
//	// Scope.TransactionSHA256 over the bytes you hold. Run it on the SIGNED
//	// bytes, immediately before submitting: signature slots are zeroed before
//	// hashing, so signing does not change the digest, and checking the bytes
//	// that will actually go out covers the window between verification and
//	// submission — a compromised RPC proxy, a malicious wallet adapter, a
//	// race in your own pipeline.
//	signed := sign(unsigned)
//	if err := graphite.VerifyTransactionDigest(signed, result); err != nil {
//	    return err // not the transaction Graphite approved — do not submit
//	}
//
//	// ...only now submit `signed`, and nothing else.
//
// A descriptive verdict (no SignedTransaction supplied) binds no transaction
// at all; VerifyTransactionDigest refuses it. If all you can supply is a
// description, VerifyInstructionWithDiscriminator binds the one instruction
// you described — pass the discriminator exactly as sent, which native
// programs require (System 4-byte tags, SPL Token 1-byte tags) — and
// everything else in the transaction is unexamined.
//
// This SDK communicates with the Graphite Core HTTP server (Rust/axum).
// It does NOT make any security decisions — all verification happens in Core.
package graphite

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client is the Graphite Core HTTP client.
//
// A Client literal works: a nil HTTPClient means the same client NewClient
// installs (DefaultTimeout, no redirects).
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	// APIKey is the Bearer token for a secured Core server (GRAPHITE_API_KEY).
	// When non-empty, every call but Health sends
	// `Authorization: Bearer <APIKey>`. /health stays open by design.
	APIKey string
}

// DefaultTimeout bounds every request of a client NewClient built, or of a
// Client literal with no HTTPClient. A timeout means VERIFICATION DID NOT
// HAPPEN: a hard stop, never an implicit pass.
const DefaultTimeout = 30 * time.Second

// newHTTPClient is the client NewClient installs.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       DefaultTimeout,
		CheckRedirect: refuseRedirect,
	}
}

// NewClient creates a new Graphite client pointing at the Core server
// (no API key — for keyless dev deployments).
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: newHTTPClient(),
	}
}

// refuseRedirect stops the client at the first redirect and hands the 3xx
// back, which every method then refuses (see do).
//
// A5-04 (2026-09-29 audit): CheckBaseURL is enforced on BaseURL, but the
// default client followed redirects, so a Core or a proxy answering 307 to an
// http:// URL had the request body and the Authorization header re-sent in
// cleartext, and the verdict read back over that hop was accepted. The Core's
// own RPC client refuses redirects (Round 12); so does this one.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// do sends req without following redirects, whatever HTTPClient a caller
// installed, and refuses a 3xx answer. HTTPClient is an exported field a
// caller can replace with one that follows redirects; the policy is applied
// to a copy per request rather than trusted to the field.
//
// Audit 2026-10-20: a nil HTTPClient (a `&graphite.Client{BaseURL: …}`
// literal) used http.DefaultClient, which has no timeout, so a hung Core hung
// Verify forever. It now gets NewClient's client: DefaultTimeout.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	noRedirect := *c.httpClient()
	noRedirect.CheckRedirect = refuseRedirect
	resp, err := noRedirect.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close()
		return nil, fmt.Errorf(
			"graphite: %s %s answered %d (redirect to %q); redirects are refused, because the "+
				"hop would bypass CheckBaseURL (A5-04)",
			req.Method, req.URL.Path, resp.StatusCode, resp.Header.Get("Location"))
	}
	return resp, nil
}

// httpClient is the client a request goes through: HTTPClient, or for a nil
// one NewClient's.
func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return newHTTPClient()
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
	Destination string `json:"destination,omitempty"`
	AccountType string `json:"account_type,omitempty"`
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
//
// Every element must be an integer from 0 to 255, written as one. Audit
// 2026-10-20: elements were read as float64 and truncated, so 1.5 decoded
// as 1 — a different byte from the one written, silently. serde reads a
// Vec<u8> the same strict way.
func (b *ByteArray) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var arr []interface{}
	if err := dec.Decode(&arr); err != nil {
		return err
	}
	result := make(ByteArray, 0, len(arr))
	for i, v := range arr {
		n, ok := v.(json.Number)
		if !ok {
			return fmt.Errorf("ByteArray: element %d: expected a number, got %T", i, v)
		}
		u, err := strconv.ParseUint(string(n), 10, 8)
		if err != nil {
			return fmt.Errorf("ByteArray: element %d: %s is not a byte (an integer from 0 to 255)", i, n)
		}
		result = append(result, byte(u))
	}
	*b = result
	return nil
}

// WalletProfile is the risk tolerance profile for policy evaluation: one of
// the four built-in names. For explicit thresholds set
// VerificationInput.CustomWalletProfile instead.
type WalletProfile string

const (
	WalletProfileTreasury   WalletProfile = "Treasury"
	WalletProfileTradingBot WalletProfile = "TradingBot"
	WalletProfileGaming     WalletProfile = "Gaming"
	WalletProfileEnterprise WalletProfile = "Enterprise"
)

// Trust tiers, as the Core serializes them (graphite-core TrustTier).
const (
	TrustTierUnknown             = "Unknown"
	TrustTierHeuristicInferred   = "HeuristicInferred"
	TrustTierOfficialManifest    = "OfficialManifest"
	TrustTierSimulationValidated = "SimulationValidated"
	TrustTierCommunityVerified   = "CommunityVerified"
	TrustTierBattleTested        = "BattleTested"
)

// CustomProfile is the Core's WalletProfile::Custom: explicit thresholds.
// The server clamps a caller-supplied profile to the weakest built-in
// (Gaming) unless the operator opted out.
type CustomProfile struct {
	MinConfidence float64 `json:"min_confidence"`
	// MinTrustTier is one of the TrustTier* constants.
	MinTrustTier string `json:"min_trust_tier"`
}

// walletProfileJSON is wallet_profile as serde's externally tagged enum
// expects it: "Gaming" for a built-in, {"Custom":{...}} for thresholds, and
// nothing at all (the Core's default, Treasury) for neither. nil means omit.
func walletProfileJSON(name WalletProfile, custom *CustomProfile) (json.RawMessage, error) {
	if custom != nil {
		if name != "" {
			return nil, fmt.Errorf("graphite: WalletProfile %q and CustomWalletProfile are both set; set one", name)
		}
		if math.IsNaN(custom.MinConfidence) || custom.MinConfidence < 0 || custom.MinConfidence > 1 {
			return nil, fmt.Errorf("graphite: CustomWalletProfile.MinConfidence must be within [0, 1], got %v", custom.MinConfidence)
		}
		if !oneOf(custom.MinTrustTier, trustTiers...) {
			return nil, fmt.Errorf("graphite: CustomWalletProfile.MinTrustTier %q is not a trust tier", custom.MinTrustTier)
		}
		return json.Marshal(map[string]*CustomProfile{"Custom": custom})
	}
	switch name {
	case "":
		return nil, nil
	case WalletProfileTreasury, WalletProfileTradingBot, WalletProfileGaming, WalletProfileEnterprise:
		return json.Marshal(string(name))
	default:
		return nil, fmt.Errorf("graphite: unknown WalletProfile %q (Treasury, TradingBot, Gaming, Enterprise, or set CustomWalletProfile)", name)
	}
}

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
	// SignedTransaction is the serialized transaction artifact, UNSIGNED:
	// every signature slot must be 64 zero bytes. Despite the name it is not a
	// signed blob — Graphite verifies before signing, and the Core answers 400
	// to an artifact with a filled slot, because signed bytes mean the signing
	// already happened (Round 17, F-16-01; this doc corrected in Round 19,
	// F-19-C3). When supplied the verdict is artifact_bound, the Core simulates
	// these exact bytes, and Scope.TransactionSHA256 is their digest — check it
	// with VerifyTransactionDigest. JSON array of bytes, NOT base64 (serde
	// Vec<u8>).
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
	// CustomWalletProfile, when set, sends the Core's Custom profile
	// ({"Custom":{"min_confidence":…,"min_trust_tier":…}}) in place of a
	// built-in WalletProfile; setting both is an error. Leaving both empty
	// omits wallet_profile, and the Core applies its default (Treasury, the
	// strictest built-in).
	CustomWalletProfile *CustomProfile `json:"-"`
	// Simulation baselines are TRUSTED SERVER STATE (earned via RPC-verified
	// usage or seeded by the operator) — never sent from the client.
}

// verificationInputFields is VerificationInput without its methods, so the
// methods below can marshal it without recursing.
type verificationInputFields VerificationInput

// MarshalJSON writes the request the Rust Core's serde accepts.
//
// Audit 2026-10-20 (G2): a zero-value VerificationInput sent
// "wallet_profile":"" and "account_addresses":null, and serde refuses both
// (no variant is named "", and account_addresses is a required Vec), so the
// request failed with a 422 whose cause was the SDK. An empty WalletProfile
// is now omitted (the Core's default applies), a nil AccountAddresses is
// sent as [], and CustomWalletProfile is written as serde's externally
// tagged Custom variant.
func (in VerificationInput) MarshalJSON() ([]byte, error) {
	profile, err := walletProfileJSON(in.WalletProfile, in.CustomWalletProfile)
	if err != nil {
		return nil, err
	}
	accounts := in.AccountAddresses
	if accounts == nil {
		accounts = []string{}
	}
	return json.Marshal(struct {
		verificationInputFields
		AccountAddresses []string        `json:"account_addresses"`
		WalletProfile    json.RawMessage `json:"wallet_profile,omitempty"`
	}{verificationInputFields(in), accounts, profile})
}

// UnmarshalJSON reads what MarshalJSON writes, Custom profile included.
func (in *VerificationInput) UnmarshalJSON(data []byte) error {
	var wire struct {
		verificationInputFields
		WalletProfile json.RawMessage `json:"wallet_profile,omitempty"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*in = VerificationInput(wire.verificationInputFields)
	in.WalletProfile, in.CustomWalletProfile = "", nil
	raw := bytes.TrimSpace(wire.WalletProfile)
	switch {
	case len(raw) == 0 || bytes.Equal(raw, []byte("null")):
	case raw[0] == '"':
		var name string
		if err := json.Unmarshal(raw, &name); err != nil {
			return err
		}
		in.WalletProfile = WalletProfile(name)
	default:
		var custom struct {
			Custom *CustomProfile `json:"Custom"`
		}
		if err := json.Unmarshal(raw, &custom); err != nil || custom.Custom == nil {
			return fmt.Errorf("graphite: wallet_profile is neither a profile name nor {\"Custom\":{...}}")
		}
		in.CustomWalletProfile = custom.Custom
	}
	return nil
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
	// Approved says whether the pipeline refused the transaction. It is NOT
	// permission to sign: an approval from a node without an RPC was never
	// simulated, and a descriptive approval binds to no bytes. Gate signing
	// on IsExecutable.
	Approved bool `json:"approved"`
	// Decision is what this verdict permits (Round 30, G-01): one of the
	// Decision* constants. Only DecisionExecutableApproved permits signing.
	// Empty from a server older than Round 30.
	Decision string `json:"decision,omitempty"`
	// Executable is Decision == DecisionExecutableApproved (Round 30). Nil
	// from a server older than Round 30.
	Executable    *bool                       `json:"executable,omitempty"`
	Confidence    float64                     `json:"confidence"`
	Breakdown     []VerificationBreakdownItem `json:"breakdown"`
	TrustTier     string                      `json:"trust_tier"`
	RiskVerdict   RiskVerdictSummary          `json:"risk_verdict"`
	PolicyVerdict string                      `json:"policy_verdict"`
	AuditTrailID  string                      `json:"audit_trail_id"`
	// ContentHash is deprecated (Round 30, R-M10): read InstructionBindKey
	// (or BindKey), which carries the same value — a 64-bit key for the
	// described instruction, not the transaction's identity (that is
	// Scope.TransactionSHA256).
	ContentHash string `json:"content_hash"`
	// InstructionBindKey is ContentHash under the name that says what it is
	// (Round 30). Empty from a server older than Round 30.
	InstructionBindKey string            `json:"instruction_bind_key,omitempty"`
	Transaction        BuiltTransaction  `json:"transaction"`
	ResolvedAccounts   []ResolvedAccount `json:"resolved_accounts"`
	ProtocolName       string            `json:"protocol_name"`
	InstructionName    string            `json:"instruction_name"`
	ManifestFound      bool              `json:"manifest_found"`
	UnknownProtocol    bool              `json:"unknown_protocol"`
	// ManifestVersion is the version label of the protocol manifest this result
	// was checked against (nil for unknown protocols). Constitution G7 — lets a
	// consumer confirm which manifest version produced the verification.
	ManifestVersion      *string               `json:"manifest_version,omitempty"`
	SimulationFlagged    *bool                 `json:"simulation_flagged,omitempty"`
	SimulationDivergence *float64              `json:"simulation_divergence,omitempty"`
	Summary              string                `json:"summary"`
	Layers               []PipelineLayerResult `json:"layers,omitempty"`
	// ProgramUpgrades lists programs this transaction invokes that were
	// redeployed, or handed to a new upgrade authority, since Graphite last
	// saw them (roadmap R-M1). Empty when none were.
	ProgramUpgrades []ProgramUpgrade `json:"program_upgrades,omitempty"`
	// Scope is what this verdict is BOUND to, and what it did not observe.
	//
	// It makes Graphite's central promise checkable instead of assumed: the
	// thing it approved is the thing that gets signed, and every
	// security-relevant property of that thing was either independently
	// verified or explicitly identified as unverified. Approved alone does not
	// say which half applies.
	//
	// Verify refuses a response without it (audit 2026-10-20: the Core has
	// emitted it since 2026-09-08 and the schema requires it); it can be nil
	// only in a result built or decoded by other means. Nil is NOT
	// "descriptive" — it means nothing said, and a gate requiring artifact
	// binding must treat it as unknown.
	Scope *VerificationScope `json:"scope,omitempty"`
}

// VerificationScope is the artifact-binding half of a verdict.
//
// Kind is either "artifact_bound" or "descriptive". The artifact fields are
// populated only for the former.
type VerificationScope struct {
	Kind string `json:"kind"`
	// TransactionSHA256 is the digest of the exact bytes supplied, so a caller
	// can recompute it over what it is about to submit and refuse if it
	// differs. Stronger than ContentHash, which covers a projection of one
	// instruction and cannot see the fee payer, blockhash, signer set, or any
	// sibling instruction.
	TransactionSHA256 string `json:"transaction_sha256,omitempty"`
	TransactionBytes  int    `json:"transaction_bytes,omitempty"`
	// Simulated reports whether a simulator actually executed those bytes.
	Simulated bool `json:"simulated,omitempty"`
	// Unobserved lists security-relevant properties that were not
	// independently established.
	Unobserved []string `json:"unobserved,omitempty"`
	// UnobservedCodes names each entry of Unobserved with a stable
	// identifier (UnobservedCodes[i] names Unobserved[i]). The prose is for
	// people; a gate that decides which residuals it accepts decides on
	// these. ProgramSemantics and InnerInstructions are inherent to every
	// artifact-bound verdict; every other code names an observation that was
	// possible and did not happen. Nil from a server older than 2026-09-12,
	// which is unknown rather than empty.
	UnobservedCodes []string `json:"unobserved_codes,omitempty"`
	// ComputeBudget is what the transaction asks of the compute budget, read
	// from its bytes (Round 21). Nil from older servers and when the bytes
	// did not parse.
	ComputeBudget *ComputeBudgetRequest `json:"compute_budget,omitempty"`
	// MessageVersion is the message version the bytes carry: "legacy",
	// "v0" or "v1" (Round 24). Empty when they did not parse, and from
	// servers older than Round 24.
	MessageVersion string `json:"message_version,omitempty"`
}

// ProgramUpgrade is a program whose deployment changed since Graphite last
// saw it (roadmap R-M1).
type ProgramUpgrade struct {
	ProgramID                string  `json:"program_id"`
	PreviousDeploySlot       uint64  `json:"previous_deploy_slot"`
	DeploySlot               uint64  `json:"deploy_slot"`
	PreviousUpgradeAuthority *string `json:"previous_upgrade_authority"`
	UpgradeAuthority         *string `json:"upgrade_authority"`
	// Quarantined says whether GRAPHITE_QUARANTINE_ON_UPGRADE withdrew it.
	Quarantined bool `json:"quarantined"`
}

// ComputeBudgetRequest is a transaction's compute-budget request: the v1
// header's values, or the Compute Budget instructions of a legacy or v0
// transaction (Round 21).
type ComputeBudgetRequest struct {
	Source                        string   `json:"source"`
	ComputeUnitLimit              *uint32  `json:"compute_unit_limit,omitempty"`
	EffectiveComputeUnitLimit     uint32   `json:"effective_compute_unit_limit"`
	ComputeUnitPriceMicroLamports *uint64  `json:"compute_unit_price_micro_lamports,omitempty"`
	PriorityFeeLamports           uint64   `json:"priority_fee_lamports"`
	HeapBytes                     *uint32  `json:"heap_bytes,omitempty"`
	LoadedAccountsDataSizeLimit   *uint32  `json:"loaded_accounts_data_size_limit,omitempty"`
	Problems                      []string `json:"problems,omitempty"`
}

// The residual codes a Graphite server can report in UnobservedCodes.
// Mirrors UnobservedCode in graphite-core/src/verification.rs and the enum in
// schemas/verification-result-v1.json.
const (
	UnobservedNotSimulated = "not_simulated"
	UnobservedNoStateDiff  = "no_state_diff"
	// Round 17: the simulator ran and reported an error; nothing it would do
	// was measured and its compute usage is not evidence.
	UnobservedSimulationFailed         = "simulation_failed"
	UnobservedPrivilegesFromCaller     = "privileges_from_caller"
	UnobservedPrivilegesAbsent         = "privileges_absent"
	UnobservedLookupTablesUnresolved   = "lookup_tables_unresolved"
	UnobservedProgramSemantics         = "program_semantics"
	UnobservedInnerInstructions        = "inner_instructions"
	UnobservedArtifactUnparsed         = "artifact_unparsed"
	UnobservedAccountIdentityUnparsed  = "account_identity_unparsed"
	UnobservedInstructionNotLocated    = "instruction_not_located"
	UnobservedNoArtifact               = "no_artifact"
	UnobservedOtherInstructions        = "other_instructions"
	UnobservedFeePayerBlockhashSigners = "fee_payer_blockhash_signers"
	UnobservedNoRealEffects            = "no_real_effects"
	// UnobservedIntentParameters (Round 36, F-003): the request states an
	// amount, recipient or asset the Core could not tie to the bytes.
	UnobservedIntentParameters = "intent_parameters"
)

// IsInherentUnobserved reports whether a residual code is one every
// artifact-bound verdict carries by construction.
func IsInherentUnobserved(code string) bool {
	return code == UnobservedProgramSemantics || code == UnobservedInnerInstructions
}

// NonInherentUnobserved returns the residual codes on this verdict that name
// an observation which was possible and did not happen — the ones an
// execution gate has to decide on. Nil (with ok == false) when the server
// reported no codes, which a gate must treat as undecidable, not as clear.
func (r *VerificationResult) NonInherentUnobserved() (codes []string, ok bool) {
	if r == nil || r.Scope == nil || r.Scope.UnobservedCodes == nil {
		return nil, false
	}
	out := []string{}
	for _, c := range r.Scope.UnobservedCodes {
		if !IsInherentUnobserved(c) {
			out = append(out, c)
		}
	}
	return out, true
}

// IsArtifactBound reports whether the verdict is tied to concrete transaction
// bytes rather than to a description of them.
//
// An execution gate that can move funds should require this rather than gating
// on Approved alone. False for a nil scope: a server that did not say has not
// said yes. False, too, for a scope that claims artifact_bound without a
// well-formed digest of what it bound — 64 lowercase hex characters (audit
// 2026-10-20, G1): a binding without its digest binds nothing.
func (r *VerificationResult) IsArtifactBound() bool {
	return r != nil && r.Scope != nil && r.Scope.Kind == "artifact_bound" &&
		isLowerHex64(r.Scope.TransactionSHA256)
}

// The execution decisions (Round 30, G-01). Mirrors ExecutionDecision in
// graphite-core/src/verification.rs and the schema's enum.
const (
	DecisionExecutableApproved = "executable_approved"
	DecisionAnalysisOnly       = "analysis_only"
	DecisionInconclusive       = "inconclusive"
	DecisionBlocked            = "blocked"
)

// ExecutionDecisions lists every decision, in the Core's declaration order.
var ExecutionDecisions = []string{
	DecisionExecutableApproved, DecisionAnalysisOnly, DecisionInconclusive, DecisionBlocked,
}

// ComputeExecutionDecision recomputes the Core's execution-decision rule from
// the verdict's own fields (Round 30, G-01; execution_decision in
// graphite-core/src/verification.rs). Executable only when ALL hold:
// approved; risk Clear; policy "Approved"; scope artifact_bound with a digest
// and Simulated; UnobservedCodes present, naming every Unobserved entry, and
// all inherent; layers reported and none "failed". Otherwise an approval is
// analysis_only; a refusal whose findings are all VerificationIncomplete is
// inconclusive; every other refusal is blocked. Missing fields never make a
// verdict executable.
func (r *VerificationResult) ComputeExecutionDecision() string {
	if r == nil {
		return DecisionBlocked
	}
	if !r.Approved {
		f := r.RiskVerdict.Findings
		if len(f) == 0 {
			return DecisionBlocked
		}
		for _, x := range f {
			if x.Pattern != "VerificationIncomplete" {
				return DecisionBlocked
			}
		}
		return DecisionInconclusive
	}
	executable := r.RiskVerdict.Status == "Clear" && r.PolicyVerdict == "Approved" &&
		r.IsArtifactBound() && r.Scope.Simulated &&
		r.Scope.UnobservedCodes != nil && len(r.Scope.UnobservedCodes) == len(r.Scope.Unobserved) &&
		r.Layers != nil
	if executable {
		for _, c := range r.Scope.UnobservedCodes {
			if !IsInherentUnobserved(c) {
				executable = false
			}
		}
		for _, l := range r.Layers {
			if l.Status == "failed" {
				executable = false
			}
		}
	}
	if executable {
		return DecisionExecutableApproved
	}
	return DecisionAnalysisOnly
}

// IsExecutable reports whether this verdict permits signing — the ONE gate an
// execution path should use (Round 30, G-01), not Approved.
//
// It recomputes the Core's rule and requires the server to agree: a server
// that sent a decision must say executable_approved with executable true AND
// the recomputation must agree; a decision this SDK does not know is not
// executable; a verdict with neither field (a server older than Round 30) is
// judged by the recomputation alone, which is never looser than the server.
func (r *VerificationResult) IsExecutable() bool {
	if r == nil {
		return false
	}
	local := r.ComputeExecutionDecision()
	if r.Decision == "" && r.Executable == nil {
		return local == DecisionExecutableApproved
	}
	return r.Decision == DecisionExecutableApproved && r.Executable != nil && *r.Executable &&
		local == DecisionExecutableApproved
}

// BindKey is the key binding audit and lifecycle records to the described
// instruction (Round 30, R-M10): InstructionBindKey, or the deprecated
// ContentHash from an older server.
func (r *VerificationResult) BindKey() string {
	if r == nil {
		return ""
	}
	if r.InstructionBindKey != "" {
		return r.InstructionBindKey
	}
	return r.ContentHash
}

// Unobserved returns everything Graphite did not independently observe. Empty
// when the server reported no scope, which is unknown rather than nothing.
func (r *VerificationResult) Unobserved() []string {
	if r == nil || r.Scope == nil {
		return nil
	}
	return r.Scope.Unobserved
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

// AccountIdentity describes how an account's identity is verified: "pda"
// (re-derived from the manifest's seed template), "constant" (matched
// against a manifest-declared fixed address), or "unverified" (genuinely
// externally-determined — no PDA formula, no fixed constant). Mirrors
// graphite-core/src/account_resolution.rs AccountIdentity, which serializes
// snake_case. A5-03 (2026-09-29 audit): these constants were "Pda" /
// "Constant" / "Unverified", so a consumer comparing against them never
// matched a real verdict.
type AccountIdentity string

const (
	AccountIdentityPda        AccountIdentity = "pda"
	AccountIdentityConstant   AccountIdentity = "constant"
	AccountIdentityUnverified AccountIdentity = "unverified"
)

// ResolvedAccount is a resolved account with identity verification status.
type ResolvedAccount struct {
	Address string `json:"address"`
	Role    string `json:"role"`
	// Name is the slot's name in the manifest ("source", "authority", ...).
	// The Core omits it when empty: an account past the manifest's declared
	// list, or of an unknown program.
	Name        string          `json:"name,omitempty"`
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

// Response-size bounds (audit 2026-10-20). Error bodies were read with an
// unbounded io.ReadAll and pasted into the error text, so a hostile or broken
// server (or a proxy in front of it) could make one failed call allocate
// without limit and put megabytes into a log line.
const (
	// MaxResponseBytes bounds a successful answer; the manifest list, the
	// largest, is a small fraction of it.
	MaxResponseBytes = 16 << 20
	// maxErrorBodyBytes bounds what of a non-200 answer reaches an error.
	maxErrorBodyBytes = 4 << 10
)

// roundTrip sends one request and returns a 200's body. Everything else — a
// refused base URL, a transport error, a redirect, a non-200, a body over
// MaxResponseBytes — is an error: what was asked did not happen.
func (c *Client) roundTrip(ctx context.Context, method, path string, body []byte, auth bool, what string) ([]byte, error) {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		c.setAuth(req)
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		prefix, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes+1))
		text := string(prefix)
		if len(prefix) > maxErrorBodyBytes {
			text = string(prefix[:maxErrorBodyBytes]) + "… (truncated)"
		}
		return nil, fmt.Errorf("graphite: %s failed: server error (status %d): %s", what, resp.StatusCode, text)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("graphite: %s: read response: %w", what, err)
	}
	if len(data) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: %s: the response exceeds %d bytes", ErrInvalidResponse, what, MaxResponseBytes)
	}
	return data, nil
}

// Verify sends a verification request to the Graphite Core server.
//
// The answer is held to DecodeVerificationResult's rules before it is
// returned (audit 2026-10-20, G1): a body that is not a whole, consistent
// verdict is an error, never a zero-valued result.
func (c *Client) Verify(input *VerificationInput) (*VerificationResult, error) {
	return c.VerifyContext(context.Background(), input)
}

// VerifyContext is Verify with a context: cancelling it, or its deadline
// passing, abandons the request. Like a timeout, that means verification did
// not happen.
func (c *Client) VerifyContext(ctx context.Context, input *VerificationInput) (*VerificationResult, error) {
	if input == nil {
		return nil, fmt.Errorf("graphite: no verification input")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}
	data, err := c.roundTrip(ctx, http.MethodPost, "/verify", body, true, "verification")
	if err != nil {
		return nil, err
	}
	return DecodeVerificationResult(data)
}

// HealthResponse is the answer of GET /health. Status stays "ok" while the
// node serves traffic; Degraded is the operator signal.
type HealthResponse struct {
	Status          string   `json:"status"`
	Service         string   `json:"service"`
	Version         string   `json:"version"`
	Degraded        bool     `json:"degraded"`
	DegradedReasons []string `json:"degraded_reasons,omitempty"`
	// VerificationMode is "analysis_only" when the Core has no RPC — every
	// verdict from it is then not executable — and "executable" otherwise
	// (Round 30). Empty from an older server.
	VerificationMode string `json:"verification_mode,omitempty"`
}

// Health checks if the Core server is running.
func (c *Client) Health() error {
	_, err := c.HealthContext(context.Background())
	return err
}

// HealthContext is Health with a context, returning the server's answer. A
// 200 whose body is not a health response is an error (audit 2026-10-20).
func (c *Client) HealthContext(ctx context.Context) (*HealthResponse, error) {
	data, err := c.roundTrip(ctx, http.MethodGet, "/health", nil, false, "health check")
	if err != nil {
		return nil, err
	}
	var h HealthResponse
	if err := decodeStrict(data, &h, "health response", healthViolation); err != nil {
		return nil, err
	}
	return &h, nil
}

// ListManifests returns all loaded protocol manifests, typed.
func (c *Client) ListManifests() ([]ProtocolManifest, error) {
	return c.ListManifestsContext(context.Background())
}

// ListManifestsContext is ListManifests with a context.
//
// Round 19 (F-19-C6): the status was ignored, so a 401 (wrong key), 429 or
// 503 body was handed to the JSON decoder — an error object decodes into an
// empty or partial list, and a caller got "no manifests" instead of "that
// request failed". Every call refuses a non-200; since the 2026-10-20 audit
// a 200 that is not a manifest list is refused too.
func (c *Client) ListManifestsContext(ctx context.Context) ([]ProtocolManifest, error) {
	data, err := c.roundTrip(ctx, http.MethodGet, "/manifests", nil, true, "list manifests")
	if err != nil {
		return nil, err
	}
	var manifests []ProtocolManifest
	if err := decodeStrict(data, &manifests, "manifest list", manifestListViolation); err != nil {
		return nil, err
	}
	return manifests, nil
}

// CheckBaseURL refuses a Core base URL that would carry the API key, or a
// verdict, in cleartext across a network.
//
// Round 19 (F-19-C6): the client accepted any http:// URL and sent
// `Authorization: Bearer <key>` to it. On anything but the local machine that
// puts the operator key on the wire in the clear — and lets anyone on the
// path rewrite `"approved": false` into `"approved": true`. https:// is always
// accepted; http:// only for a loopback host: localhost, 127.0.0.0/8, or ::1.
func CheckBaseURL(baseURL string) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("graphite base URL %q is not a valid URL: %w", baseURL, err)
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return fmt.Errorf("graphite base URL %q has no host", baseURL)
		}
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf(
			"graphite base URL %q is plain http:// to a non-loopback host: the API key and every "+
				"verdict would cross the network unencrypted, where a verdict can be rewritten in "+
				"flight. Use https://, or http:// only to localhost / 127.0.0.0/8 / [::1] (Round 19, F-19-C6)",
			baseURL)
	default:
		return fmt.Errorf("graphite base URL must be https:// (or http:// to loopback), got %q", baseURL)
	}
}

// isLoopbackHost reports whether a hostname is the local machine. Only
// canonical forms count: "localhost", a dotted-quad IPv4 in 127.0.0.0/8, the
// IPv6 loopback, or 127.0.0.0/8 written as an IPv4-mapped IPv6 address
// (::ffff:127.0.0.1 — To4 unwraps it). Go's URL parser does not canonicalise
// "127.1", so that spelling is refused rather than guessed at.
//
// Audit 2026-10-20: this accepted the IPv4-mapped form and the TypeScript
// SDK refused it. A mapped address is the IPv4 address — a connection to it
// is a connection to 127.0.0.1 — so the TypeScript SDK now accepts it too.
// The deprecated IPv4-compatible form (::127.0.0.1) is refused by both.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// net.ParseIP accepts only canonical dotted-quad for IPv4.
		return v4[0] == 127
	}
	return ip.Equal(net.IPv6loopback)
}

// endpoint joins the base URL and path after enforcing CheckBaseURL. Checked
// on every request, not once at construction: BaseURL is an exported field a
// caller can set directly, and NewClient has no error to return.
func (c *Client) endpoint(path string) (string, error) {
	if err := CheckBaseURL(c.BaseURL); err != nil {
		return "", err
	}
	return strings.TrimRight(c.BaseURL, "/") + path, nil
}

// setAuth attaches the Bearer API key when one is configured.
func (c *Client) setAuth(req *http.Request) {
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
}
