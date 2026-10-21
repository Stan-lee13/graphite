package graphite

// Lifecycle events and L8 execution verification (audit 2026-10-20: the Go
// SDK had neither, so a Go integration could not put its signing on the
// trail or ask whether a submitted transaction was the one Graphite
// approved — parity with the TypeScript SDK's recordLifecycleEvent and
// verifyExecution). Shapes mirror sdk/typescript/src/types.ts and the
// handlers in graphite-core/src/server.rs.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Caller-reported lifecycle stages. Graphite records construction, simulation
// and verification itself; signing, submission, confirmation and
// finalization happen in the caller, and only the caller can report them.
const (
	LifecycleSigning      = "signing"
	LifecycleSubmission   = "submission"
	LifecycleConfirmation = "confirmation"
	LifecycleFinalization = "finalization"
)

// What the trail held for an event's verification when the event was recorded.
const (
	VerdictOnRecordApproved = "approved"
	// VerdictOnRecordBlocked means the caller just reported acting on a
	// transaction Graphite refused.
	VerdictOnRecordBlocked  = "blocked"
	VerdictOnRecordNotFound = "not_found"
)

// LifecycleEventInput is the body of POST /audit/event.
type LifecycleEventInput struct {
	// EventType is one of the Lifecycle* constants.
	EventType string `json:"event_type"`
	// ContentHash is the verification's content_hash (16 lowercase hex). An
	// instruction-level key — send AuditTrailID and TransactionSHA256 with it.
	ContentHash string `json:"content_hash"`
	// AuditTrailID names the exact verification; it resolves first.
	AuditTrailID string `json:"audit_trail_id,omitempty"`
	// TransactionSHA256 names the exact transaction (Scope.TransactionSHA256).
	TransactionSHA256 string `json:"transaction_sha256,omitempty"`
	// TransactionSignature is the base58 signature, from submission onward.
	TransactionSignature string `json:"transaction_signature,omitempty"`
	// ReportedBy is an operator-meaningful name, never a credential.
	ReportedBy string `json:"reported_by,omitempty"`
	// Detail is free-form, at most 1024 characters.
	Detail string `json:"detail,omitempty"`
}

// LifecycleEventReceipt is the answer to a recorded lifecycle event.
type LifecycleEventReceipt struct {
	Recorded    bool   `json:"recorded"`
	EventType   string `json:"event_type"`
	ContentHash string `json:"content_hash"`
	// VerdictOnRecord is established by Graphite, not reported by the caller.
	VerdictOnRecord string `json:"verdict_on_record"`
	// VerdictOnRecordKey is the key VerdictOnRecord was resolved by:
	// "audit_trail_id", "transaction_sha256" or "content_hash" (the last is
	// about *a* transaction carrying that instruction, not necessarily this one).
	VerdictOnRecordKey string `json:"verdict_on_record_key"`
	// SequenceAnomalies: "duplicate: …" (a harmless retry), "out of order: …",
	// "unpreceded: …" or "signature conflict: …". Empty when in order.
	SequenceAnomalies   []string `json:"sequence_anomalies,omitempty"`
	PriorEventsOnRecord *uint64  `json:"prior_events_on_record,omitempty"`
}

// ExecutionCheckInput is the body of POST /verify/execution (L8).
type ExecutionCheckInput struct {
	Signature         string `json:"signature"`
	ContentHash       string `json:"content_hash,omitempty"`
	TransactionSHA256 string `json:"transaction_sha256,omitempty"`
	AuditTrailID      string `json:"audit_trail_id,omitempty"`
	ReportedBy        string `json:"reported_by,omitempty"`
}

// InclusionWitness is a second RPC's account of the signature (Round 12).
type InclusionWitness struct {
	Agrees     bool    `json:"agrees"`
	Seen       *bool   `json:"seen"`
	Commitment *string `json:"commitment,omitempty"`
	Detail     string  `json:"detail"`
}

// RecordedVerdicts counts every verdict the trail holds for the resolved key.
type RecordedVerdicts struct {
	Approved uint64 `json:"approved"`
	Refused  uint64 `json:"refused"`
}

// ExecutionCheckResult is L8's answer: what the chain says about the
// signature, reconciled against the verdict on record. Discrepancy is the
// field to page on (BlockedButExecuted).
type ExecutionCheckResult struct {
	Signature string `json:"signature"`
	// ChainStatus is the server's ExecutionVerification, as-is.
	ChainStatus               json.RawMessage `json:"chain_status"`
	RecordedApproved          *bool           `json:"recorded_approved"`
	RecordedAuditTrailID      *string         `json:"recorded_audit_trail_id"`
	RecordedTransactionSHA256 *string         `json:"recorded_transaction_sha256"`
	// Reconciliation is the server's ExecutionReconciliation: a JSON string
	// for unit variants, a one-key object for data variants. See
	// ReconciliationVariant.
	Reconciliation         json.RawMessage   `json:"reconciliation"`
	Discrepancy            bool              `json:"discrepancy"`
	Attribution            string            `json:"attribution"`
	ChainTransactionSHA256 *string           `json:"chain_transaction_sha256"`
	CallerKeysDisagree     []string          `json:"caller_keys_disagree"`
	ChainBytesRejected     *string           `json:"chain_bytes_rejected,omitempty"`
	ChainBytesUnavailable  *string           `json:"chain_bytes_unavailable,omitempty"`
	ChainInconsistent      *string           `json:"chain_inconsistent,omitempty"`
	InclusionWitness       *InclusionWitness `json:"inclusion_witness,omitempty"`
	// InclusionAssurance says what the account of inclusion rests on
	// (Round 30): single_provider, witnessed, witnessed_not_independent,
	// witness_disputed or witness_unavailable. Empty from older servers.
	InclusionAssurance string            `json:"inclusion_assurance,omitempty"`
	RecordedVerdicts   *RecordedVerdicts `json:"recorded_verdicts,omitempty"`
	AuditRecorded      bool              `json:"audit_recorded"`
}

// ReconciliationVariant names the reconciliation ("ApprovedAndExecuted",
// "BlockedButExecuted", "Unavailable", ...). Empty when it is malformed,
// which a validated result never is.
func (r *ExecutionCheckResult) ReconciliationVariant() string {
	if r == nil {
		return ""
	}
	var v any
	if err := json.Unmarshal(r.Reconciliation, &v); err != nil {
		return ""
	}
	return variantName(v, reconciliationUnits, reconciliationData)
}

// RecordLifecycleEvent puts a caller-performed lifecycle stage on Graphite's
// append-only trail (POST /audit/event, Constitution P9). It returns a
// receipt only when the server says recorded: true about this event; a 503
// means the event was NOT recorded and is an error. Record signing before
// submitting, and refuse to submit when it was not recorded, when
// VerdictOnRecord is not "approved", or when it was not resolved by
// "audit_trail_id".
func (c *Client) RecordLifecycleEvent(event *LifecycleEventInput) (*LifecycleEventReceipt, error) {
	return c.RecordLifecycleEventContext(context.Background(), event)
}

// RecordLifecycleEventContext is RecordLifecycleEvent with a context.
func (c *Client) RecordLifecycleEventContext(ctx context.Context, event *LifecycleEventInput) (*LifecycleEventReceipt, error) {
	if event == nil {
		return nil, fmt.Errorf("graphite: no lifecycle event")
	}
	body, err := c.post(ctx, "/audit/event", event, fmt.Sprintf("record the %s event", event.EventType))
	if err != nil {
		return nil, err
	}
	var receipt LifecycleEventReceipt
	if err := decodeStrict(body, &receipt, "lifecycle receipt", func(v any) string {
		return lifecycleReceiptViolation(v, event)
	}); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// VerifyExecution runs L8 after submission (POST /verify/execution): it
// confirms the signature on-chain and reconciles it against the verdict
// Graphite recorded. A 503 (AuditUnavailable) still carries the
// reconciliation in the error's text; it is an error, because a
// reconciliation that was not recorded is not one the trail can be audited
// against.
func (c *Client) VerifyExecution(input *ExecutionCheckInput) (*ExecutionCheckResult, error) {
	return c.VerifyExecutionContext(context.Background(), input)
}

// VerifyExecutionContext is VerifyExecution with a context.
func (c *Client) VerifyExecutionContext(ctx context.Context, input *ExecutionCheckInput) (*ExecutionCheckResult, error) {
	if input == nil {
		return nil, fmt.Errorf("graphite: no execution check input")
	}
	body, err := c.post(ctx, "/verify/execution", input, "check the execution")
	if err != nil {
		return nil, err
	}
	var result ExecutionCheckResult
	if err := decodeStrict(body, &result, "execution check result", func(v any) string {
		return executionResultViolation(v, input)
	}); err != nil {
		return nil, err
	}
	return &result, nil
}

// post sends an authenticated JSON POST and returns a 200's body; anything
// else is an error carrying (a bounded prefix of) the server's answer.
func (c *Client) post(ctx context.Context, path string, payload any, what string) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}
	return c.roundTrip(ctx, http.MethodPost, path, data, true, what)
}
