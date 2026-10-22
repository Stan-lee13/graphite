package graphite

// Response validation (audit 2026-10-20, G1).
//
// Verify used to hand the response body straight to encoding/json. Three
// things followed. Nothing was required, so `{"approved":true}` alone decoded
// into an approval with every other field zero. Nothing was cross-checked, so
// an approval beside a Blocked risk verdict passed. And encoding/json matches
// object keys case-insensitively and lets the last duplicate win, so
// `{"approved":false,"APPROVED":true}` decoded as Approved == true — a body
// that the Rust Core (serde, exact keys, duplicates refused) and every other
// reader would call a refusal. The TypeScript SDK had a validator; this is
// its equivalent, plus the two checks only Go needs:
//
//  1. No object anywhere in a response may carry two keys that the decoder
//     would fold together (exact duplicates included).
//  2. A key that folds to a field of the target type must spell it exactly;
//     `APPROVED` is not `approved`, it is an attempt to be read as it.
//
// Unknown keys that fold to no field are ignored, as in the TypeScript SDK,
// so a newer Core that adds an optional field does not break deployed
// clients. Everything a caller decides on is required and checked.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// ErrInvalidResponse wraps every structural refusal of a server response.
var ErrInvalidResponse = errors.New("graphite: structurally invalid response")

// foldKey canonicalises a key the way encoding/json compares them: every
// rune is replaced by the smallest member of its Unicode simple-fold orbit,
// so "APPROVED", "approved" and "ApProVed" — and "ſcope" (U+017F) and
// "scope" — share one key.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		b.WriteRune(min)
	}
	return b.String()
}

// checkNoFoldedDuplicates walks a JSON document and refuses any object with
// two keys that fold together, and any trailing data after the document.
func checkNoFoldedDuplicates(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSON(dec, "$"); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after the JSON document")
	}
	return nil
}

func walkJSON(dec *json.Decoder, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]string{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			f := foldKey(key)
			if prior, dup := seen[f]; dup {
				return fmt.Errorf("%s: keys %q and %q are the same key to a case-insensitive decoder", path, prior, key)
			}
			seen[f] = key
			if err := walkJSON(dec, path+"."+key); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkJSON(dec, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// checkExactKeys refuses a key that folds to a field of t without spelling
// it exactly, at every depth t describes.
func checkExactKeys(v any, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for k, val := range m {
			if ft, exact := fields[k]; exact {
				if err := checkExactKeys(val, ft, path+"."+k); err != nil {
					return err
				}
				continue
			}
			for name := range fields {
				if foldKey(name) == foldKey(k) {
					return fmt.Errorf("%s: key %q is not %q; a case-insensitive decoder would read it as that field", path, k, name)
				}
			}
		}
	case reflect.Slice, reflect.Array:
		a, ok := v.([]any)
		if !ok {
			return nil
		}
		for i, e := range a {
			if err := checkExactKeys(e, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// decodeStrict is the one path every response body takes: no folded
// duplicates, the shape check, exact keys for the target type, and only then
// the typed decode.
func decodeStrict(data []byte, target any, what string, violation func(any) string) error {
	if err := checkNoFoldedDuplicates(data); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalidResponse, what, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return fmt.Errorf("%w: %s is not JSON: %v", ErrInvalidResponse, what, err)
	}
	if v := violation(generic); v != "" {
		return fmt.Errorf("%w: %s: %s", ErrInvalidResponse, what, v)
	}
	if err := checkExactKeys(generic, reflect.TypeOf(target), "$"); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalidResponse, what, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalidResponse, what, err)
	}
	return nil
}

// DecodeVerificationResult decodes and validates a /verify response body. It
// is what Verify uses; it is exported for callers that receive a verdict by
// another route (a queue, a file) and must hold it to the same rules.
//
// Required: every field the Core always emits, as
// schemas/verification-result-v1.json requires it. Refused: a verdict that
// contradicts itself (approved beside a Blocked risk verdict, or a
// policy_verdict other than "Approved"; a layer whose passed disagrees with
// its status), a scope claiming artifact_bound without the digest of what it
// bound, a descriptive scope carrying artifact fields, residual codes that do
// not name each unobserved entry, and any key that differs from a field only
// by case.
func DecodeVerificationResult(data []byte) (*VerificationResult, error) {
	var r VerificationResult
	if err := decodeStrict(data, &r, "verification result", verificationResultViolation); err != nil {
		return nil, err
	}
	return &r, nil
}

// ─── generic value helpers (numbers arrive as json.Number) ───

func asObject(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func isStr(v any) bool {
	_, ok := v.(string)
	return ok
}

func isBool(v any) bool {
	_, ok := v.(bool)
	return ok
}

func asFloat(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func isNum(v any) bool {
	_, ok := asFloat(v)
	return ok
}

// isCount is a non-negative integer that fits a uint64.
func isCount(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	_, err := strconv.ParseUint(string(n), 10, 64)
	return err == nil
}

func isStrArray(v any) bool {
	a, ok := v.([]any)
	if !ok {
		return false
	}
	for _, e := range a {
		if !isStr(e) {
			return false
		}
	}
	return true
}

func nullOr(v any, present bool, test func(any) bool) bool {
	return present && (v == nil || test(v))
}

func oneOf(v any, values ...string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range values {
		if s == x {
			return true
		}
	}
	return false
}

var trustTiers = []string{"Unknown", "HeuristicInferred", "OfficialManifest", "SimulationValidated", "CommunityVerified", "BattleTested"}

var unobservedCodes = []string{
	UnobservedNotSimulated, UnobservedNoStateDiff, UnobservedSimulationFailed, UnobservedPrivilegesFromCaller,
	UnobservedPrivilegesAbsent, UnobservedLookupTablesUnresolved, UnobservedProgramSemantics,
	UnobservedInnerInstructions, UnobservedArtifactUnparsed, UnobservedAccountIdentityUnparsed,
	UnobservedInstructionNotLocated, UnobservedNoArtifact, UnobservedOtherInstructions,
	UnobservedFeePayerBlockhashSigners, UnobservedNoRealEffects,
}

// ─── the verdict ───

func verificationResultViolation(value any) string {
	v, ok := asObject(value)
	if !ok {
		return "verification result must be a JSON object"
	}
	approved, ok := v["approved"].(bool)
	if !ok {
		return "`approved` must be a boolean"
	}
	if c, ok := asFloat(v["confidence"]); !ok || c < 0 || c > 1 {
		return "`confidence` must be a finite number in [0, 1]"
	}
	bd, ok := v["breakdown"].([]any)
	if !ok || len(bd) == 0 {
		return "`breakdown` must be a non-empty array"
	}
	for _, b := range bd {
		m, ok := asObject(b)
		if !ok || !isStr(m["kind"]) || !isNum(m["raw_value"]) || !isNum(m["weight"]) || !isNum(m["contribution"]) {
			return "each `breakdown` entry must be { kind, raw_value, weight, contribution }"
		}
	}
	if !oneOf(v["trust_tier"], trustTiers...) {
		return "`trust_tier` must be one of the schema's tiers"
	}
	risk, ok := asObject(v["risk_verdict"])
	if !ok {
		return "`risk_verdict` must be an object"
	}
	if !oneOf(risk["status"], "Clear", "Blocked") {
		return "`risk_verdict.status` must be \"Clear\" or \"Blocked\""
	}
	findings, ok := risk["findings"].([]any)
	if !ok {
		return "`risk_verdict.findings` must be an array"
	}
	for _, f := range findings {
		m, ok := asObject(f)
		if !ok || !isStr(m["pattern"]) || !isStr(m["reason"]) {
			return "`risk_verdict.findings` must be an array of { pattern, reason } strings"
		}
	}
	if !oneOf(v["policy_verdict"], "Approved", "Rejected") {
		return "`policy_verdict` must be \"Approved\" or \"Rejected\""
	}
	if approved && risk["status"] != "Clear" {
		return "an approved verdict must have a Clear risk verdict"
	}
	if approved != (v["policy_verdict"] == "Approved") {
		return "`policy_verdict` must be \"Approved\" exactly when `approved` is true"
	}
	if s, ok := v["audit_trail_id"].(string); !ok || s == "" {
		return "`audit_trail_id` must be a non-empty string"
	}
	if s, ok := v["content_hash"].(string); !ok || s == "" {
		return "`content_hash` must be a non-empty string"
	}
	if why := transactionViolation(v["transaction"]); why != "" {
		return why
	}
	accounts, ok := v["resolved_accounts"].([]any)
	if !ok {
		return "`resolved_accounts` must be an array"
	}
	for i, a := range accounts {
		if why := resolvedAccountViolation(a, i); why != "" {
			return why
		}
	}
	for _, k := range []string{"protocol_name", "instruction_name", "summary"} {
		if !isStr(v[k]) {
			return fmt.Sprintf("`%s` must be a string", k)
		}
	}
	for _, k := range []string{"manifest_found", "unknown_protocol"} {
		if !isBool(v[k]) {
			return fmt.Sprintf("`%s` must be a boolean", k)
		}
	}
	// Always emitted, possibly null: absent is a different answer from null.
	mv, has := v["manifest_version"]
	if !nullOr(mv, has, isStr) {
		return "`manifest_version` must be a string or null"
	}
	sf, has := v["simulation_flagged"]
	if !nullOr(sf, has, isBool) {
		return "`simulation_flagged` must be a boolean or null"
	}
	sd, has := v["simulation_divergence"]
	if !nullOr(sd, has, isNum) {
		return "`simulation_divergence` must be a number or null"
	}
	layers, ok := v["layers"].([]any)
	if !ok {
		return "`layers` must be an array"
	}
	for _, l := range layers {
		if why := layerViolation(l); why != "" {
			return why
		}
	}
	if pu, has := v["program_upgrades"]; has {
		ups, ok := pu.([]any)
		if !ok {
			return "`program_upgrades` must be an array"
		}
		for _, u := range ups {
			m, ok := asObject(u)
			pua, hasPUA := m["previous_upgrade_authority"]
			ua, hasUA := m["upgrade_authority"]
			if !ok || !isStr(m["program_id"]) || !isCount(m["previous_deploy_slot"]) || !isCount(m["deploy_slot"]) ||
				!nullOr(pua, hasPUA, isStr) || !nullOr(ua, hasUA, isStr) || !isBool(m["quarantined"]) {
				return "each `program_upgrades` entry must match the schema's ProgramUpgrade"
			}
		}
	}
	scope, has := v["scope"]
	if !has {
		return "`scope` is missing: the verdict does not say what it is bound to"
	}
	if why := scopeViolation(scope); why != "" {
		return why
	}
	return decisionViolation(v, approved)
}

// decisionViolation checks Round 30's decision, executable and
// instruction_bind_key. Optional, so a server older than Round 30 still
// decodes (IsExecutable then recomputes alone); when present they must be
// known, agree with each other and with approved, and a server claiming
// executable must agree with the rule recomputed from the verdict's own
// fields. A server stricter than the rule is accepted: that is never the
// dangerous direction.
func decisionViolation(v map[string]any, approved bool) string {
	if k, has := v["instruction_bind_key"]; has {
		if s, ok := k.(string); !ok || s != v["content_hash"] {
			return "`instruction_bind_key` must be a string equal to `content_hash`"
		}
	}
	d, hasD := v["decision"]
	e, hasE := v["executable"]
	if !hasD && !hasE {
		return ""
	}
	if !oneOf(d, ExecutionDecisions...) {
		return "`decision` must be one of " + strings.Join(ExecutionDecisions, ", ")
	}
	executable, ok := e.(bool)
	if !ok {
		return "`executable` must be a boolean beside `decision`"
	}
	if executable != (d == DecisionExecutableApproved) {
		return "`executable` must be true exactly when `decision` is \"executable_approved\""
	}
	if approved != (d == DecisionExecutableApproved || d == DecisionAnalysisOnly) {
		return "`decision` contradicts `approved`"
	}
	if executable {
		// The shape is valid by now; decode it to recompute the rule.
		raw, err := json.Marshal(v)
		var r VerificationResult
		if err != nil || json.Unmarshal(raw, &r) != nil ||
			r.ComputeExecutionDecision() != DecisionExecutableApproved {
			return "`executable` is true but the verdict's own fields do not permit execution (not artifact-bound and simulated, a non-inherent residual, or a failed layer)"
		}
	}
	return ""
}

func transactionViolation(value any) string {
	t, ok := asObject(value)
	if !ok {
		return "`transaction` must be an object"
	}
	for _, k := range []string{"program_id", "protocol_version", "instruction_name", "instruction_discriminator", "data_hex"} {
		if !isStr(t[k]) {
			return fmt.Sprintf("`transaction.%s` must be a string", k)
		}
	}
	for _, k := range []string{"instruction_count", "account_count", "signer_count", "writable_count", "compute_budget_units", "data_len"} {
		if !isCount(t[k]) {
			return fmt.Sprintf("`transaction.%s` must be a non-negative integer", k)
		}
	}
	accts, ok := t["accounts"].([]any)
	if !ok {
		return "`transaction.accounts` must be an array"
	}
	for _, a := range accts {
		m, ok := asObject(a)
		if !ok || !isStr(m["address"]) || !isBool(m["is_signer"]) || !isBool(m["is_writable"]) {
			return "`transaction.accounts` must be an array of { address, is_signer, is_writable }"
		}
	}
	return ""
}

func resolvedAccountViolation(value any, i int) string {
	at := fmt.Sprintf("`resolved_accounts[%d]`", i)
	a, ok := asObject(value)
	if !ok {
		return at + " must be an object"
	}
	if !isStr(a["address"]) || !isStr(a["role"]) {
		return at + " must carry string `address` and `role`"
	}
	if n, has := a["name"]; has && !isStr(n) {
		return at + ".name must be a string"
	}
	if !isStrArray(a["pda_seeds"]) {
		return at + ".pda_seeds must be an array of strings"
	}
	// The three mismatch flags are security signals the Core always emits;
	// an absent one is not "no mismatch".
	for _, k := range []string{"is_pda", "is_signer", "is_writable", "pda_mismatch", "expected_address_mismatch", "privilege_mismatch"} {
		if !isBool(a[k]) {
			return fmt.Sprintf("%s.%s must be a boolean", at, k)
		}
	}
	if !oneOf(a["identity"], string(AccountIdentityPda), string(AccountIdentityConstant), string(AccountIdentityUnverified)) {
		return at + ".identity must be pda, constant or unverified"
	}
	return ""
}

func layerViolation(value any) string {
	l, ok := asObject(value)
	if !ok || !isStr(l["layer"]) || !isBool(l["passed"]) || !isStr(l["reason"]) {
		return "each layer must carry `layer` (string), `passed` (boolean) and `reason` (string)"
	}
	if !oneOf(l["status"], "passed", "failed", "inconclusive") {
		return "each layer's `status` must be \"passed\", \"failed\" or \"inconclusive\""
	}
	if l["passed"].(bool) != (l["status"] == "passed") {
		// The Core derives passed from status at construction
		// (GAP-2026-08-06-3); a layer where they disagree did not come from it.
		return fmt.Sprintf("layer %v: `passed` must be true exactly when `status` is \"passed\"", l["layer"])
	}
	return ""
}

var artifactFields = []string{"transaction_sha256", "transaction_bytes", "simulated", "compute_budget", "message_version"}

func scopeViolation(value any) string {
	s, ok := asObject(value)
	if !ok {
		return "`scope` must be an object"
	}
	if !oneOf(s["kind"], "artifact_bound", "descriptive") {
		return "`scope.kind` must be \"artifact_bound\" or \"descriptive\""
	}
	prose, ok := s["unobserved"].([]any)
	if !ok || len(prose) == 0 || !isStrArray(prose) {
		return "`scope.unobserved` must be a non-empty array of strings"
	}
	codes, ok := s["unobserved_codes"].([]any)
	if !ok || !isStrArray(codes) {
		return "`scope.unobserved_codes` must be an array of strings"
	}
	for _, c := range codes {
		if !oneOf(c, unobservedCodes...) {
			return fmt.Sprintf("`scope.unobserved_codes` has an unknown code %q", c)
		}
	}
	if len(codes) != len(prose) {
		return "`scope.unobserved_codes` must name each entry of `scope.unobserved`"
	}
	if s["kind"] == "descriptive" {
		for _, f := range artifactFields {
			if _, has := s[f]; has {
				return fmt.Sprintf("a descriptive `scope` must not carry `%s`: nothing was bound", f)
			}
		}
		return ""
	}
	if sha, _ := s["transaction_sha256"].(string); !isLowerHex64(sha) {
		return "`scope.transaction_sha256` must be 64 lowercase hex characters"
	}
	if !isCount(s["transaction_bytes"]) || s["transaction_bytes"] == json.Number("0") {
		return "`scope.transaction_bytes` must be a positive integer"
	}
	if !isBool(s["simulated"]) {
		return "`scope.simulated` must be a boolean"
	}
	if mv, has := s["message_version"]; has && !oneOf(mv, "legacy", "v0", "v1") {
		return "`scope.message_version` must be \"legacy\", \"v0\" or \"v1\""
	}
	if cb, has := s["compute_budget"]; has {
		m, ok := asObject(cb)
		if !ok || !oneOf(m["source"], "v1_header", "compute_budget_instructions") ||
			!isCount(m["effective_compute_unit_limit"]) || !isCount(m["priority_fee_lamports"]) {
			return "`scope.compute_budget` must carry its source, effective limit and priority fee"
		}
		for _, k := range []string{"compute_unit_limit", "compute_unit_price_micro_lamports", "heap_bytes", "loaded_accounts_data_size_limit"} {
			if x, has := m[k]; has && x != nil && !isCount(x) {
				return fmt.Sprintf("`scope.compute_budget.%s` must be a non-negative integer or null", k)
			}
		}
		if p, has := m["problems"]; has && !isStrArray(p) {
			return "`scope.compute_budget.problems` must be an array of strings"
		}
	}
	return ""
}

// ─── the other routes ───

func healthViolation(value any) string {
	h, ok := asObject(value)
	if !ok {
		return "health response must be a JSON object"
	}
	for _, k := range []string{"status", "service", "version"} {
		if !isStr(h[k]) {
			return fmt.Sprintf("`%s` must be a string", k)
		}
	}
	if d, has := h["degraded"]; has && !isBool(d) {
		return "`degraded` must be a boolean"
	}
	if r, has := h["degraded_reasons"]; has && !isStrArray(r) {
		return "`degraded_reasons` must be an array of strings"
	}
	return ""
}

func manifestListViolation(value any) string {
	list, ok := value.([]any)
	if !ok {
		return "manifest list must be a JSON array"
	}
	for i, item := range list {
		at := fmt.Sprintf("manifest %d", i)
		m, ok := asObject(item)
		if !ok || !isStr(m["graphite_manifest_version"]) {
			return at + ": must be an object with a string `graphite_manifest_version`"
		}
		p, ok := asObject(m["protocol"])
		if !ok || !isStr(p["name"]) || !isStr(p["program_id"]) {
			return at + ": `protocol` must carry string `name` and `program_id`"
		}
		ver, ok := asObject(m["version"])
		if !ok || !isStr(ver["label"]) {
			return at + ": `version` must carry a string `label`"
		}
		ixs, ok := m["instructions"].([]any)
		if !ok {
			return at + ": `instructions` must be an array"
		}
		for _, ix := range ixs {
			x, ok := asObject(ix)
			if !ok || !isStr(x["name"]) || !isStr(x["discriminator"]) || !isStrArray(x["expected_state_changes"]) ||
				!isStrArray(x["allowed_cpis"]) || !isStrArray(x["risk_rules"]) {
				return at + ": every instruction must match the manifest schema"
			}
			accts, ok := x["accounts"].([]any)
			if !ok {
				return at + ": every instruction must carry `accounts`"
			}
			for _, a := range accts {
				am, ok := asObject(a)
				if !ok || !isStr(am["name"]) || !isStr(am["role"]) || !isBool(am["is_writable"]) || !isBool(am["is_signer"]) {
					return at + ": every account role must be { name, role, is_writable, is_signer }"
				}
			}
		}
	}
	return ""
}

func lifecycleReceiptViolation(value any, sent *LifecycleEventInput) string {
	r, ok := asObject(value)
	if !ok {
		return "lifecycle receipt must be a JSON object"
	}
	if r["recorded"] != true {
		return "`recorded` must be true"
	}
	if !oneOf(r["event_type"], LifecycleSigning, LifecycleSubmission, LifecycleConfirmation, LifecycleFinalization) {
		return "`event_type` must be a caller-reported lifecycle stage"
	}
	if !isStr(r["content_hash"]) {
		return "`content_hash` must be a string"
	}
	if !oneOf(r["verdict_on_record"], VerdictOnRecordApproved, VerdictOnRecordBlocked, VerdictOnRecordNotFound) {
		return "`verdict_on_record` must be \"approved\", \"blocked\" or \"not_found\""
	}
	if !oneOf(r["verdict_on_record_key"], "audit_trail_id", "transaction_sha256", "content_hash") {
		return "`verdict_on_record_key` must be \"audit_trail_id\", \"transaction_sha256\" or \"content_hash\""
	}
	if a, has := r["sequence_anomalies"]; has && !isStrArray(a) {
		return "`sequence_anomalies` must be an array of strings"
	}
	if p, has := r["prior_events_on_record"]; has && !isCount(p) {
		return "`prior_events_on_record` must be a non-negative integer"
	}
	if sent != nil {
		if r["event_type"] != sent.EventType {
			return fmt.Sprintf("the receipt is for %v, not the %s event sent", r["event_type"], sent.EventType)
		}
		key := sent.InstructionBindKey
		if strings.TrimSpace(key) == "" {
			key = sent.ContentHash
		}
		if r["content_hash"] != strings.TrimSpace(key) {
			return "the receipt names a different instruction key (`content_hash`) from the one sent"
		}
	}
	return ""
}

// variantName reads a serde externally-tagged enum value: a unit variant's
// name, or the one key of a data variant's object. Empty when it is neither.
func variantName(value any, units, data []string) string {
	if s, ok := value.(string); ok {
		for _, u := range units {
			if s == u {
				return s
			}
		}
		return ""
	}
	m, ok := asObject(value)
	if !ok || len(m) != 1 {
		return ""
	}
	for k := range m {
		for _, d := range data {
			if k == d {
				return k
			}
		}
	}
	return ""
}

var (
	reconciliationUnits = []string{"ApprovedAndExecuted", "BlockedButExecuted", "BlockedAndNotExecuted", "NotFound", "NoVerificationOnRecord"}
	reconciliationData  = []string{"ApprovedButFailedOnChain", "RecordedForDifferentBytes", "Unavailable"}
	chainStatusData     = []string{"Confirmed", "UnknownSignature", "Unavailable"}
)

func executionResultViolation(value any, sent *ExecutionCheckInput) string {
	r, ok := asObject(value)
	if !ok {
		return "execution check result must be a JSON object"
	}
	if !isStr(r["signature"]) {
		return "`signature` must be a string"
	}
	if variantName(r["chain_status"], nil, chainStatusData) == "" {
		return "`chain_status` must be one of Confirmed, UnknownSignature or Unavailable"
	}
	rec := variantName(r["reconciliation"], reconciliationUnits, reconciliationData)
	if rec == "" {
		return "`reconciliation` is not an ExecutionReconciliation"
	}
	disc, ok := r["discrepancy"].(bool)
	if !ok {
		return "`discrepancy` must be a boolean"
	}
	// BlockedButExecuted is the one discrepancy since the audit of
	// 2026-10-20 (F5): a cited verdict about other bytes is reported in
	// caller_keys_disagree, never as an alarm.
	expected := rec == "BlockedButExecuted"
	if disc != expected {
		return fmt.Sprintf("`discrepancy` must be %v for a %s reconciliation", expected, rec)
	}
	ra, has := r["recorded_approved"]
	if !nullOr(ra, has, isBool) {
		return "`recorded_approved` must be a boolean or null"
	}
	for _, k := range []string{"recorded_audit_trail_id", "recorded_transaction_sha256", "chain_transaction_sha256"} {
		x, has := r[k]
		if !nullOr(x, has, isStr) {
			return fmt.Sprintf("`%s` must be a string or null", k)
		}
	}
	if !oneOf(r["attribution"], "chain", "audit_trail_id", "transaction_sha256", "content_hash", "none") {
		return "`attribution` must be chain, audit_trail_id, transaction_sha256, content_hash or none"
	}
	if !isStrArray(r["caller_keys_disagree"]) {
		return "`caller_keys_disagree` must be an array of strings"
	}
	for _, k := range []string{"chain_bytes_rejected", "chain_bytes_unavailable", "chain_inconsistent"} {
		if x, has := r[k]; has && x != nil && !isStr(x) {
			return fmt.Sprintf("`%s` must be a string or null", k)
		}
	}
	if w, has := r["inclusion_witness"]; has && w != nil {
		m, ok := asObject(w)
		seen, hasSeen := m["seen"]
		if !ok || !isBool(m["agrees"]) || !nullOr(seen, hasSeen, isBool) || !isStr(m["detail"]) {
			return "`inclusion_witness` must be { agrees, seen, detail } or null"
		}
	}
	// Round 30: optional (older servers do not send it); when sent, one of
	// the five labels.
	if a, has := r["inclusion_assurance"]; has && !oneOf(a, "single_provider", "witnessed", "witnessed_not_independent", "witness_disputed", "witness_unavailable") {
		return "`inclusion_assurance` must be single_provider, witnessed, witnessed_not_independent, witness_disputed or witness_unavailable"
	}
	if rv, has := r["recorded_verdicts"]; has && rv != nil {
		m, ok := asObject(rv)
		if !ok || !isCount(m["approved"]) || !isCount(m["refused"]) {
			return "`recorded_verdicts` must be { approved, refused } counts or null"
		}
	}
	if !isBool(r["audit_recorded"]) {
		return "`audit_recorded` must be a boolean"
	}
	if sent != nil && r["signature"] != strings.TrimSpace(sent.Signature) {
		return "the result is about a different signature from the one sent"
	}
	return ""
}
