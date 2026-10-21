package graphite

// Audit 2026-10-20: G1 (Verify validated nothing, and encoding/json read
// keys case-insensitively), G2 (the zero-value input and the Custom
// profile), the timeout of a Client literal, context variants, bounded
// bodies, ByteArray, the loopback rule, and the lifecycle/L8 methods.
// Loopback httptest servers only.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// sampleMap is the committed example verdict (blocked, descriptive).
func sampleMap(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../examples/sample-verification-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// approvedMap is the sample turned into an artifact-bound approval.
func approvedMap(t *testing.T) map[string]any {
	m := sampleMap(t)
	m["approved"] = true
	m["policy_verdict"] = "Approved"
	m["risk_verdict"] = map[string]any{"status": "Clear", "findings": []any{}}
	m["scope"] = map[string]any{
		"kind":               "artifact_bound",
		"transaction_sha256": strings.Repeat("ab", 32),
		"transaction_bytes":  215,
		"simulated":          true,
		"unobserved":         []any{"program semantics", "inner instructions"},
		"unobserved_codes":   []any{"program_semantics", "inner_instructions"},
	}
	return m
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// withExtraKey appends a raw `"key":value` to a JSON object's text, so a
// duplicate or case-variant key survives (a map would merge it).
func withExtraKey(object, key, value string) string {
	return strings.TrimSuffix(object, "}") + `,"` + key + `":` + value + "}"
}

// serve answers every request with one status and body.
func serve(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSampleAndApprovalDecode(t *testing.T) {
	for name, m := range map[string]map[string]any{"sample": sampleMap(t), "approval": approvedMap(t)} {
		r, err := DecodeVerificationResult([]byte(mustJSON(t, m)))
		if err != nil {
			t.Fatalf("%s must decode: %v", name, err)
		}
		if r.Approved != (name == "approval") || r.Scope == nil {
			t.Fatalf("%s decoded wrong: %+v", name, r)
		}
	}
}

func TestVerifyRefusesWhatTheCoreNeverSends(t *testing.T) {
	good := mustJSON(t, approvedMap(t))
	blocked := mustJSON(t, sampleMap(t))
	change := func(edit func(m map[string]any)) string {
		m := approvedMap(t)
		edit(m)
		return mustJSON(t, m)
	}
	cases := map[string]string{
		"approved alone":            `{"approved":true}`,
		"approved beside Blocked":   change(func(m map[string]any) { m["risk_verdict"] = map[string]any{"status": "Blocked", "findings": []any{}} }),
		"approved beside Rejected":  change(func(m map[string]any) { m["policy_verdict"] = "Rejected" }),
		"no scope":                  change(func(m map[string]any) { delete(m, "scope") }),
		"no layers":                 change(func(m map[string]any) { delete(m, "layers") }),
		"no manifest_version":       change(func(m map[string]any) { delete(m, "manifest_version") }),
		"bound without digest":      change(func(m map[string]any) { delete(m["scope"].(map[string]any), "transaction_sha256") }),
		"uppercase digest":          change(func(m map[string]any) { m["scope"].(map[string]any)["transaction_sha256"] = strings.Repeat("AB", 32) }),
		"codes missing":             change(func(m map[string]any) { delete(m["scope"].(map[string]any), "unobserved_codes") }),
		"codes not paired":          change(func(m map[string]any) { m["scope"].(map[string]any)["unobserved_codes"] = []any{"program_semantics"} }),
		"descriptive with a digest": change(func(m map[string]any) { s := m["scope"].(map[string]any); s["kind"] = "descriptive" }),
		"account without identity":  change(func(m map[string]any) { delete(m["resolved_accounts"].([]any)[0].(map[string]any), "identity") }),
		"layer passed beside failed": change(func(m map[string]any) {
			l := m["layers"].([]any)[0].(map[string]any)
			l["passed"], l["status"] = true, "failed"
		}),
		"confidence above 1":          change(func(m map[string]any) { m["confidence"] = 1.5 }),
		"case variant beside the key": withExtraKey(strings.Replace(good, `"approved":true`, `"approved":false`, 1), "APPROVED", "true"),
		"case variant instead":        strings.Replace(blocked, `"approved":false`, `"APPROVED":true`, 1),
		"exact duplicate":             withExtraKey(blocked, "approved", "true"),
		"Unicode fold of scope":       withExtraKey(good, "\u017fcope", `{}`),
		"case variant of optional":    withExtraKey(good, "Program_Upgrades", `[]`),
		"nested case variant":         strings.Replace(good, `"status":"Clear"`, `"status":"Clear","STATUS":"Blocked"`, 1),
		"trailing data":               good + `{}`,
		"not JSON":                    `<html>`,
	}
	if strings.Count(good, `"approved":true`) != 1 || strings.Count(blocked, `"approved":false`) != 1 {
		t.Fatal("fixture text changed shape")
	}
	for name, body := range cases {
		srv := serve(t, http.StatusOK, body)
		r, err := NewClient(srv.URL).Verify(&VerificationInput{})
		if err == nil {
			t.Errorf("%s: Verify accepted it: approved=%v", name, r.Approved)
		} else if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: want ErrInvalidResponse, got %v", name, err)
		}
	}
	// Control: the well-formed approval passes the same path.
	if _, err := NewClient(serve(t, http.StatusOK, good).URL).Verify(&VerificationInput{}); err != nil {
		t.Fatalf("a well-formed approval must be accepted: %v", err)
	}
}

func TestIsArtifactBoundRequiresADigest(t *testing.T) {
	for _, sha := range []string{"", "ab", strings.Repeat("AB", 32), strings.Repeat("ab", 31) + "zz"} {
		r := &VerificationResult{Scope: &VerificationScope{Kind: "artifact_bound", TransactionSHA256: sha}}
		if r.IsArtifactBound() {
			t.Errorf("digest %q must not count as a binding", sha)
		}
	}
	r := &VerificationResult{Scope: &VerificationScope{Kind: "artifact_bound", TransactionSHA256: strings.Repeat("ab", 32)}}
	if !r.IsArtifactBound() {
		t.Error("a well-formed binding must count")
	}
}

// G2: what the SDK sends is what serde accepts. testdata/wire_inputs.json is
// also deserialized by graphite-core/tests/go_sdk_wire_inputs.rs, so both
// sides are held to the same bytes.
func TestInputsMarshalToTheWireTheCoreAccepts(t *testing.T) {
	raw, err := os.ReadFile("testdata/wire_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]any
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	transfer := func() VerificationInput {
		return VerificationInput{
			ProposedIntent:           ProposedIntent{IntentType: "transfer", RawNaturalLanguage: "send SOL", ConfidenceOfParse: 0.95},
			ProgramID:                "11111111111111111111111111111111",
			ProtocolVersion:          "1.0.0",
			InstructionDiscriminator: "02000000",
			AccountAddresses:         []string{"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"},
			ComputeUnits:             150,
			AccountWrites:            2,
		}
	}
	custom := transfer()
	custom.CustomWalletProfile = &CustomProfile{MinConfidence: 0.7, MinTrustTier: TrustTierOfficialManifest}
	preset := transfer()
	preset.WalletProfile = WalletProfileGaming
	for name, in := range map[string]VerificationInput{"zero_value": {}, "custom": custom, "preset": preset} {
		var got any
		if err := json.Unmarshal([]byte(mustJSON(t, &in)), &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, golden[name]) {
			t.Errorf("%s:\n got  %s\n want %s", name, mustJSON(t, got), mustJSON(t, golden[name]))
		}
		// And it reads back as itself.
		var back VerificationInput
		if err := json.Unmarshal([]byte(mustJSON(t, &in)), &back); err != nil {
			t.Fatalf("%s: read back: %v", name, err)
		}
		if name != "zero_value" && !reflect.DeepEqual(back, in) {
			t.Errorf("%s: round trip changed it: %+v", name, back)
		}
	}
	both := preset
	both.CustomWalletProfile = custom.CustomWalletProfile
	for name, in := range map[string]VerificationInput{
		"both profiles":  both,
		"unknown name":   {WalletProfile: "gaming"},
		"bad confidence": {CustomWalletProfile: &CustomProfile{MinConfidence: 1.5, MinTrustTier: TrustTierUnknown}},
		"bad tier":       {CustomWalletProfile: &CustomProfile{MinConfidence: 0.5, MinTrustTier: "Trusted"}},
	} {
		if _, err := json.Marshal(&in); err == nil {
			t.Errorf("%s: must be refused before it is sent", name)
		}
	}
}

func TestAClientLiteralHasTheDefaultTimeoutAndRefusesRedirects(t *testing.T) {
	c := &Client{BaseURL: "https://graphite.internal"}
	hc := c.httpClient()
	if hc == http.DefaultClient || hc.Timeout != DefaultTimeout || hc.CheckRedirect == nil {
		t.Fatalf("a nil HTTPClient must mean NewClient's client, got timeout %v", hc.Timeout)
	}
	if NewClient("https://x").HTTPClient.Timeout != DefaultTimeout {
		t.Fatal("NewClient must use DefaultTimeout")
	}
}

func TestContextDeadlineAbandonsAHungCall(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	c := NewClient(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := c.VerifyContext(ctx, &VerificationInput{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want a deadline error, got %v", err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("the call was not bounded by its context")
	}
}

func TestErrorAndResponseBodiesAreBounded(t *testing.T) {
	huge := strings.Repeat("x", 1<<20)
	_, err := NewClient(serve(t, http.StatusInternalServerError, huge).URL).Verify(&VerificationInput{})
	if err == nil || len(err.Error()) > 2*maxErrorBodyBytes || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("a non-200 body must be bounded in the error, got %d bytes", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("the status must be in the error: %v", err)
	}
	over := `"` + strings.Repeat("y", MaxResponseBytes) + `"`
	if _, err := NewClient(serve(t, http.StatusOK, over).URL).Verify(&VerificationInput{}); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("a body over MaxResponseBytes must be refused, got %v", err)
	}
}

func TestVerifyRefusesANon200(t *testing.T) {
	for _, status := range []int{400, 401, 413, 429, 500, 503} {
		srv := serve(t, status, `{"error":"refused"}`)
		if _, err := NewClient(srv.URL).Verify(&VerificationInput{}); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Errorf("status %d: want an error carrying the server's answer, got %v", status, err)
		}
	}
}

func TestByteArrayRefusesWhatIsNotAByte(t *testing.T) {
	var ok ByteArray
	if err := json.Unmarshal([]byte(`[0, 1, 255]`), &ok); err != nil || len(ok) != 3 || ok[2] != 255 {
		t.Fatalf("bytes must decode: %v %v", ok, err)
	}
	for _, bad := range []string{`[1.5]`, `[-1]`, `[256]`, `[1e2]`, `["1"]`, `[null]`, `[1.0]`} {
		var b ByteArray
		if err := json.Unmarshal([]byte(bad), &b); err == nil {
			t.Errorf("%s decoded as %v; it is not an array of bytes", bad, b)
		}
	}
}

func TestIPv4MappedLoopbackIsLoopbackInBothSDKs(t *testing.T) {
	for _, base := range []string{"http://[::ffff:127.0.0.1]:7331", "http://[::ffff:7f00:1]", "http://[0:0:0:0:0:ffff:127.1.2.3]"} {
		if err := CheckBaseURL(base); err != nil {
			t.Errorf("%s must be accepted: %v", base, err)
		}
	}
	for _, base := range []string{"http://[::ffff:10.0.0.1]", "http://[::ffff:128.0.0.1]", "http://[::127.0.0.1]", "http://[::ffff:7f:1]"} {
		if err := CheckBaseURL(base); err == nil {
			t.Errorf("%s must be refused", base)
		}
	}
}

const signature = "5555555555555555555555555555555555555555555555555555555555555555555555555555555555555555"

func receiptJSON(eventType string) string {
	return `{"recorded":true,"event_type":"` + eventType + `","content_hash":"48c65c638aceb5de",` +
		`"verdict_on_record":"approved","verdict_on_record_key":"audit_trail_id","sequence_anomalies":[],"prior_events_on_record":0}`
}

func executionJSON(reconciliation string, discrepancy bool) string {
	d := "false"
	if discrepancy {
		d = "true"
	}
	return `{"signature":"` + signature + `","chain_status":{"Confirmed":{"signature":"` + signature +
		`","slot":1,"success":true,"error":null,"commitment":"finalized"}},"recorded_approved":true,` +
		`"recorded_audit_trail_id":"gr-x","recorded_transaction_sha256":null,"reconciliation":` + reconciliation +
		`,"discrepancy":` + d + `,"attribution":"chain","chain_transaction_sha256":null,"caller_keys_disagree":[],` +
		`"chain_bytes_rejected":null,"chain_bytes_unavailable":null,"chain_inconsistent":null,"inclusion_witness":null,` +
		`"recorded_verdicts":{"approved":1,"refused":0},"audit_recorded":true}`
}

func TestRecordLifecycleEventIsCheckedLikeAVerdict(t *testing.T) {
	event := &LifecycleEventInput{EventType: LifecycleSigning, ContentHash: "48c65c638aceb5de", AuditTrailID: "gr-x"}
	r, err := NewClient(serve(t, http.StatusOK, receiptJSON("signing")).URL).RecordLifecycleEvent(event)
	if err != nil || !r.Recorded || r.VerdictOnRecord != VerdictOnRecordApproved {
		t.Fatalf("a well-formed receipt must be accepted: %+v %v", r, err)
	}
	for name, body := range map[string]string{
		"not recorded":        strings.Replace(receiptJSON("signing"), `"recorded":true`, `"recorded":false`, 1),
		"another event":       receiptJSON("submission"),
		"another hash":        strings.Replace(receiptJSON("signing"), "48c65c638aceb5de", "0000000000000000", 1),
		"unknown verdict":     strings.Replace(receiptJSON("signing"), `"approved"`, `"maybe"`, 1),
		"case-variant record": withExtraKey(strings.Replace(receiptJSON("signing"), `"recorded":true`, `"recorded":false`, 1), "Recorded", "true"),
		"not JSON":            "ok",
	} {
		if _, err := NewClient(serve(t, http.StatusOK, body).URL).RecordLifecycleEvent(event); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if _, err := NewClient(serve(t, http.StatusServiceUnavailable, `{"error":"audit write failed"}`).URL).RecordLifecycleEvent(event); err == nil ||
		!strings.Contains(err.Error(), "audit write failed") {
		t.Errorf("a 503 means the event was not recorded: %v", err)
	}
}

func TestVerifyExecutionIsCheckedLikeAVerdict(t *testing.T) {
	in := &ExecutionCheckInput{Signature: signature, AuditTrailID: "gr-x"}
	r, err := NewClient(serve(t, http.StatusOK, executionJSON(`"ApprovedAndExecuted"`, false)).URL).VerifyExecution(in)
	if err != nil || r.ReconciliationVariant() != "ApprovedAndExecuted" || r.Discrepancy {
		t.Fatalf("a well-formed answer must be accepted: %+v %v", r, err)
	}
	r, err = NewClient(serve(t, http.StatusOK, executionJSON(`"BlockedButExecuted"`, true)).URL).VerifyExecution(in)
	if err != nil || !r.Discrepancy {
		t.Fatalf("the alarm must come through: %+v %v", r, err)
	}
	for name, body := range map[string]string{
		"alarm dropped": executionJSON(`"BlockedButExecuted"`, false),
		// Only BlockedButExecuted is a discrepancy (audit 2026-10-20, F5).
		"cited other bytes alarmed": executionJSON(`{"RecordedForDifferentBytes":{"recorded_approved":false,"recorded_transaction_sha256":null,"chain_transaction_sha256":"ab"}}`, true),
		"unknown outcome":           executionJSON(`"Fine"`, false),
		"another signature":         strings.ReplaceAll(executionJSON(`"ApprovedAndExecuted"`, false), signature, strings.Repeat("4", 88)),
		"empty object":              `{}`,
		"not JSON":                  `<html>`,
	} {
		if _, err := NewClient(serve(t, http.StatusOK, body).URL).VerifyExecution(in); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if _, err := NewClient(serve(t, http.StatusServiceUnavailable, `{"error":"audit write failed","outcome":{}}`).URL).VerifyExecution(in); err == nil {
		t.Error("a 503 must be an error")
	}
}

func TestHealthAndManifestsRefuseAMalformed200(t *testing.T) {
	if _, err := NewClient(serve(t, http.StatusOK, `{"status":"ok","service":"graphite-core","version":"0.3.0-beta","degraded":false}`).URL).HealthContext(context.Background()); err != nil {
		t.Fatalf("a well-formed health answer must be accepted: %v", err)
	}
	for _, body := range []string{`<html>`, `{}`, `[]`, `{"status":1,"service":"s","version":"v"}`} {
		if err := NewClient(serve(t, http.StatusOK, body).URL).Health(); err == nil {
			t.Errorf("health %s: must be refused", body)
		}
	}
	for _, body := range []string{`<html>`, `{}`, `[{}]`, `[{"graphite_manifest_version":"1","protocol":{"name":"n","program_id":"p"},"version":{"label":"1"},"instructions":[{"name":"x"}]}]`} {
		if _, err := NewClient(serve(t, http.StatusOK, body).URL).ListManifests(); err == nil {
			t.Errorf("manifests %s: must be refused", body)
		}
	}
}
