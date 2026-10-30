package graphite

// Round 30 (G-01): sign only on IsExecutable, and this SDK's copy of the rule
// gives the Core's answer. examples/decisions/<decision>.json are real
// verdicts the Core produced (graphite-core/tests/round30_decision_fixtures.rs);
// the TypeScript SDK reads the same files.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func decisionFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../examples/decisions/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeFixture(t *testing.T, name string) *VerificationResult {
	t.Helper()
	r, err := DecodeVerificationResult(decisionFixture(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func TestEachCommittedVerdictRecomputesTheCoresDecision(t *testing.T) {
	for _, d := range ExecutionDecisions {
		r := decodeFixture(t, d)
		if r.Decision != d {
			t.Fatalf("%s: the fixture says %q", d, r.Decision)
		}
		if got := r.ComputeExecutionDecision(); got != d {
			t.Errorf("%s: the SDK's rule says %q", d, got)
		}
		if r.IsExecutable() != (d == DecisionExecutableApproved) {
			t.Errorf("%s: IsExecutable() = %v", d, r.IsExecutable())
		}
		if r.Executable == nil || *r.Executable != (d == DecisionExecutableApproved) {
			t.Errorf("%s: executable %v", d, r.Executable)
		}
		if r.BindKey() != r.ContentHash || r.InstructionBindKey != r.ContentHash {
			t.Errorf("%s: instruction_bind_key %q, content_hash %q", d, r.InstructionBindKey, r.ContentHash)
		}
	}
}

func fixtureMap(t *testing.T, name string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(decisionFixture(t, name), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func decodeMap(t *testing.T, m map[string]any) (*VerificationResult, error) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return DecodeVerificationResult(b)
}

// An approval nothing simulated claims permission: the decoder refuses it,
// and IsExecutable on a hand-built copy says no.
func TestAnAnalysisOnlyApprovalEditedIntoPermissionIsRefused(t *testing.T) {
	r := decodeFixture(t, DecisionAnalysisOnly)
	if !r.Approved || r.IsExecutable() {
		t.Fatal("control: approved, not executable")
	}
	m := fixtureMap(t, DecisionAnalysisOnly)
	m["decision"], m["executable"] = DecisionExecutableApproved, true
	if _, err := decodeMap(t, m); err == nil || !strings.Contains(err.Error(), "do not permit execution") {
		t.Fatalf("a forged executable decoded: %v", err)
	}
	forged := *r
	yes := true
	forged.Decision, forged.Executable = DecisionExecutableApproved, &yes
	if forged.IsExecutable() {
		t.Fatal("a forged decision was taken")
	}
}

func TestTheRuleTakesPermissionAwayFieldByField(t *testing.T) {
	base := decodeFixture(t, DecisionExecutableApproved)
	if !base.IsExecutable() {
		t.Fatal("control: the executable fixture is executable")
	}
	clone := func() *VerificationResult {
		var c VerificationResult
		b, _ := json.Marshal(base)
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		return &c
	}
	no := false
	cases := map[string]func(r *VerificationResult){
		"not simulated": func(r *VerificationResult) { r.Scope.Simulated = false },
		"a non-inherent residual": func(r *VerificationResult) {
			r.Scope.Unobserved = append(r.Scope.Unobserved, "lookup tables")
			r.Scope.UnobservedCodes = append(r.Scope.UnobservedCodes, UnobservedLookupTablesUnresolved)
		},
		"prose without a code": func(r *VerificationResult) { r.Scope.Unobserved = append(r.Scope.Unobserved, "x") },
		"no codes":             func(r *VerificationResult) { r.Scope.UnobservedCodes = nil },
		"a failed layer":       func(r *VerificationResult) { r.Layers[0].Status = "failed" },
		"no layers":            func(r *VerificationResult) { r.Layers = nil },
		"risk Blocked":         func(r *VerificationResult) { r.RiskVerdict.Status = "Blocked" },
		"policy Rejected":      func(r *VerificationResult) { r.PolicyVerdict = "Rejected" },
		"descriptive": func(r *VerificationResult) {
			r.Scope = &VerificationScope{Kind: "descriptive", Unobserved: []string{"x"}, UnobservedCodes: []string{UnobservedNoArtifact}}
		},
		"a malformed digest":            func(r *VerificationResult) { r.Scope.TransactionSHA256 = "zz" },
		"no scope":                      func(r *VerificationResult) { r.Scope = nil },
		"an unknown decision":           func(r *VerificationResult) { r.Decision = "approved" },
		"executable false":              func(r *VerificationResult) { r.Executable = &no },
		"decision without executable":   func(r *VerificationResult) { r.Executable = nil },
		"the server says analysis_only": func(r *VerificationResult) { r.Decision, r.Executable = DecisionAnalysisOnly, &no },
	}
	for what, edit := range cases {
		r := clone()
		edit(r)
		if r.IsExecutable() {
			t.Errorf("%s must take executable away", what)
		}
	}
	var nilResult *VerificationResult
	if nilResult.IsExecutable() {
		t.Error("nil is not executable")
	}
}

// Re-pinned in Round 39 (R39-CLIENTS-1). This test was
// TestAServerOlderThanRound30IsJudgedByTheRecomputation and asserted the
// verdict below EXECUTABLE. The Core's own is_executable reads an absent
// decision as blocked (serde default), the agent guard refuses it (Round 34),
// and a server that old predates every rule added since — so the SDK was
// looser than the Core. It still decodes; it is never executable.
func TestAServerOlderThanRound30DecodesAndIsNeverExecutable(t *testing.T) {
	m := fixtureMap(t, DecisionExecutableApproved)
	delete(m, "decision")
	delete(m, "executable")
	delete(m, "instruction_bind_key")
	r, err := decodeMap(t, m)
	if err != nil {
		t.Fatalf("an older server must still decode: %v", err)
	}
	if r.ComputeExecutionDecision() != DecisionExecutableApproved {
		t.Fatal("control: its own fields would permit it")
	}
	if r.IsExecutable() || r.BindKey() != r.ContentHash {
		t.Fatal("no decision was made: not executable, and keyed by content_hash")
	}
	m = fixtureMap(t, DecisionAnalysisOnly)
	delete(m, "decision")
	delete(m, "executable")
	r, err = decodeMap(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if r.IsExecutable() {
		t.Fatal("recomputed: not executable")
	}
}

func TestRefusalsAreInconclusiveOnlyOnMissingEvidence(t *testing.T) {
	base := decodeFixture(t, DecisionBlocked)
	refusal := func(patterns ...string) string {
		r := *base
		r.RiskVerdict = RiskVerdictSummary{Status: "Blocked"}
		for _, p := range patterns {
			r.RiskVerdict.Findings = append(r.RiskVerdict.Findings, RiskFinding{Pattern: p, Reason: "t"})
		}
		return r.ComputeExecutionDecision()
	}
	for want, patterns := range map[string][]string{
		DecisionInconclusive: {"VerificationIncomplete"},
		DecisionBlocked:      {"VerificationIncomplete", "DrainerPattern"},
	} {
		if got := refusal(patterns...); got != want {
			t.Errorf("%v: %q, want %q", patterns, got, want)
		}
	}
	if refusal("SimulationFailed") != DecisionBlocked || refusal() != DecisionBlocked {
		t.Error("a definite refusal is blocked")
	}
}

func TestTheDecoderRefusesADecisionThatContradictsTheVerdict(t *testing.T) {
	cases := map[string]struct {
		edit func(m map[string]any)
		want string
	}{
		"unknown decision":            {func(m map[string]any) { m["decision"] = "approved" }, "`decision` must be one of"},
		"executable on a refusal":     {func(m map[string]any) { m["executable"] = true }, "`executable` must be true exactly when"},
		"a refusal named an approval": {func(m map[string]any) { m["decision"] = DecisionAnalysisOnly }, "contradicts `approved`"},
		"decision without executable": {func(m map[string]any) { delete(m, "executable") }, "`executable` must be a boolean"},
		"bind key differs":            {func(m map[string]any) { m["instruction_bind_key"] = "0000000000000000" }, "instruction_bind_key"},
	}
	for what, c := range cases {
		m := fixtureMap(t, DecisionBlocked)
		c.edit(m)
		if _, err := decodeMap(t, m); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", what, err)
		}
	}
}
