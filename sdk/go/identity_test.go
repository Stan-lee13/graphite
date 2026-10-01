package graphite

// A5-03 (2026-09-30 audit): the Core serializes AccountIdentity snake_case
// (`#[serde(rename_all = "snake_case")]` in
// graphite-core/src/account_resolution.rs), while these constants and the
// published schema said "Pda" / "Constant" / "Unverified". A consumer
// comparing against the constants never matched a real verdict. This pins
// the constants to the wire, to the schema, and to the committed example.

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

func TestAccountIdentityConstantsAreTheCoresWireValues(t *testing.T) {
	want := map[AccountIdentity]string{
		AccountIdentityPda:        "pda",
		AccountIdentityConstant:   "constant",
		AccountIdentityUnverified: "unverified",
	}
	for got, wire := range want {
		if string(got) != wire {
			t.Errorf("constant %q, the Core serializes %q", got, wire)
		}
		var acct ResolvedAccount
		if err := json.Unmarshal([]byte(`{"address":"x","identity":"`+wire+`"}`), &acct); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if acct.Identity != got {
			t.Errorf("wire identity %q decoded to %q, not the constant %q", wire, acct.Identity, got)
		}
	}
}

func TestAccountIdentityConstantsMatchTheSchemaEnum(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/verification-result-v1.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Properties struct {
			ResolvedAccounts struct {
				Items struct {
					Properties struct {
						Identity struct {
							Enum []string `json:"enum"`
						} `json:"identity"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"resolved_accounts"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	got := schema.Properties.ResolvedAccounts.Items.Properties.Identity.Enum
	sort.Strings(got)
	want := []string{string(AccountIdentityConstant), string(AccountIdentityPda), string(AccountIdentityUnverified)}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schema identity enum %v, SDK constants %v", got, want)
	}
}

func TestSampleVerdictIdentitiesAreSDKConstants(t *testing.T) {
	raw, err := os.ReadFile("../../examples/sample-verification-result.json")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	var result VerificationResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("parse example: %v", err)
	}
	if len(result.ResolvedAccounts) == 0 {
		t.Fatal("the example carries no resolved accounts to check")
	}
	for i, acct := range result.ResolvedAccounts {
		switch acct.Identity {
		case AccountIdentityPda, AccountIdentityConstant, AccountIdentityUnverified:
		default:
			t.Errorf("resolved_accounts[%d].identity %q matches no SDK constant", i, acct.Identity)
		}
	}
}

// The Core emits the manifest slot's name on each resolved account and omits
// it when empty (`skip_serializing_if = "String::is_empty"`); the SDK reads it
// and, like the Core, leaves it out when empty.
func TestResolvedAccountNameIsReadAndOmittedWhenEmpty(t *testing.T) {
	var acct ResolvedAccount
	if err := json.Unmarshal([]byte(`{"address":"x","role":"writable","name":"source","identity":"unverified"}`), &acct); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if acct.Name != "source" {
		t.Fatalf("name %q, want %q", acct.Name, "source")
	}
	out, err := json.Marshal(ResolvedAccount{Address: "x", Identity: AccountIdentityUnverified})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(out, &fields); err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if _, present := fields["name"]; present {
		t.Fatalf("an empty name must be omitted, got %s", out)
	}
}
