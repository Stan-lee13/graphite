package graphite

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// Round 30: IntentTypes is the request schema's intent_type enum, in order.
func TestIntentTypesAreTheRequestSchemaEnum(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/proposed-intent-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			IntentType struct {
				Enum []string `json:"enum"`
			} `json:"intent_type"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(IntentTypes, schema.Properties.IntentType.Enum) {
		t.Fatalf("IntentTypes %v, schema %v", IntentTypes, schema.Properties.IntentType.Enum)
	}
	if !IsKnownIntentType("withdraw") || IsKnownIntentType("lend") || IsKnownIntentType("") {
		t.Fatal("IsKnownIntentType disagrees with the vocabulary")
	}
}
