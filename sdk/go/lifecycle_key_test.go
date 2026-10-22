package graphite

// Round 32 (R-M10): the lifecycle requests carry the instruction-level key
// under its Round 30 name, instruction_bind_key, and under content_hash, the
// name every earlier Core requires — the same value under both, so every
// Core reads one key. Two different values are refused before anything is
// sent. Loopback httptest servers only.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recording answers every request with one body and keeps what was sent.
func recording(t *testing.T, body string) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var sent []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		sent = append(sent, m)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &sent
}

func TestLifecycleRequestsSendTheKeyUnderBothNames(t *testing.T) {
	const key = "48c65c638aceb5de"
	srv, sent := recording(t, receiptJSON("signing"))
	c := NewClient(srv.URL)
	for _, ev := range []LifecycleEventInput{
		{EventType: LifecycleSigning, InstructionBindKey: key},
		{EventType: LifecycleSigning, ContentHash: key},
		{EventType: LifecycleSigning, ContentHash: key, InstructionBindKey: key},
	} {
		given := ev
		if _, err := c.RecordLifecycleEvent(&ev); err != nil {
			t.Fatalf("%+v: %v", ev, err)
		}
		if ev != given {
			t.Errorf("the caller's event is not rewritten: %+v became %+v", given, ev)
		}
	}
	exec, execSent := recording(t, executionJSON(`"ApprovedAndExecuted"`, false))
	if _, err := NewClient(exec.URL).VerifyExecution(&ExecutionCheckInput{Signature: signature, InstructionBindKey: key}); err != nil {
		t.Fatal(err)
	}
	for _, body := range append(append([]map[string]any{}, *sent...), *execSent...) {
		if body["instruction_bind_key"] != key || body["content_hash"] != key {
			t.Errorf("both names must carry the key: %v", body)
		}
	}
	// No key on an execution check is still no key: nothing is invented.
	if _, err := NewClient(exec.URL).VerifyExecution(&ExecutionCheckInput{Signature: signature}); err != nil {
		t.Fatal(err)
	}
	last := (*execSent)[len(*execSent)-1]
	if _, has := last["instruction_bind_key"]; has {
		t.Errorf("no key was given: %v", last)
	}
	if _, has := last["content_hash"]; has {
		t.Errorf("no key was given: %v", last)
	}
}

func TestLifecycleRequestsRefuseTwoDifferentKeys(t *testing.T) {
	srv, sent := recording(t, receiptJSON("signing"))
	c := NewClient(srv.URL)
	other := strings.Repeat("0", 16)
	_, err := c.RecordLifecycleEvent(&LifecycleEventInput{EventType: LifecycleSigning, ContentHash: "48c65c638aceb5de", InstructionBindKey: other})
	if err == nil || !strings.Contains(err.Error(), "same key under two names") {
		t.Errorf("an event naming two keys must be refused: %v", err)
	}
	_, err = c.VerifyExecution(&ExecutionCheckInput{Signature: signature, ContentHash: "48c65c638aceb5de", InstructionBindKey: other})
	if err == nil || !strings.Contains(err.Error(), "same key under two names") {
		t.Errorf("an execution check naming two keys must be refused: %v", err)
	}
	if len(*sent) != 0 {
		t.Errorf("nothing may reach the Core: %v", *sent)
	}
}

func TestTheReceiptIsHeldToTheKeySentUnderTheNewName(t *testing.T) {
	srv, _ := recording(t, strings.Replace(receiptJSON("signing"), "48c65c638aceb5de", "0000000000000000", 1))
	_, err := NewClient(srv.URL).RecordLifecycleEvent(&LifecycleEventInput{EventType: LifecycleSigning, InstructionBindKey: "48c65c638aceb5de"})
	if err == nil || !strings.Contains(err.Error(), "different instruction key") {
		t.Errorf("a receipt about another key must be refused: %v", err)
	}
}
