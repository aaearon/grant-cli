package models

import (
	"encoding/json"
	"testing"
)

// These pin the literal JSON keys of the three request bodies grant sends to
// the UAR API. Round-tripping through the same Go struct cannot catch a renamed
// tag, so each test inspects the marshaled keys directly.

func TestSubmitAccessRequest_JSONTags(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(SubmitAccessRequest{
		TargetCategory: "CLOUD_CONSOLE",
		RequestDetails: map[string]interface{}{"reason": "need access to prod"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"targetCategory", "requestDetails"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("submit body is missing key %q: %s", key, b)
		}
	}
	if string(raw["targetCategory"]) != `"CLOUD_CONSOLE"` {
		t.Errorf("targetCategory = %s, want \"CLOUD_CONSOLE\"", raw["targetCategory"])
	}
	if string(raw["requestDetails"]) != `{"reason":"need access to prod"}` {
		t.Errorf("requestDetails = %s", raw["requestDetails"])
	}
}

func TestFinalizeAccessRequest_JSONTags(t *testing.T) {
	t.Parallel()

	reason := "approved after review"
	b, err := json.Marshal(FinalizeAccessRequest{Result: "APPROVED", FinalizationReason: &reason})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(raw["result"]) != `"APPROVED"` {
		t.Errorf("result = %s, want \"APPROVED\" under key \"result\": %s", raw["result"], b)
	}
	if string(raw["finalizationReason"]) != `"approved after review"` {
		t.Errorf("finalizationReason = %s: %s", raw["finalizationReason"], b)
	}

	// omitempty: a nil reason must not appear at all.
	b, err = json.Marshal(FinalizeAccessRequest{Result: "REJECTED"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw = nil
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["finalizationReason"]; ok {
		t.Errorf("finalizationReason present for a nil reason: %s", b)
	}
}

func TestCancelAccessRequest_JSONTags(t *testing.T) {
	t.Parallel()

	reason := "no longer needed"
	b, err := json.Marshal(CancelAccessRequest{CancelReason: &reason})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(raw["cancelReason"]) != `"no longer needed"` {
		t.Errorf("cancelReason = %s: %s", raw["cancelReason"], b)
	}
}
