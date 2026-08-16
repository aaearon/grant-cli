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

// The response models below were previously unpinned in both directions: every
// test decoded a body produced by marshaling the same Go struct, so a renamed
// tag round-tripped trivially while `grant request get` / `grant request list`
// rendered blanks. These pin the keys that reach the user's screen. The
// validation metadata on form.go is still unpinned — see ledger row WF-25.

// TestAccessRequest_DecodesPopulatedResponse pins the response keys that
// `grant request get` renders, decoding a literal wire body rather than a
// marshaled struct.
func TestAccessRequest_DecodesPopulatedResponse(t *testing.T) {
	t.Parallel()

	// Distinguishable values: no two keys share a value, so a swap cannot be
	// masked. Do not "tidy" these.
	const wire = `{
	  "requestId": "req-decode-1",
	  "targetCategory": "CLOUD_CONSOLE",
	  "requestState": "PENDING",
	  "requestResult": "UNKNOWN",
	  "requestDetails": {"reason": "reason-decode-2"},
	  "requestApprovers": [
	    {"approver": {"entityId": "ent-decode-3", "entityName": "approver-decode-4"}, "result": "APPROVED"}
	  ],
	  "requester": {"entityId": "ent-decode-5", "entityName": "requester-decode-6"},
	  "createdBy": "createdby-decode-7",
	  "createdAt": "2025-08-12T09:41:00",
	  "updatedBy": "updatedby-decode-8",
	  "updatedAt": "2025-08-12T17:41:00"
	}`

	var req AccessRequest
	if err := json.Unmarshal([]byte(wire), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if req.RequestID != "req-decode-1" {
		t.Errorf("requestId = %q, want %q", req.RequestID, "req-decode-1")
	}
	if req.TargetCategory != "CLOUD_CONSOLE" {
		t.Errorf("targetCategory = %q, want %q", req.TargetCategory, "CLOUD_CONSOLE")
	}
	if req.RequestState != RequestStatePending {
		t.Errorf("requestState = %q, want %q", req.RequestState, RequestStatePending)
	}
	if req.RequestResult != RequestResultUnknown {
		t.Errorf("requestResult = %q, want %q", req.RequestResult, RequestResultUnknown)
	}
	if got := req.DetailString("reason"); got != "reason-decode-2" {
		t.Errorf("requestDetails[reason] = %q, want %q", got, "reason-decode-2")
	}
	if req.Requester == nil {
		t.Fatal("requester = nil, want the decoded entity")
	}
	if req.Requester.EntityName != "requester-decode-6" {
		t.Errorf("requester.entityName = %q, want %q", req.Requester.EntityName, "requester-decode-6")
	}
	if req.Requester.EntityID != "ent-decode-5" {
		t.Errorf("requester.entityId = %q, want %q", req.Requester.EntityID, "ent-decode-5")
	}
	if len(req.RequestApprovers) != 1 {
		t.Fatalf("requestApprovers len = %d, want 1", len(req.RequestApprovers))
	}
	if req.RequestApprovers[0].Result != RequestResultApproved {
		t.Errorf("requestApprovers[0].result = %q, want %q", req.RequestApprovers[0].Result, RequestResultApproved)
	}
	if req.RequestApprovers[0].Approver.EntityName != "approver-decode-4" {
		t.Errorf("requestApprovers[0].approver.entityName = %q, want %q",
			req.RequestApprovers[0].Approver.EntityName, "approver-decode-4")
	}
	if req.CreatedBy != "createdby-decode-7" {
		t.Errorf("createdBy = %q, want %q", req.CreatedBy, "createdby-decode-7")
	}
	if req.CreatedAt != "2025-08-12T09:41:00" {
		t.Errorf("createdAt = %q, want %q", req.CreatedAt, "2025-08-12T09:41:00")
	}
	if req.UpdatedBy != "updatedby-decode-8" {
		t.Errorf("updatedBy = %q, want %q", req.UpdatedBy, "updatedby-decode-8")
	}
	if req.UpdatedAt != "2025-08-12T17:41:00" {
		t.Errorf("updatedAt = %q, want %q", req.UpdatedAt, "2025-08-12T17:41:00")
	}
}

// TestListRequestsResponse_DecodesPopulatedPage pins the pagination envelope.
// count and totalCount drive both the pagination loop and what the user is told
// about how many requests exist.
func TestListRequestsResponse_DecodesPopulatedPage(t *testing.T) {
	t.Parallel()

	const wire = `{
	  "items": [{"requestId": "req-page-1"}, {"requestId": "req-page-2"}],
	  "count": 2,
	  "totalCount": 7
	}`

	var page ListRequestsResponse
	if err := json.Unmarshal([]byte(wire), &page); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("items len = %d, want 2", len(page.Items))
	}
	if page.Items[0].RequestID != "req-page-1" {
		t.Errorf("items[0].requestId = %q, want %q", page.Items[0].RequestID, "req-page-1")
	}
	if page.Count != 2 {
		t.Errorf("count = %d, want 2", page.Count)
	}
	if page.TotalCount != 7 {
		t.Errorf("totalCount = %d, want 7", page.TotalCount)
	}
}
