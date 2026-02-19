package models

import (
	"encoding/json"
	"testing"
)

func TestRevokeRequest_JSONMarshal(t *testing.T) {
	t.Parallel()
	req := RevokeRequest{
		SessionIDs: []string{"session-1", "session-2"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	ids, ok := raw["sessionIds"]
	if !ok {
		t.Fatal("expected 'sessionIds' key in JSON output")
	}

	arr, ok := ids.([]interface{})
	if !ok {
		t.Fatalf("expected sessionIds to be array, got %T", ids)
	}
	if len(arr) != 2 {
		t.Errorf("expected 2 session IDs, got %d", len(arr))
	}
}

func TestRevokeResponse_Success(t *testing.T) {
	t.Parallel()
	jsonInput := `{
		"response": [
			{
				"sessionId": "session-1",
				"revocationStatus": "SUCCESSFULLY_REVOKED"
			}
		]
	}`

	var resp RevokeResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(resp.Response) != 1 {
		t.Fatalf("Response length = %d, want 1", len(resp.Response))
	}

	r := resp.Response[0]
	if r.SessionID != "session-1" {
		t.Errorf("SessionID = %q, want %q", r.SessionID, "session-1")
	}
	if r.RevocationStatus != RevocationSuccessful {
		t.Errorf("RevocationStatus = %q, want %q", r.RevocationStatus, RevocationSuccessful)
	}
}

func TestRevokeResponse_InProgress(t *testing.T) {
	t.Parallel()
	jsonInput := `{
		"response": [
			{
				"sessionId": "session-1",
				"revocationStatus": "REVOCATION_IN_PROGRESS"
			}
		]
	}`

	var resp RevokeResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if resp.Response[0].RevocationStatus != RevocationInProgress {
		t.Errorf("RevocationStatus = %q, want %q", resp.Response[0].RevocationStatus, RevocationInProgress)
	}
}

func TestRevokeResponse_Mixed(t *testing.T) {
	t.Parallel()
	jsonInput := `{
		"response": [
			{
				"sessionId": "session-1",
				"revocationStatus": "SUCCESSFULLY_REVOKED"
			},
			{
				"sessionId": "session-2",
				"revocationStatus": "REVOCATION_IN_PROGRESS"
			}
		]
	}`

	var resp RevokeResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(resp.Response) != 2 {
		t.Fatalf("Response length = %d, want 2", len(resp.Response))
	}
	if resp.Response[0].RevocationStatus != RevocationSuccessful {
		t.Errorf("Response[0].RevocationStatus = %q, want %q", resp.Response[0].RevocationStatus, RevocationSuccessful)
	}
	if resp.Response[1].RevocationStatus != RevocationInProgress {
		t.Errorf("Response[1].RevocationStatus = %q, want %q", resp.Response[1].RevocationStatus, RevocationInProgress)
	}
}

func TestRevokeResponse_SnakeCase(t *testing.T) {
	t.Parallel()
	jsonInput := `{
		"response": [
			{
				"session_id": "session-1",
				"revocation_status": "SUCCESSFULLY_REVOKED"
			}
		]
	}`

	var resp RevokeResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(resp.Response) != 1 {
		t.Fatalf("Response length = %d, want 1", len(resp.Response))
	}

	r := resp.Response[0]
	if r.SessionID != "session-1" {
		t.Errorf("SessionID = %q, want %q", r.SessionID, "session-1")
	}
	if r.RevocationStatus != RevocationSuccessful {
		t.Errorf("RevocationStatus = %q, want %q", r.RevocationStatus, RevocationSuccessful)
	}
}
