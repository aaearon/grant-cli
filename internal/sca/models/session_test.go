package models

import (
	"encoding/json"
	"testing"
)

func TestSessionInfo_JSONUnmarshal(t *testing.T) {
	jsonInput := `{
		"sessionId": "session-abc-123",
		"userId": "user@example.com",
		"csp": "AZURE",
		"workspaceId": "/subscriptions/11111111-2222-3333-4444-555555555555",
		"roleId": "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
		"sessionDuration": 3600
	}`

	var session SessionInfo
	if err := json.Unmarshal([]byte(jsonInput), &session); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if session.SessionID != "session-abc-123" {
		t.Errorf("SessionID = %q, want %q", session.SessionID, "session-abc-123")
	}
	if session.UserID != "user@example.com" {
		t.Errorf("UserID = %q, want %q", session.UserID, "user@example.com")
	}
	if session.CSP != CSPAzure {
		t.Errorf("CSP = %q, want %q", session.CSP, CSPAzure)
	}
	if session.WorkspaceID != "/subscriptions/11111111-2222-3333-4444-555555555555" {
		t.Errorf("WorkspaceID = %q, want %q", session.WorkspaceID, "/subscriptions/11111111-2222-3333-4444-555555555555")
	}
	if session.RoleID != "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7" {
		t.Errorf("RoleID = %q, want %q", session.RoleID, "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7")
	}
	if session.SessionDuration != 3600 {
		t.Errorf("SessionDuration = %d, want %d", session.SessionDuration, 3600)
	}
}

func TestSessionsResponse_Multiple(t *testing.T) {
	jsonInput := `{
		"response": [
			{
				"sessionId": "session-1",
				"userId": "user1@example.com",
				"csp": "AZURE",
				"workspaceId": "/subscriptions/sub-1",
				"roleId": "role-1",
				"sessionDuration": 3600
			},
			{
				"sessionId": "session-2",
				"userId": "user1@example.com",
				"csp": "AZURE",
				"workspaceId": "/subscriptions/sub-2",
				"roleId": "role-2",
				"sessionDuration": 7200
			}
		],
		"nextToken": "page2token",
		"total": 5
	}`

	var resp SessionsResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(resp.Response) != 2 {
		t.Fatalf("Response length = %d, want 2", len(resp.Response))
	}

	if resp.NextToken == nil {
		t.Fatal("NextToken is nil, want non-nil")
	}
	if *resp.NextToken != "page2token" {
		t.Errorf("NextToken = %q, want %q", *resp.NextToken, "page2token")
	}

	if resp.Total != 5 {
		t.Errorf("Total = %d, want 5", resp.Total)
	}

	// Verify first session
	first := resp.Response[0]
	if first.SessionID != "session-1" {
		t.Errorf("Response[0].SessionID = %q, want %q", first.SessionID, "session-1")
	}
	if first.SessionDuration != 3600 {
		t.Errorf("Response[0].SessionDuration = %d, want %d", first.SessionDuration, 3600)
	}

	// Verify second session
	second := resp.Response[1]
	if second.SessionID != "session-2" {
		t.Errorf("Response[1].SessionID = %q, want %q", second.SessionID, "session-2")
	}
	if second.WorkspaceID != "/subscriptions/sub-2" {
		t.Errorf("Response[1].WorkspaceID = %q, want %q", second.WorkspaceID, "/subscriptions/sub-2")
	}
	if second.SessionDuration != 7200 {
		t.Errorf("Response[1].SessionDuration = %d, want %d", second.SessionDuration, 7200)
	}
}

func TestSessionsResponse_Empty(t *testing.T) {
	jsonInput := `{
		"response": [],
		"total": 0
	}`

	var resp SessionsResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(resp.Response) != 0 {
		t.Errorf("Response length = %d, want 0", len(resp.Response))
	}

	if resp.NextToken != nil {
		t.Errorf("NextToken = %v, want nil", resp.NextToken)
	}

	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
}
