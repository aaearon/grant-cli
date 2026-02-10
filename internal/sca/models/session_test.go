package models

import (
	"encoding/json"
	"testing"
)

func TestSessionInfo_JSONUnmarshal(t *testing.T) {
	// Real API format: snake_case field names, role_id contains display name
	jsonInput := `{
		"session_id": "session-abc-123",
		"user_id": "user@example.com",
		"csp": "AZURE",
		"workspace_id": "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
		"role_id": "User Access Administrator",
		"session_duration": 3600
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
	if session.WorkspaceID != "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782" {
		t.Errorf("WorkspaceID = %q, want %q", session.WorkspaceID, "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782")
	}
	if session.RoleID != "User Access Administrator" {
		t.Errorf("RoleID = %q, want %q", session.RoleID, "User Access Administrator")
	}
	if session.SessionDuration != 3600 {
		t.Errorf("SessionDuration = %d, want %d", session.SessionDuration, 3600)
	}
}

func TestSessionsResponse_Multiple(t *testing.T) {
	// Real API format with multiple sessions
	jsonInput := `{
		"response": [
			{
				"session_id": "session-1",
				"user_id": "user1@example.com",
				"csp": "AZURE",
				"workspace_id": "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
				"role_id": "User Access Administrator",
				"session_duration": 3600
			},
			{
				"session_id": "session-2",
				"user_id": "user1@example.com",
				"csp": "AZURE",
				"workspace_id": "/subscriptions/11111111-2222-3333-4444-555555555555",
				"role_id": "Contributor",
				"session_duration": 7200
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
	if first.RoleID != "User Access Administrator" {
		t.Errorf("Response[0].RoleID = %q, want %q", first.RoleID, "User Access Administrator")
	}
	if first.SessionDuration != 3600 {
		t.Errorf("Response[0].SessionDuration = %d, want %d", first.SessionDuration, 3600)
	}

	// Verify second session
	second := resp.Response[1]
	if second.SessionID != "session-2" {
		t.Errorf("Response[1].SessionID = %q, want %q", second.SessionID, "session-2")
	}
	if second.WorkspaceID != "/subscriptions/11111111-2222-3333-4444-555555555555" {
		t.Errorf("Response[1].WorkspaceID = %q, want %q", second.WorkspaceID, "/subscriptions/11111111-2222-3333-4444-555555555555")
	}
	if second.RoleID != "Contributor" {
		t.Errorf("Response[1].RoleID = %q, want %q", second.RoleID, "Contributor")
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

func TestSessionInfo_RealAPIPayload(t *testing.T) {
	// Exact payload captured from live SCA API on 2026-02-10
	jsonInput := `{
		"response": [
			{
				"session_id": "0e796e75-6027-48bd-bf1e-80e3b1024de4",
				"user_id": "tim.schindler@cyberark.cloud.40562",
				"csp": "AZURE",
				"workspace_id": "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
				"role_id": "User Access Administrator",
				"session_duration": 3600
			}
		],
		"total": 1
	}`

	var resp SessionsResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(resp.Response) != 1 {
		t.Fatalf("Response length = %d, want 1", len(resp.Response))
	}

	session := resp.Response[0]
	if session.SessionID != "0e796e75-6027-48bd-bf1e-80e3b1024de4" {
		t.Errorf("SessionID = %q, want %q", session.SessionID, "0e796e75-6027-48bd-bf1e-80e3b1024de4")
	}
	if session.UserID != "tim.schindler@cyberark.cloud.40562" {
		t.Errorf("UserID = %q, want %q", session.UserID, "tim.schindler@cyberark.cloud.40562")
	}
	if session.CSP != CSPAzure {
		t.Errorf("CSP = %q, want %q", session.CSP, CSPAzure)
	}
	if session.RoleID != "User Access Administrator" {
		t.Errorf("RoleID = %q, want %q", session.RoleID, "User Access Administrator")
	}
	if session.SessionDuration != 3600 {
		t.Errorf("SessionDuration = %d, want %d", session.SessionDuration, 3600)
	}
}
