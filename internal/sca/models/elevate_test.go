package models

import (
	"encoding/json"
	"testing"
)

func TestElevateRequest_JSONMarshal(t *testing.T) {
	req := ElevateRequest{
		CSP:            CSPAzure,
		OrganizationID: "org-12345",
		Targets: []ElevateTarget{
			{
				WorkspaceID: "/subscriptions/sub-1",
				RoleID:      "role-def-1",
			},
			{
				WorkspaceID: "/subscriptions/sub-2",
				RoleName:    "Contributor",
			},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	// Unmarshal into a generic map to verify field names
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	// Verify top-level JSON field names
	for _, field := range []string{"csp", "organizationId", "targets"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing expected JSON field %q", field)
		}
	}

	// Verify CSP value
	var csp string
	if err := json.Unmarshal(raw["csp"], &csp); err != nil {
		t.Fatalf("failed to unmarshal csp: %v", err)
	}
	if csp != "AZURE" {
		t.Errorf("csp = %q, want %q", csp, "AZURE")
	}

	// Verify targets array length
	var targets []json.RawMessage
	if err := json.Unmarshal(raw["targets"], &targets); err != nil {
		t.Fatalf("failed to unmarshal targets: %v", err)
	}
	if len(targets) != 2 {
		t.Errorf("targets length = %d, want 2", len(targets))
	}
}

func TestElevateRequest_WithRoleID(t *testing.T) {
	req := ElevateRequest{
		CSP:            CSPAzure,
		OrganizationID: "org-1",
		Targets: []ElevateTarget{
			{
				WorkspaceID: "/subscriptions/sub-1",
				RoleID:      "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
			},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	// Unmarshal back and verify
	var decoded ElevateRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(decoded.Targets) != 1 {
		t.Fatalf("Targets length = %d, want 1", len(decoded.Targets))
	}

	target := decoded.Targets[0]
	if target.WorkspaceID != "/subscriptions/sub-1" {
		t.Errorf("WorkspaceID = %q, want %q", target.WorkspaceID, "/subscriptions/sub-1")
	}
	if target.RoleID != "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7" {
		t.Errorf("RoleID = %q, want full role definition ID", target.RoleID)
	}
	if target.RoleName != "" {
		t.Errorf("RoleName = %q, want empty string", target.RoleName)
	}

	// Verify roleName is omitted from JSON when empty
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	var targets []map[string]json.RawMessage
	if err := json.Unmarshal(raw["targets"], &targets); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if _, ok := targets[0]["roleName"]; ok {
		t.Error("roleName should be omitted from JSON when empty")
	}
}

func TestElevateRequest_WithRoleName(t *testing.T) {
	req := ElevateRequest{
		CSP:            CSPAzure,
		OrganizationID: "org-1",
		Targets: []ElevateTarget{
			{
				WorkspaceID: "/subscriptions/sub-1",
				RoleName:    "Contributor",
			},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var decoded ElevateRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	target := decoded.Targets[0]
	if target.RoleName != "Contributor" {
		t.Errorf("RoleName = %q, want %q", target.RoleName, "Contributor")
	}
	if target.RoleID != "" {
		t.Errorf("RoleID = %q, want empty string", target.RoleID)
	}

	// Verify roleId is omitted from JSON when empty
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	var targets []map[string]json.RawMessage
	if err := json.Unmarshal(raw["targets"], &targets); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if _, ok := targets[0]["roleId"]; ok {
		t.Error("roleId should be omitted from JSON when empty")
	}
}

func TestElevateResponse_Success(t *testing.T) {
	jsonInput := `{
		"response": {
			"csp": "AZURE",
			"organizationId": "org-12345",
			"results": [
				{
					"workspaceId": "/subscriptions/sub-1",
					"roleId": "role-def-1",
					"sessionId": "session-abc-123",
					"accessCredentials": null,
					"errorInfo": null
				}
			]
		}
	}`

	var resp ElevateResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if resp.Response.CSP != CSPAzure {
		t.Errorf("CSP = %q, want %q", resp.Response.CSP, CSPAzure)
	}
	if resp.Response.OrganizationID != "org-12345" {
		t.Errorf("OrganizationID = %q, want %q", resp.Response.OrganizationID, "org-12345")
	}
	if len(resp.Response.Results) != 1 {
		t.Fatalf("Results length = %d, want 1", len(resp.Response.Results))
	}

	result := resp.Response.Results[0]
	if result.WorkspaceID != "/subscriptions/sub-1" {
		t.Errorf("WorkspaceID = %q, want %q", result.WorkspaceID, "/subscriptions/sub-1")
	}
	if result.RoleID != "role-def-1" {
		t.Errorf("RoleID = %q, want %q", result.RoleID, "role-def-1")
	}
	if result.SessionID != "session-abc-123" {
		t.Errorf("SessionID = %q, want %q", result.SessionID, "session-abc-123")
	}
	if result.AccessCredentials != nil {
		t.Errorf("AccessCredentials = %v, want nil", result.AccessCredentials)
	}
	if result.ErrorInfo != nil {
		t.Errorf("ErrorInfo = %v, want nil", result.ErrorInfo)
	}
}

func TestElevateResponse_WithErrorInfo(t *testing.T) {
	jsonInput := `{
		"response": {
			"csp": "AZURE",
			"organizationId": "org-12345",
			"results": [
				{
					"workspaceId": "/subscriptions/sub-1",
					"roleId": "role-def-1",
					"sessionId": "",
					"accessCredentials": null,
					"errorInfo": {
						"code": "ELEVATION_FAILED",
						"message": "Role elevation request failed",
						"description": "The target role is not eligible for elevation"
					}
				}
			]
		}
	}`

	var resp ElevateResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(resp.Response.Results) != 1 {
		t.Fatalf("Results length = %d, want 1", len(resp.Response.Results))
	}

	result := resp.Response.Results[0]
	if result.ErrorInfo == nil {
		t.Fatal("ErrorInfo is nil, want non-nil")
	}
	if result.ErrorInfo.Code != "ELEVATION_FAILED" {
		t.Errorf("ErrorInfo.Code = %q, want %q", result.ErrorInfo.Code, "ELEVATION_FAILED")
	}
	if result.ErrorInfo.Message != "Role elevation request failed" {
		t.Errorf("ErrorInfo.Message = %q, want %q", result.ErrorInfo.Message, "Role elevation request failed")
	}
	if result.ErrorInfo.Description != "The target role is not eligible for elevation" {
		t.Errorf("ErrorInfo.Description = %q, want %q", result.ErrorInfo.Description, "The target role is not eligible for elevation")
	}
}

func TestErrorInfo_JSONUnmarshal(t *testing.T) {
	tests := []struct {
		name            string
		jsonInput       string
		wantCode        string
		wantMessage     string
		wantDescription string
		wantLink        string
	}{
		{
			name: "all fields present",
			jsonInput: `{
				"code": "ACCESS_DENIED",
				"message": "Access denied",
				"description": "You do not have permission",
				"link": "https://docs.example.com/errors/access-denied"
			}`,
			wantCode:        "ACCESS_DENIED",
			wantMessage:     "Access denied",
			wantDescription: "You do not have permission",
			wantLink:        "https://docs.example.com/errors/access-denied",
		},
		{
			name: "link omitted",
			jsonInput: `{
				"code": "TIMEOUT",
				"message": "Request timed out",
				"description": "The elevation request exceeded the timeout"
			}`,
			wantCode:        "TIMEOUT",
			wantMessage:     "Request timed out",
			wantDescription: "The elevation request exceeded the timeout",
			wantLink:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ei ErrorInfo
			if err := json.Unmarshal([]byte(tt.jsonInput), &ei); err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}

			if ei.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", ei.Code, tt.wantCode)
			}
			if ei.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", ei.Message, tt.wantMessage)
			}
			if ei.Description != tt.wantDescription {
				t.Errorf("Description = %q, want %q", ei.Description, tt.wantDescription)
			}
			if ei.Link != tt.wantLink {
				t.Errorf("Link = %q, want %q", ei.Link, tt.wantLink)
			}
		})
	}
}
