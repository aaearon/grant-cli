package models

import (
	"encoding/json"
	"testing"
)

func TestEligibleTarget_JSONUnmarshal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		jsonInput       string
		wantOrgID       string
		wantWorkspaceID string
		wantName        string
		wantType        WorkspaceType
		wantRoleID      string
		wantRoleName    string
	}{
		{
			name: "full target with roleInfo field",
			jsonInput: `{
				"organizationId": "29cb7961-e16d-42c7-8ade-1794bbb76782",
				"workspaceId": "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
				"workspaceName": "Tenant Root Group",
				"workspaceType": "MANAGEMENT_GROUP",
				"roleInfo": {
					"id": "/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
					"name": "User Access Administrator"
				}
			}`,
			wantOrgID:       "29cb7961-e16d-42c7-8ade-1794bbb76782",
			wantWorkspaceID: "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
			wantName:        "Tenant Root Group",
			wantType:        WorkspaceTypeManagementGroup,
			wantRoleID:      "/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
			wantRoleName:    "User Access Administrator",
		},
		{
			name: "AWS account workspace type",
			jsonInput: `{
				"organizationId": "o-abc123def456",
				"workspaceId": "123456789012",
				"workspaceName": "Acme AWS Management",
				"workspaceType": "account",
				"roleInfo": {
					"id": "arn:aws:iam::123456789012:role/AdministratorAccess",
					"name": "AdministratorAccess"
				}
			}`,
			wantOrgID:       "o-abc123def456",
			wantWorkspaceID: "123456789012",
			wantName:        "Acme AWS Management",
			wantType:        WorkspaceTypeAccount,
			wantRoleID:      "arn:aws:iam::123456789012:role/AdministratorAccess",
			wantRoleName:    "AdministratorAccess",
		},
		{
			name: "subscription workspace type",
			jsonInput: `{
				"organizationId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				"workspaceId": "/subscriptions/11111111-2222-3333-4444-555555555555",
				"workspaceName": "My Subscription",
				"workspaceType": "SUBSCRIPTION",
				"roleInfo": {
					"id": "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
					"name": "Reader"
				}
			}`,
			wantOrgID:       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			wantWorkspaceID: "/subscriptions/11111111-2222-3333-4444-555555555555",
			wantName:        "My Subscription",
			wantType:        WorkspaceTypeSubscription,
			wantRoleID:      "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
			wantRoleName:    "Reader",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var target EligibleTarget
			if err := json.Unmarshal([]byte(tt.jsonInput), &target); err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}

			if target.OrganizationID != tt.wantOrgID {
				t.Errorf("OrganizationID = %q, want %q", target.OrganizationID, tt.wantOrgID)
			}
			if target.WorkspaceID != tt.wantWorkspaceID {
				t.Errorf("WorkspaceID = %q, want %q", target.WorkspaceID, tt.wantWorkspaceID)
			}
			if target.WorkspaceName != tt.wantName {
				t.Errorf("WorkspaceName = %q, want %q", target.WorkspaceName, tt.wantName)
			}
			if target.WorkspaceType != tt.wantType {
				t.Errorf("WorkspaceType = %q, want %q", target.WorkspaceType, tt.wantType)
			}
			if target.RoleInfo.ID != tt.wantRoleID {
				t.Errorf("RoleInfo.ID = %q, want %q", target.RoleInfo.ID, tt.wantRoleID)
			}
			if target.RoleInfo.Name != tt.wantRoleName {
				t.Errorf("RoleInfo.Name = %q, want %q", target.RoleInfo.Name, tt.wantRoleName)
			}
		})
	}
}

func TestEligibleTarget_JSONUnmarshal_RoleFieldFallback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		jsonInput    string
		wantRoleID   string
		wantRoleName string
		wantType     WorkspaceType
	}{
		{
			name: "role field instead of roleInfo (OpenAPI spec variant)",
			jsonInput: `{
				"organizationId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				"workspaceId": "/subscriptions/11111111-2222-3333-4444-555555555555",
				"workspaceName": "Dev Subscription",
				"workspaceType": "SUBSCRIPTION",
				"role": {
					"id": "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
					"name": "Contributor"
				}
			}`,
			wantRoleID:   "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
			wantRoleName: "Contributor",
			wantType:     WorkspaceTypeSubscription,
		},
		{
			name: "role field with resource group type",
			jsonInput: `{
				"organizationId": "org-id-123",
				"workspaceId": "/subscriptions/sub-1/resourceGroups/rg-1",
				"workspaceName": "rg-1",
				"workspaceType": "RESOURCE_GROUP",
				"role": {
					"id": "/providers/Microsoft.Authorization/roleDefinitions/owner-role-id",
					"name": "Owner"
				}
			}`,
			wantRoleID:   "/providers/Microsoft.Authorization/roleDefinitions/owner-role-id",
			wantRoleName: "Owner",
			wantType:     WorkspaceTypeResourceGroup,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var target EligibleTarget
			if err := json.Unmarshal([]byte(tt.jsonInput), &target); err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}

			if target.RoleInfo.ID != tt.wantRoleID {
				t.Errorf("RoleInfo.ID = %q, want %q", target.RoleInfo.ID, tt.wantRoleID)
			}
			if target.RoleInfo.Name != tt.wantRoleName {
				t.Errorf("RoleInfo.Name = %q, want %q", target.RoleInfo.Name, tt.wantRoleName)
			}
			if target.WorkspaceType != tt.wantType {
				t.Errorf("WorkspaceType = %q, want %q", target.WorkspaceType, tt.wantType)
			}
		})
	}
}

func TestEligibilityResponse_Pagination(t *testing.T) {
	t.Parallel()
	jsonInput := `{
		"response": [
			{
				"organizationId": "org-1",
				"workspaceId": "ws-1",
				"workspaceName": "Workspace One",
				"workspaceType": "SUBSCRIPTION",
				"roleInfo": {"id": "role-1", "name": "Reader"}
			},
			{
				"organizationId": "org-1",
				"workspaceId": "ws-2",
				"workspaceName": "Workspace Two",
				"workspaceType": "RESOURCE_GROUP",
				"roleInfo": {"id": "role-2", "name": "Contributor"}
			}
		],
		"nextToken": "abc123token",
		"total": 10
	}`

	var resp EligibilityResponse
	if err := json.Unmarshal([]byte(jsonInput), &resp); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if len(resp.Response) != 2 {
		t.Fatalf("Response length = %d, want 2", len(resp.Response))
	}

	if resp.NextToken == nil {
		t.Fatal("NextToken is nil, want non-nil")
	}
	if *resp.NextToken != "abc123token" {
		t.Errorf("NextToken = %q, want %q", *resp.NextToken, "abc123token")
	}

	if resp.Total != 10 {
		t.Errorf("Total = %d, want 10", resp.Total)
	}

	// Verify first target
	first := resp.Response[0]
	if first.WorkspaceName != "Workspace One" {
		t.Errorf("Response[0].WorkspaceName = %q, want %q", first.WorkspaceName, "Workspace One")
	}
	if first.RoleInfo.Name != "Reader" {
		t.Errorf("Response[0].RoleInfo.Name = %q, want %q", first.RoleInfo.Name, "Reader")
	}

	// Verify second target
	second := resp.Response[1]
	if second.WorkspaceType != WorkspaceTypeResourceGroup {
		t.Errorf("Response[1].WorkspaceType = %q, want %q", second.WorkspaceType, WorkspaceTypeResourceGroup)
	}
}

func TestEligibilityResponse_Empty(t *testing.T) {
	t.Parallel()
	jsonInput := `{
		"response": [],
		"total": 0
	}`

	var resp EligibilityResponse
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

func TestWorkspaceType_Values(t *testing.T) {
	t.Parallel()
	tests := []struct {
		constant WorkspaceType
		want     string
	}{
		{WorkspaceTypeResource, "RESOURCE"},
		{WorkspaceTypeResourceGroup, "RESOURCE_GROUP"},
		{WorkspaceTypeSubscription, "SUBSCRIPTION"},
		{WorkspaceTypeManagementGroup, "MANAGEMENT_GROUP"},
		{WorkspaceTypeDirectory, "DIRECTORY"},
		{WorkspaceTypeAccount, "account"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if string(tt.constant) != tt.want {
				t.Errorf("WorkspaceType constant = %q, want %q", tt.constant, tt.want)
			}
		})
	}
}

func TestCSP_Values(t *testing.T) {
	t.Parallel()
	tests := []struct {
		constant CSP
		want     string
	}{
		{CSPAzure, "AZURE"},
		{CSPAWS, "AWS"},
		{CSPGCP, "GCP"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if string(tt.constant) != tt.want {
				t.Errorf("CSP constant = %q, want %q", tt.constant, tt.want)
			}
		})
	}
}
