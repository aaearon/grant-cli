package models

import "encoding/json"

// CSP represents a cloud service provider.
type CSP string

const (
	CSPAzure CSP = "AZURE"
	CSPAWS   CSP = "AWS"
	CSPGCP   CSP = "GCP"
)

// WorkspaceType represents the type of Azure workspace.
type WorkspaceType string

const (
	WorkspaceTypeResource        WorkspaceType = "RESOURCE"
	WorkspaceTypeResourceGroup   WorkspaceType = "RESOURCE_GROUP"
	WorkspaceTypeSubscription    WorkspaceType = "SUBSCRIPTION"
	WorkspaceTypeManagementGroup WorkspaceType = "MANAGEMENT_GROUP"
	WorkspaceTypeDirectory       WorkspaceType = "DIRECTORY"
)

// RoleInfo contains the ID and name of a role.
type RoleInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AzureEligibleTarget represents a target the user is eligible to elevate to.
type AzureEligibleTarget struct {
	OrganizationID string        `json:"organizationId"`
	WorkspaceID    string        `json:"workspaceId"`
	WorkspaceName  string        `json:"workspaceName"`
	WorkspaceType  WorkspaceType `json:"workspaceType"`
	RoleInfo       RoleInfo      `json:"roleInfo"`
}

// UnmarshalJSON implements custom unmarshaling to handle both "roleInfo" (live API)
// and "role" (OpenAPI spec) field names.
func (t *AzureEligibleTarget) UnmarshalJSON(data []byte) error {
	type Alias AzureEligibleTarget
	aux := &struct {
		*Alias
		Role *RoleInfo `json:"role"`
	}{
		Alias: (*Alias)(t),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// If roleInfo was not populated but role was, use role as fallback
	if t.RoleInfo == (RoleInfo{}) && aux.Role != nil {
		t.RoleInfo = *aux.Role
	}

	return nil
}

// EligibilityResponse is the response from GET /api/access/{CSP}/eligibility.
type EligibilityResponse struct {
	Response  []AzureEligibleTarget `json:"response"`
	NextToken *string               `json:"nextToken"`
	Total     int                   `json:"total"`
}
