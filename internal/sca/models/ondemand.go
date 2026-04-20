package models

// OnDemandResource is a role returned by the on-demand role discovery endpoints.
type OnDemandResource struct {
	ResourceID              string   `json:"resource_id"`
	ResourceName            string   `json:"resource_name"`
	Provider                string   `json:"provider"`
	Custom                  bool     `json:"custom"`
	Description             string   `json:"description,omitempty"`
	RoleType                int      `json:"role_type,omitempty"`
	AssignableScope         []string `json:"assignable_scope,omitempty"`
	AssignableWorkspaceType string   `json:"assignable_workspace_type,omitempty"`
}

// OnDemandRequest describes an on-demand roles lookup for a single workspace.
type OnDemandRequest struct {
	WorkspaceID  string
	PlatformName string
	OrgID        string
	ResourceType string
	Ancestors    []string
}
