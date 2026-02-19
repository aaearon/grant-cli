package models

const (
	// TargetTypeGroups indicates an Entra ID group membership session.
	TargetTypeGroups = "groups"
	// TargetTypeCloudConsole indicates a cloud console elevation session.
	TargetTypeCloudConsole = "cloud_console"
)

// SessionTarget identifies what a session is targeting (group or cloud console).
// Present on group sessions; may be absent on older cloud sessions.
type SessionTarget struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// SessionInfo represents an active elevated session.
// Note: The live SCA API uses snake_case field names, which differs from the
// OpenAPI spec's camelCase. The role_id field contains the role display name
// (e.g., "User Access Administrator"), not an ARM resource path.
// For group sessions, role_id is absent and Target.Type is "groups".
type SessionInfo struct {
	SessionID       string         `json:"session_id"`
	UserID          string         `json:"user_id"`
	CSP             CSP            `json:"csp"`
	WorkspaceID     string         `json:"workspace_id"`
	RoleID          string         `json:"role_id"`
	SessionDuration int            `json:"session_duration"`
	Target          *SessionTarget `json:"target,omitempty"`
}

// IsGroupSession returns true if this session is for Entra ID group membership.
func (s SessionInfo) IsGroupSession() bool {
	return s.Target != nil && s.Target.Type == TargetTypeGroups
}

// SessionsResponse is the response from GET /api/access/sessions.
type SessionsResponse struct {
	Response  []SessionInfo `json:"response"`
	NextToken *string       `json:"nextToken"`
	Total     int           `json:"total"`
}
