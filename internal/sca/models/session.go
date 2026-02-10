package models

// SessionInfo represents an active elevated session.
// Note: The live SCA API uses snake_case field names, which differs from the
// OpenAPI spec's camelCase. The role_id field contains the role display name
// (e.g., "User Access Administrator"), not an ARM resource path.
type SessionInfo struct {
	SessionID       string `json:"session_id"`
	UserID          string `json:"user_id"`
	CSP             CSP    `json:"csp"`
	WorkspaceID     string `json:"workspace_id"`
	RoleID          string `json:"role_id"`
	SessionDuration int    `json:"session_duration"`
}

// SessionsResponse is the response from GET /api/access/sessions.
type SessionsResponse struct {
	Response  []SessionInfo `json:"response"`
	NextToken *string       `json:"nextToken"`
	Total     int           `json:"total"`
}
