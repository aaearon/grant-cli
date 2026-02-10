package models

import "time"

// SessionInfo represents an active elevated session.
type SessionInfo struct {
	SessionID       string     `json:"sessionId"`
	UserID          string     `json:"userId"`
	CSP             CSP        `json:"csp"`
	WorkspaceID     string     `json:"workspaceId"`
	WorkspaceName   string     `json:"workspaceName,omitempty"`
	RoleID          string     `json:"roleId"`
	RoleName        string     `json:"roleName,omitempty"`
	SessionDuration int        `json:"sessionDuration"`
	ExpiresAt       *time.Time `json:"expiresAt,omitempty"`
}

// SessionsResponse is the response from GET /api/access/sessions.
type SessionsResponse struct {
	Response  []SessionInfo `json:"response"`
	NextToken *string       `json:"nextToken"`
	Total     int           `json:"total"`
}
