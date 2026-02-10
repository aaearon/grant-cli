package models

// SessionInfo represents an active elevated session.
type SessionInfo struct {
	SessionID       string `json:"sessionId"`
	UserID          string `json:"userId"`
	CSP             CSP    `json:"csp"`
	WorkspaceID     string `json:"workspaceId"`
	RoleID          string `json:"roleId"`
	SessionDuration int    `json:"sessionDuration"`
}

// SessionsResponse is the response from GET /api/access/sessions.
type SessionsResponse struct {
	Response  []SessionInfo `json:"response"`
	NextToken *string       `json:"nextToken"`
	Total     int           `json:"total"`
}
