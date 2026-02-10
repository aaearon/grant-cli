package models

// ElevateTarget represents a single target for elevation.
type ElevateTarget struct {
	WorkspaceID string `json:"workspaceId"`
	RoleID      string `json:"roleId,omitempty"`
	RoleName    string `json:"roleName,omitempty"`
}

// ElevateRequest is the request body for POST /api/access/elevate.
type ElevateRequest struct {
	CSP            CSP             `json:"csp"`
	OrganizationID string          `json:"organizationId"`
	Targets        []ElevateTarget `json:"targets"`
}

// ErrorInfo describes the reason for an elevation failure.
type ErrorInfo struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Description string `json:"description"`
	Link        string `json:"link,omitempty"`
}

// ElevateTargetResult is the per-target result of an elevation request.
type ElevateTargetResult struct {
	WorkspaceID       string     `json:"workspaceId"`
	RoleID            string     `json:"roleId"`
	SessionID         string     `json:"sessionId"`
	AccessCredentials *string    `json:"accessCredentials"`
	ErrorInfo         *ErrorInfo `json:"errorInfo"`
}

// ElevateAccessResult contains the overall elevation response.
type ElevateAccessResult struct {
	CSP            CSP                   `json:"csp"`
	OrganizationID string                `json:"organizationId"`
	Results        []ElevateTargetResult `json:"results"`
}

// ElevateResponse is the response from POST /api/access/elevate.
type ElevateResponse struct {
	Response ElevateAccessResult `json:"response"`
}
