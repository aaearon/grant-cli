package models

// GroupsEligibleTarget represents an Entra ID group the user is eligible to join.
type GroupsEligibleTarget struct {
	DirectoryID   string `json:"directoryId"`
	DirectoryName string `json:"-"` // Set programmatically from cloud eligibility cross-reference
	GroupID       string `json:"groupId"`
	GroupName     string `json:"groupName"`
}

// GroupsEligibilityResponse is the response from GET /api/access/{CSP}/eligibility/groups.
type GroupsEligibilityResponse struct {
	Response  []GroupsEligibleTarget `json:"response"`
	NextToken *string                `json:"nextToken"`
	Total     int                    `json:"total"`
}

// GroupsElevateTarget represents a single group target for elevation.
type GroupsElevateTarget struct {
	GroupID string `json:"groupId"`
}

// GroupsElevateRequest is the request body for POST /api/access/elevate/groups.
type GroupsElevateRequest struct {
	DirectoryID string                `json:"directoryId"`
	CSP         CSP                   `json:"csp"`
	Targets     []GroupsElevateTarget `json:"targets"`
}

// GroupsElevateTargetResult is the per-target result of a groups elevation request.
type GroupsElevateTargetResult struct {
	GroupID   string     `json:"groupId"`
	SessionID string     `json:"sessionId"`
	ErrorInfo *ErrorInfo `json:"errorInfo"`
}

// GroupsElevateResponse is the inner response from POST /api/access/elevate/groups.
// Note: The wire format wraps this in a "response" key (same as cloud elevation).
type GroupsElevateResponse struct {
	DirectoryID string                      `json:"directoryId"`
	CSP         CSP                         `json:"csp"`
	Results     []GroupsElevateTargetResult `json:"results"`
}
