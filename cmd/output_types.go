package cmd

// cloudElevationOutput is the JSON representation of a cloud elevation result.
type cloudElevationOutput struct {
	Type        string               `json:"type"`
	Provider    string               `json:"provider"`
	SessionID   string               `json:"sessionId"`
	Target      string               `json:"target"`
	Role        string               `json:"role"`
	Credentials *awsCredentialOutput `json:"credentials,omitempty"`
}

// awsCredentialOutput is the JSON representation of AWS credentials.
type awsCredentialOutput struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
}

// groupElevationJSON is the JSON representation of a group elevation result.
type groupElevationJSON struct {
	Type        string `json:"type"`
	SessionID   string `json:"sessionId"`
	GroupName   string `json:"groupName"`
	GroupID     string `json:"groupId"`
	DirectoryID string `json:"directoryId"`
	Directory   string `json:"directory,omitempty"`
}

// sessionOutput is the JSON representation of an active session.
type sessionOutput struct {
	SessionID        string `json:"sessionId"`
	Provider         string `json:"provider"`
	WorkspaceID      string `json:"workspaceId"`
	WorkspaceName    string `json:"workspaceName,omitempty"`
	RoleID           string `json:"roleId,omitempty"`
	Duration         int    `json:"duration"`
	RemainingSeconds *int   `json:"remainingSeconds,omitempty"`
	Type             string `json:"type"`
	GroupID          string `json:"groupId,omitempty"`
	GroupName        string `json:"groupName,omitempty"`
}

// statusOutput is the JSON representation of grant status.
type statusOutput struct {
	Authenticated bool            `json:"authenticated"`
	Username      string          `json:"username,omitempty"`
	Sessions      []sessionOutput `json:"sessions"`
}

// revocationOutput is the JSON representation of a revocation result.
// There is one entry per *requested* session, in requested order, plus any
// results the service returned that could not be attributed to a request.
// There is deliberately no "revoked" boolean: an in-progress revocation is
// accepted but not complete, and a boolean cannot say that.
type revocationOutput struct {
	SessionID  string `json:"sessionId"`
	Status     string `json:"status"`           // raw API value; "" when no row was returned
	Outcome    string `json:"outcome"`          // revoked | in_progress | not_applicable | unknown
	Accepted   bool   `json:"accepted"`         // the service accepted the command
	Complete   bool   `json:"complete"`         // revocation confirmed finished
	Reason     string `json:"reason,omitempty"` // explanation when not confirmed revoked
	Unexpected bool   `json:"unexpected,omitempty"`
}

// favoriteOutput is the JSON representation of a saved favorite.
type favoriteOutput struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Provider    string `json:"provider"`
	Target      string `json:"target,omitempty"`
	Role        string `json:"role,omitempty"`
	Group       string `json:"group,omitempty"`
	DirectoryID string `json:"directoryId,omitempty"`
}

// accessRequestOutput is the JSON representation of an access request.
type accessRequestOutput struct {
	RequestID          string `json:"requestId"`
	TargetCategory     string `json:"targetCategory"`
	State              string `json:"state"`
	Result             string `json:"result"`
	Priority           string `json:"priority,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Provider           string `json:"provider,omitempty"`
	Target             string `json:"target,omitempty"`
	Role               string `json:"role,omitempty"`
	RequestDate        string `json:"requestDate,omitempty"`
	Timezone           string `json:"timezone,omitempty"`
	TimeFrom           string `json:"timeFrom,omitempty"`
	TimeTo             string `json:"timeTo,omitempty"`
	FinalizationReason string `json:"finalizationReason,omitempty"`
	RequestLink        string `json:"requestLink,omitempty"`
	CreatedBy          string `json:"createdBy"`
	CreatedAt          string `json:"createdAt"`
	UpdatedBy          string `json:"updatedBy"`
	UpdatedAt          string `json:"updatedAt"`
}

// accessRequestListOutput is the JSON representation of a list of access requests.
type accessRequestListOutput struct {
	Requests   []accessRequestOutput `json:"requests"`
	TotalCount int                   `json:"totalCount"`
}
