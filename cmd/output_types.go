package cmd

// cloudElevationOutput is the JSON representation of a cloud elevation result.
type cloudElevationOutput struct {
	Type        string              `json:"type"`
	Provider    string              `json:"provider"`
	SessionID   string              `json:"sessionId"`
	Target      string              `json:"target"`
	Role        string              `json:"role"`
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
type revocationOutput struct {
	SessionID string `json:"sessionId"`
	Status    string `json:"status"`
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
