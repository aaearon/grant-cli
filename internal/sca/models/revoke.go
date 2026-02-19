package models

import "encoding/json"

const (
	RevocationSuccessful = "SUCCESSFULLY_REVOKED"
	RevocationInProgress = "REVOCATION_IN_PROGRESS"
)

// RevokeRequest is the request body for POST /api/access/sessions/revoke.
type RevokeRequest struct {
	SessionIDs []string `json:"sessionIds"`
}

// RevocationResult represents the outcome of revoking a single session.
type RevocationResult struct {
	SessionID        string `json:"sessionId"`
	RevocationStatus string `json:"revocationStatus"`
}

// UnmarshalJSON implements custom unmarshaling to handle both camelCase (spec)
// and snake_case (live API) field names.
func (r *RevocationResult) UnmarshalJSON(data []byte) error {
	type Alias RevocationResult
	aux := &struct {
		*Alias
		SnakeSessionID        string `json:"session_id"`
		SnakeRevocationStatus string `json:"revocation_status"`
	}{
		Alias: (*Alias)(r),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	if r.SessionID == "" && aux.SnakeSessionID != "" {
		r.SessionID = aux.SnakeSessionID
	}
	if r.RevocationStatus == "" && aux.SnakeRevocationStatus != "" {
		r.RevocationStatus = aux.SnakeRevocationStatus
	}

	return nil
}

// RevokeResponse is the response from POST /api/access/sessions/revoke.
type RevokeResponse struct {
	Response []RevocationResult `json:"response"`
}
