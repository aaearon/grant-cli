package models

import "encoding/json"

// Revocation status values returned in SessionRevocationInfo.revocationStatus.
//
// Only RevocationSuccessful and RevocationInProgress appear in the API spec's
// enum. RevocationNotApplicable is observed from the live API but documented
// nowhere (neither the OpenAPI spec nor the SDK), so the status set must be
// treated as open — see ClassifyRevocationStatus.
const (
	RevocationSuccessful    = "SUCCESSFULLY_REVOKED"
	RevocationInProgress    = "REVOCATION_IN_PROGRESS"
	RevocationNotApplicable = "REVOCATION_NOT_APPLICABLE"
)

// MaxRevokeBatchSize is the maximum number of session IDs accepted in a single
// revoke request (`sessionIds` has `maxItems: 100` in the API spec).
const MaxRevokeBatchSize = 100

// RevocationOutcome is the classified result of a revocation attempt for one
// session. It is deliberately not a boolean: "in progress" means the service
// accepted the command, not that the access is gone.
type RevocationOutcome string

const (
	// OutcomeRevoked means revocation is confirmed complete.
	OutcomeRevoked RevocationOutcome = "revoked"
	// OutcomeInProgress means the service accepted the command but has not confirmed completion.
	OutcomeInProgress RevocationOutcome = "in_progress"
	// OutcomeNotApplicable means the service declined to act on the session.
	OutcomeNotApplicable RevocationOutcome = "not_applicable"
	// OutcomeUnknown covers unrecognized, empty and missing statuses. It fails closed.
	OutcomeUnknown RevocationOutcome = "unknown"
)

// ClassifyRevocationStatus maps a raw API status to an outcome. Matching is
// exact (the API uses SCREAMING_SNAKE_CASE); anything unrecognized, including
// the empty string and case variants, classifies as OutcomeUnknown so an
// unexpected value can never be read as success.
func ClassifyRevocationStatus(status string) RevocationOutcome {
	switch status {
	case RevocationSuccessful:
		return OutcomeRevoked
	case RevocationInProgress:
		return OutcomeInProgress
	case RevocationNotApplicable:
		return OutcomeNotApplicable
	default:
		return OutcomeUnknown
	}
}

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
