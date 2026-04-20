package models

// CancelAccessRequest is the request body for canceling an access request.
type CancelAccessRequest struct {
	CancelReason *string `json:"cancelReason"`
}
