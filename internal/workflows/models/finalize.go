package models

// FinalizeAccessRequest is the request body for approving or rejecting an access request.
type FinalizeAccessRequest struct {
	Result             string  `json:"result"`
	FinalizationReason *string `json:"finalizationReason,omitempty"`
}
