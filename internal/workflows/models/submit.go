package models

// SubmitAccessRequest is the request body for creating a new access request.
type SubmitAccessRequest struct {
	TargetCategory string                 `json:"targetCategory"`
	RequestDetails map[string]interface{} `json:"requestDetails"`
}
