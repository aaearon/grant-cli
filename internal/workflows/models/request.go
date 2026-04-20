package models

// RequestState represents the system activity status of an access request.
type RequestState string

const (
	RequestStateStarting RequestState = "STARTING"
	RequestStateRunning  RequestState = "RUNNING"
	RequestStatePending  RequestState = "PENDING"
	RequestStateFinished RequestState = "FINISHED"
	RequestStateExpired  RequestState = "EXPIRED"
)

// RequestResult represents the outcome of an access request.
type RequestResult string

const (
	RequestResultApproved RequestResult = "APPROVED"
	RequestResultRejected RequestResult = "REJECTED"
	RequestResultCanceled RequestResult = "CANCELED"
	RequestResultFailed   RequestResult = "FAILED"
	RequestResultUnknown  RequestResult = "UNKNOWN"
)

// AccessRequest represents a single access request from the API.
type AccessRequest struct {
	RequestID          string                 `json:"requestId"`
	TargetCategory     string                 `json:"targetCategory"`
	RequestState       RequestState           `json:"requestState"`
	RequestResult      RequestResult          `json:"requestResult"`
	RequestLink        string                 `json:"requestLink,omitempty"`
	RequestDetails     map[string]interface{} `json:"requestDetails,omitempty"`
	RequestApprovers   []ApproverAction       `json:"requestApprovers,omitempty"`
	AssignedApprovers  []Entity               `json:"assignedApprovers,omitempty"`
	Requester          *Entity                `json:"requester,omitempty"`
	RequestOutcomes    map[string]string      `json:"requestOutcomes,omitempty"`
	FinalizationReason string                 `json:"finalizationReason,omitempty"`
	CreatedBy          string                 `json:"createdBy"`
	CreatedAt          string                 `json:"createdAt"`
	UpdatedBy          string                 `json:"updatedBy"`
	UpdatedAt          string                 `json:"updatedAt"`
}

// Entity represents a user or approver identity.
type Entity struct {
	EntityID            string           `json:"entityId"`
	EntityName          string           `json:"entityName"`
	EntityDisplayName   string           `json:"entityDisplayName,omitempty"`
	EntityEmail         string           `json:"entityEmail,omitempty"`
	EntityDirectorySource *DirectorySource `json:"entityDirectorySource,omitempty"`
}

// DirectorySource represents the directory source of an entity.
type DirectorySource struct {
	DirectoryID   string `json:"directoryId"`
	DirectoryName string `json:"directoryName"`
	DirectoryType string `json:"directoryType,omitempty"`
}

// ApproverAction represents an action taken by an approver on a request.
type ApproverAction struct {
	Approver Entity        `json:"approver"`
	Result   RequestResult `json:"result"`
}

// ListRequestsResponse represents the paginated response from the list requests endpoint.
type ListRequestsResponse struct {
	Items      []AccessRequest `json:"items"`
	Count      int             `json:"count"`
	TotalCount int             `json:"totalCount"`
}

// DetailString returns a human-readable detail from requestDetails for the given key.
func (r *AccessRequest) DetailString(key string) string {
	if r.RequestDetails == nil {
		return ""
	}
	v, ok := r.RequestDetails[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
