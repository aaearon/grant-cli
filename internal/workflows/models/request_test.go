package models

import (
	"encoding/json"
	"testing"
)

func TestAccessRequest_UnmarshalJSON(t *testing.T) {
	raw := `{
		"requestId": "8a45155d-0273-4bc8-8d45-9fe3f4d4de6d",
		"targetCategory": "CLOUD_CONSOLE",
		"requestState": "FINISHED",
		"requestResult": "APPROVED",
		"requestLink": "https://tenant.cyberark.cloud/userportal/ars",
		"requestDetails": {
			"locationType": "Azure",
			"roleName": "Load Test Reader",
			"workspaceName": "Azure Subscription",
			"priority": "Low",
			"reason": "I need access"
		},
		"requestApprovers": [{
			"approver": {
				"entityId": "279bd5a1-83db-4ec0-89e4-569396b0044c",
				"entityName": "approver_2@cyberark.cloud",
				"entityDisplayName": "Approver Two",
				"entityEmail": "approver_2@cyberark.com",
				"entityDirectorySource": {
					"directoryId": "09B9A9B0-6CE8-465F-AB03-65766D33B05E",
					"directoryName": "CyberArk Cloud Directory",
					"directoryType": "CDS"
				}
			},
			"result": "APPROVED"
		}],
		"assignedApprovers": [{
			"entityId": "0e061076-c3bc-4027-ac35-f864d98cdef7",
			"entityName": "approver_1@cyberark.cloud"
		}],
		"requestOutcomes": {"policyId": "aws_23f89256"},
		"finalizationReason": "Approved your access",
		"createdBy": "user@cyberark.cloud",
		"createdAt": "2025-08-12T09:41:00.594008",
		"updatedBy": "SYSTEM",
		"updatedAt": "2025-08-12T09:42:31.886399"
	}`

	var req AccessRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"RequestID", req.RequestID, "8a45155d-0273-4bc8-8d45-9fe3f4d4de6d"},
		{"TargetCategory", req.TargetCategory, "CLOUD_CONSOLE"},
		{"RequestState", string(req.RequestState), "FINISHED"},
		{"RequestResult", string(req.RequestResult), "APPROVED"},
		{"RequestLink", req.RequestLink, "https://tenant.cyberark.cloud/userportal/ars"},
		{"FinalizationReason", req.FinalizationReason, "Approved your access"},
		{"CreatedBy", req.CreatedBy, "user@cyberark.cloud"},
		{"UpdatedBy", req.UpdatedBy, "SYSTEM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}

	if len(req.RequestApprovers) != 1 {
		t.Fatalf("expected 1 approver action, got %d", len(req.RequestApprovers))
	}
	if req.RequestApprovers[0].Approver.EntityDisplayName != "Approver Two" {
		t.Errorf("approver display name: got %q", req.RequestApprovers[0].Approver.EntityDisplayName)
	}
	if req.RequestApprovers[0].Approver.EntityDirectorySource.DirectoryType != "CDS" {
		t.Errorf("directory type: got %q", req.RequestApprovers[0].Approver.EntityDirectorySource.DirectoryType)
	}

	if len(req.AssignedApprovers) != 1 {
		t.Fatalf("expected 1 assigned approver, got %d", len(req.AssignedApprovers))
	}

	if req.RequestOutcomes["policyId"] != "aws_23f89256" {
		t.Errorf("outcomes policyId: got %q", req.RequestOutcomes["policyId"])
	}
}

func TestAccessRequest_DetailString(t *testing.T) {
	tests := []struct {
		name    string
		details map[string]interface{}
		key     string
		want    string
	}{
		{"existing key", map[string]interface{}{"reason": "need access"}, "reason", "need access"},
		{"missing key", map[string]interface{}{"reason": "need access"}, "priority", ""},
		{"nil details", nil, "reason", ""},
		{"non-string value", map[string]interface{}{"roleType": 0}, "roleType", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &AccessRequest{RequestDetails: tt.details}
			if got := r.DetailString(tt.key); got != tt.want {
				t.Errorf("DetailString(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestListRequestsResponse_Unmarshal(t *testing.T) {
	raw := `{
		"items": [
			{"requestId": "id-1", "requestState": "PENDING", "requestResult": "UNKNOWN", "createdBy": "a", "createdAt": "t", "updatedBy": "b", "updatedAt": "t"},
			{"requestId": "id-2", "requestState": "FINISHED", "requestResult": "APPROVED", "createdBy": "a", "createdAt": "t", "updatedBy": "b", "updatedAt": "t"}
		],
		"count": 2,
		"totalCount": 10
	}`

	var resp ListRequestsResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(resp.Items))
	}
	if resp.TotalCount != 10 {
		t.Errorf("totalCount: got %d, want 10", resp.TotalCount)
	}
	if resp.Items[0].RequestState != RequestStatePending {
		t.Errorf("item[0] state: got %q", resp.Items[0].RequestState)
	}
}
