package models

import (
	"encoding/json"
	"testing"
)

func TestGroupsEligibleTarget_UnmarshalJSON(t *testing.T) {
	t.Parallel()
	input := `{"directoryId":"dir1","groupId":"grp1","groupName":"Engineering"}`

	var target GroupsEligibleTarget
	if err := json.Unmarshal([]byte(input), &target); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if target.DirectoryID != "dir1" {
		t.Errorf("DirectoryID = %q, want %q", target.DirectoryID, "dir1")
	}
	if target.GroupID != "grp1" {
		t.Errorf("GroupID = %q, want %q", target.GroupID, "grp1")
	}
	if target.GroupName != "Engineering" {
		t.Errorf("GroupName = %q, want %q", target.GroupName, "Engineering")
	}
}

func TestGroupsEligibilityResponse_UnmarshalJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		wantLen   int
		wantTotal int
		wantToken bool
	}{
		{
			name:      "single group",
			input:     `{"response":[{"directoryId":"dir1","groupId":"grp1","groupName":"Admins"}],"total":1}`,
			wantLen:   1,
			wantTotal: 1,
		},
		{
			name:      "empty response",
			input:     `{"response":[],"total":0}`,
			wantLen:   0,
			wantTotal: 0,
		},
		{
			name:      "with next token",
			input:     `{"response":[{"directoryId":"d1","groupId":"g1","groupName":"G1"}],"nextToken":"tok123","total":10}`,
			wantLen:   1,
			wantTotal: 10,
			wantToken: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var resp GroupsEligibilityResponse
			if err := json.Unmarshal([]byte(tt.input), &resp); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if len(resp.Response) != tt.wantLen {
				t.Errorf("len(Response) = %d, want %d", len(resp.Response), tt.wantLen)
			}
			if resp.Total != tt.wantTotal {
				t.Errorf("Total = %d, want %d", resp.Total, tt.wantTotal)
			}
			if tt.wantToken && resp.NextToken == nil {
				t.Error("NextToken is nil, want non-nil")
			}
		})
	}
}

func TestGroupsElevateRequest_MarshalJSON(t *testing.T) {
	t.Parallel()
	req := GroupsElevateRequest{
		DirectoryID: "dir1",
		CSP:         CSPAzure,
		Targets:     []GroupsElevateTarget{{GroupID: "grp1"}},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal check failed: %v", err)
	}
	if m["directoryId"] != "dir1" {
		t.Errorf("directoryId = %v, want dir1", m["directoryId"])
	}
	if m["csp"] != "AZURE" {
		t.Errorf("csp = %v, want AZURE", m["csp"])
	}
	targets := m["targets"].([]interface{})
	if len(targets) != 1 {
		t.Errorf("targets length = %d, want 1", len(targets))
	}
}

func TestGroupsElevateResponse_UnmarshalJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantError bool
	}{
		{
			name:      "success",
			input:     `{"directoryId":"dir1","csp":"AZURE","results":[{"groupId":"grp1","sessionId":"sess1"}]}`,
			wantCount: 1,
		},
		{
			name:      "with error",
			input:     `{"directoryId":"dir1","csp":"AZURE","results":[{"groupId":"grp1","sessionId":"","errorInfo":{"code":"ERR","message":"failed","description":"detail"}}]}`,
			wantCount: 1,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var resp GroupsElevateResponse
			if err := json.Unmarshal([]byte(tt.input), &resp); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if len(resp.Results) != tt.wantCount {
				t.Errorf("len(Results) = %d, want %d", len(resp.Results), tt.wantCount)
			}
			if tt.wantError && resp.Results[0].ErrorInfo == nil {
				t.Error("ErrorInfo is nil, want non-nil")
			}
			if !tt.wantError && resp.Results[0].ErrorInfo != nil {
				t.Errorf("ErrorInfo = %v, want nil", resp.Results[0].ErrorInfo)
			}
		})
	}
}
