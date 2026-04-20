package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
	"github.com/spf13/cobra"
)

func TestRequestListCommand(t *testing.T) {
	tests := []struct {
		name        string
		svc         *mockAccessRequestService
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "list requests text output",
			svc: &mockAccessRequestService{
				listItems: []wfmodels.AccessRequest{
					{
						RequestID:    "req-1",
						RequestState: wfmodels.RequestStatePending,
						RequestResult: wfmodels.RequestResultUnknown,
						RequestDetails: map[string]interface{}{
							"workspaceName": "Azure Subscription",
							"roleName":      "Contributor",
							"priority":      "Medium",
						},
						CreatedBy: "user@test.com",
						CreatedAt: "2025-08-12T09:41:00.594008",
					},
				},
				listTotalCount: 1,
			},
			args:        []string{"list"},
			wantContain: []string{"req-1", "PENDING", "Azure Subscription", "Contributor", "Total: 1"},
		},
		{
			name: "list requests JSON output",
			svc: &mockAccessRequestService{
				listItems: []wfmodels.AccessRequest{
					{
						RequestID:    "req-1",
						RequestState: wfmodels.RequestStatePending,
						RequestResult: wfmodels.RequestResultUnknown,
						CreatedBy:    "user@test.com",
						CreatedAt:    "t",
						UpdatedBy:    "SYSTEM",
						UpdatedAt:    "t",
					},
				},
				listTotalCount: 1,
			},
			args:        []string{"list", "--output", "json"},
			wantContain: []string{`"requestId"`, `"totalCount"`},
		},
		{
			name: "list empty",
			svc: &mockAccessRequestService{
				listItems:      []wfmodels.AccessRequest{},
				listTotalCount: 0,
			},
			args:        []string{"list"},
			wantContain: []string{"No access requests found"},
		},
		{
			name:    "list error",
			svc:     &mockAccessRequestService{listErr: errors.New("API error")},
			args:    []string{"list"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewRequestCommandWithDeps(tt.svc)
			root := newTestRootCommand()
			root.AddCommand(cmd)

			args := append([]string{"request"}, tt.args...)
			output, err := executeCommand(root, args...)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v\noutput: %s", err, tt.wantErr, output)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestRequestGetCommand(t *testing.T) {
	tests := []struct {
		name        string
		svc         *mockAccessRequestService
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "get request text",
			svc: &mockAccessRequestService{
				getResult: &wfmodels.AccessRequest{
					RequestID:    "req-1",
					RequestState: wfmodels.RequestStateFinished,
					RequestResult: wfmodels.RequestResultApproved,
					TargetCategory: "CLOUD_CONSOLE",
					RequestDetails: map[string]interface{}{
						"workspaceName": "Azure Sub",
						"roleName":      "Reader",
						"priority":      "High",
						"reason":        "Need access",
					},
					FinalizationReason: "Looks good",
					CreatedBy:          "user@test.com",
					CreatedAt:          "2025-08-12T09:41:00",
					UpdatedBy:          "SYSTEM",
					UpdatedAt:          "2025-08-12T09:42:00",
				},
			},
			args:        []string{"get", "req-1"},
			wantContain: []string{"req-1", "FINISHED", "APPROVED", "Azure Sub", "Reader", "Looks good"},
		},
		{
			name: "get request JSON",
			svc: &mockAccessRequestService{
				getResult: &wfmodels.AccessRequest{
					RequestID:    "req-1",
					RequestState: wfmodels.RequestStateFinished,
					RequestResult: wfmodels.RequestResultApproved,
					CreatedBy:    "user@test.com",
					CreatedAt:    "t",
					UpdatedBy:    "SYSTEM",
					UpdatedAt:    "t",
				},
			},
			args:        []string{"get", "req-1", "--output", "json"},
			wantContain: []string{`"requestId"`, `"state"`},
		},
		{
			name:    "get no args",
			svc:     &mockAccessRequestService{},
			args:    []string{"get"},
			wantErr: true,
		},
		{
			name:    "get error",
			svc:     &mockAccessRequestService{getErr: errors.New("not found")},
			args:    []string{"get", "bad-id"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewRequestCommandWithDeps(tt.svc)
			root := newTestRootCommand()
			root.AddCommand(cmd)

			args := append([]string{"request"}, tt.args...)
			output, err := executeCommand(root, args...)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v\noutput: %s", err, tt.wantErr, output)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestRequestCancelCommand(t *testing.T) {
	tests := []struct {
		name        string
		svc         *mockAccessRequestService
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "cancel success",
			svc: &mockAccessRequestService{
				cancelResult: &wfmodels.AccessRequest{
					RequestID:     "req-1",
					RequestResult: wfmodels.RequestResultCanceled,
				},
			},
			args:        []string{"cancel", "req-1"},
			wantContain: []string{"req-1", "canceled"},
		},
		{
			name: "cancel with reason",
			svc: &mockAccessRequestService{
				cancelResult: &wfmodels.AccessRequest{
					RequestID:     "req-1",
					RequestResult: wfmodels.RequestResultCanceled,
				},
			},
			args:        []string{"cancel", "req-1", "--reason", "no longer needed"},
			wantContain: []string{"req-1", "canceled"},
		},
		{
			name:    "cancel error",
			svc:     &mockAccessRequestService{cancelErr: errors.New("forbidden")},
			args:    []string{"cancel", "req-1"},
			wantErr: true,
		},
		{
			name:    "cancel no args",
			svc:     &mockAccessRequestService{},
			args:    []string{"cancel"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewRequestCommandWithDeps(tt.svc)
			root := newTestRootCommand()
			root.AddCommand(cmd)

			args := append([]string{"request"}, tt.args...)
			output, err := executeCommand(root, args...)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v\noutput: %s", err, tt.wantErr, output)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestRequestApproveCommand(t *testing.T) {
	svc := &mockAccessRequestService{
		finalizeResult: &wfmodels.AccessRequest{
			RequestID:     "req-1",
			RequestResult: wfmodels.RequestResultApproved,
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "approve", "req-1", "--reason", "looks good")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}
	if !strings.Contains(output, "approved") {
		t.Errorf("expected 'approved' in output, got:\n%s", output)
	}
}

func TestRequestRejectCommand(t *testing.T) {
	svc := &mockAccessRequestService{
		finalizeResult: &wfmodels.AccessRequest{
			RequestID:     "req-1",
			RequestResult: wfmodels.RequestResultRejected,
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "reject", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}
	if !strings.Contains(output, "rejected") {
		t.Errorf("expected 'rejected' in output, got:\n%s", output)
	}
}

func TestRequestFinalizeJSON(t *testing.T) {
	svc := &mockAccessRequestService{
		finalizeResult: &wfmodels.AccessRequest{
			RequestID:     "req-1",
			RequestState:  wfmodels.RequestStateRunning,
			RequestResult: wfmodels.RequestResultApproved,
			CreatedBy:     "user@test",
			CreatedAt:     "t",
			UpdatedBy:     "SYSTEM",
			UpdatedAt:     "t",
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "approve", "req-1", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	var result accessRequestOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v\nraw: %s", err, output)
	}
	if result.RequestID != "req-1" {
		t.Errorf("requestId: got %q", result.RequestID)
	}
	if result.Result != "APPROVED" {
		t.Errorf("result: got %q", result.Result)
	}
}

func TestRequestListJSON(t *testing.T) {
	svc := &mockAccessRequestService{
		listItems: []wfmodels.AccessRequest{
			{
				RequestID:    "req-1",
				RequestState: wfmodels.RequestStatePending,
				RequestResult: wfmodels.RequestResultUnknown,
				RequestDetails: map[string]interface{}{
					"priority": "High",
					"reason":   "Need access",
				},
				CreatedBy: "user@test",
				CreatedAt: "t",
				UpdatedBy: "SYSTEM",
				UpdatedAt: "t",
			},
		},
		listTotalCount: 1,
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "list", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	var result accessRequestListOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v\nraw: %s", err, output)
	}
	if result.TotalCount != 1 {
		t.Errorf("totalCount: got %d", result.TotalCount)
	}
	if len(result.Requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(result.Requests))
	}
	if result.Requests[0].Priority != "High" {
		t.Errorf("priority: got %q", result.Requests[0].Priority)
	}
}

func TestValidateSubmitFields(t *testing.T) {
	tests := []struct {
		name   string
		fields *submitFields
		wantErr bool
	}{
		{"valid", &submitFields{"need access", "High", "2026-04-21", "America/New_York", "09:00", "17:00"}, false},
		{"missing reason", &submitFields{"", "Medium", "2026-04-21", "America/New_York", "09:00", "17:00"}, true},
		{"bad priority", &submitFields{"reason", "Urgent", "2026-04-21", "America/New_York", "09:00", "17:00"}, true},
		{"bad date format", &submitFields{"reason", "Medium", "04-21-2026", "America/New_York", "09:00", "17:00"}, true},
		{"bad time from", &submitFields{"reason", "Medium", "2026-04-21", "America/New_York", "9am", "17:00"}, true},
		{"bad time to", &submitFields{"reason", "Medium", "2026-04-21", "America/New_York", "09:00", "5pm"}, true},
		{"bad timezone", &submitFields{"reason", "Medium", "2026-04-21", "Eastern", "09:00", "17:00"}, true},
		{"UTC timezone", &submitFields{"reason", "Medium", "2026-04-21", "UTC", "09:00", "17:00"}, false},
		{"CET timezone", &submitFields{"reason", "Medium", "2026-04-21", "CET", "09:00", "17:00"}, false},
		{"invalid timezone", &submitFields{"reason", "Medium", "2026-04-21", "NotAZone", "09:00", "17:00"}, true},
		{"missing date", &submitFields{"reason", "Medium", "", "UTC", "09:00", "17:00"}, true},
		{"missing timezone", &submitFields{"reason", "Medium", "2026-04-21", "", "09:00", "17:00"}, true},
		{"missing from", &submitFields{"reason", "Medium", "2026-04-21", "UTC", "", "17:00"}, true},
		{"missing to", &submitFields{"reason", "Medium", "2026-04-21", "UTC", "09:00", ""}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSubmitFields(tt.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSubmitFields() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormatTimestamp(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// No timezone, with fractional seconds: trim fraction
		{"2025-08-12T09:41:00.594008", "2025-08-12T09:41:00"},
		// No timezone, no fractional seconds: return as-is
		{"2025-08-12T09:41:00", "2025-08-12T09:41:00"},
		// RFC3339 UTC with fractional seconds: strip fraction, keep Z
		{"2025-08-12T09:41:00.594008Z", "2025-08-12T09:41:00Z"},
		// RFC3339 UTC without fractional seconds: return normalised form
		{"2025-08-12T09:41:00Z", "2025-08-12T09:41:00Z"},
		// RFC3339 with offset and fractional seconds: strip fraction, keep offset
		{"2025-08-12T09:41:00.123+05:30", "2025-08-12T09:41:00+05:30"},
		// Arbitrary short string: return as-is
		{"short", "short"},
	}
	for _, tt := range tests {
		if got := formatTimestamp(tt.input); got != tt.want {
			t.Errorf("formatTimestamp(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRequestCancelJSON(t *testing.T) {
	svc := &mockAccessRequestService{
		cancelResult: &wfmodels.AccessRequest{
			RequestID:     "req-1",
			RequestResult: wfmodels.RequestResultCanceled,
			CreatedBy:     "user@test",
			CreatedAt:     "t",
			UpdatedBy:     "SYSTEM",
			UpdatedAt:     "t",
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "cancel", "req-1", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	var result accessRequestOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v\nraw: %s", err, output)
	}
	if result.Result != "CANCELED" {
		t.Errorf("result: got %q", result.Result)
	}
}

func TestRequestListValidation(t *testing.T) {
	svc := &mockAccessRequestService{}

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"invalid state", []string{"list", "--state", "INVALID"}, "--state must be one of"},
		{"invalid result", []string{"list", "--result", "BOGUS"}, "--result must be one of"},
		{"invalid priority", []string{"list", "--priority", "Urgent"}, "--priority must be one of"},
		{"invalid sort", []string{"list", "--sort", "badField"}, "--sort must be one of"},
		{"injection attempt", []string{"list", "--state", "') or 1=1--"}, "--state must be one of"},
		{"valid lowercase state", []string{"list", "--state", "running"}, ""},
		{"valid lowercase result", []string{"list", "--result", "approved"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewRequestCommandWithDeps(svc)
			root := newTestRootCommand()
			root.AddCommand(cmd)

			args := append([]string{"request"}, tt.args...)
			_, err := executeCommand(root, args...)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestRunRequestSubmit_NonInteractive(t *testing.T) {
	original := resolveSubmitTargetFn
	defer func() { resolveSubmitTargetFn = original }()

	resolveSubmitTargetFn = func(_ context.Context, _, _ string) (*submitWorkspace, error) {
		return &submitWorkspace{
			WorkspaceName:  "Test Sub",
			WorkspaceID:    "ws-1",
			WorkspaceType:  models.WorkspaceTypeSubscription,
			CSP:            models.CSPAzure,
			OrganizationID: "org-1",
		}, nil
	}

	svc := &mockAccessRequestService{
		submitResult: &wfmodels.AccessRequest{
			RequestID:    "req-new",
			RequestState: wfmodels.RequestStatePending,
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "submit",
		"--target", "Test Sub", "--role-id", "role-1", "--role", "Contributor",
		"--reason", "need access", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00",
		"--yes")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}
	if !strings.Contains(output, "req-new") {
		t.Errorf("expected request ID in output, got:\n%s", output)
	}
}

func TestRunRequestSubmit_JSONOutput(t *testing.T) {
	original := resolveSubmitTargetFn
	defer func() { resolveSubmitTargetFn = original }()

	resolveSubmitTargetFn = func(_ context.Context, _, _ string) (*submitWorkspace, error) {
		return &submitWorkspace{
			WorkspaceName:  "Test Sub",
			WorkspaceID:    "ws-1",
			CSP:            models.CSPAzure,
			OrganizationID: "org-1",
		}, nil
	}

	svc := &mockAccessRequestService{
		submitResult: &wfmodels.AccessRequest{
			RequestID:     "req-json",
			RequestState:  wfmodels.RequestStatePending,
			RequestResult: wfmodels.RequestResultUnknown,
			CreatedBy:     "user@test",
			CreatedAt:     "t",
			UpdatedBy:     "SYSTEM",
			UpdatedAt:     "t",
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "submit",
		"--target", "Test Sub", "--role-id", "role-1", "--role", "Contributor",
		"--reason", "test", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00",
		"--output", "json", "--yes")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	var result accessRequestOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v\nraw: %s", err, output)
	}
	if result.RequestID != "req-json" {
		t.Errorf("requestId: got %q", result.RequestID)
	}
}

func TestRunRequestSubmit_ServiceError(t *testing.T) {
	original := resolveSubmitTargetFn
	defer func() { resolveSubmitTargetFn = original }()

	resolveSubmitTargetFn = func(_ context.Context, _, _ string) (*submitWorkspace, error) {
		return &submitWorkspace{
			WorkspaceName:  "Sub",
			WorkspaceID:    "ws-1",
			CSP:            models.CSPAzure,
			OrganizationID: "org-1",
		}, nil
	}

	svc := &mockAccessRequestService{
		submitErr: errors.New("API failure"),
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "request", "submit",
		"--target", "Sub", "--role-id", "r1",
		"--reason", "test", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00",
		"--yes")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "API failure") {
		t.Errorf("error %q does not contain 'API failure'", err.Error())
	}
}

func TestRunRequestSubmit_MissingFlags_NonInteractive(t *testing.T) {
	original := resolveSubmitTargetFn
	defer func() { resolveSubmitTargetFn = original }()

	resolveSubmitTargetFn = func(_ context.Context, _, _ string) (*submitWorkspace, error) {
		return &submitWorkspace{
			WorkspaceName:  "Sub",
			WorkspaceID:    "ws-1",
			CSP:            models.CSPAzure,
			OrganizationID: "org-1",
		}, nil
	}

	svc := &mockAccessRequestService{}
	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "request", "submit",
		"--target", "Sub", "--role-id", "r1",
		"--reason", "test")
	if err == nil {
		t.Fatal("expected error for missing --date/--timezone/--from/--to, got nil")
	}
	if !strings.Contains(err.Error(), "non-interactive") {
		t.Errorf("error %q does not mention non-interactive", err.Error())
	}
}

func TestBuildOnDemandRequest_UnsupportedType(t *testing.T) {
	tests := []struct {
		name string
		wt   models.WorkspaceType
	}{
		{"subscription", models.WorkspaceTypeSubscription},
		{"resource_group", models.WorkspaceType("RESOURCE_GROUP")},
		{"resource", models.WorkspaceType("RESOURCE")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildOnDemandRequest(&submitWorkspace{
				WorkspaceID:    "ws-1",
				WorkspaceType:  tt.wt,
				OrganizationID: "org-1",
			})
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), "not supported") {
				t.Errorf("error should mention not supported: %v", err)
			}
			if !strings.Contains(err.Error(), "--role-id") {
				t.Errorf("error should point to --role-id: %v", err)
			}
		})
	}
}

func TestBuildOnDemandRequest_SupportedTypes(t *testing.T) {
	tests := []struct {
		name         string
		wt           models.WorkspaceType
		wsID         string
		orgID        string
		wantPlatform string
		wantAnces    int
	}{
		{"directory", models.WorkspaceType("DIRECTORY"), "dir-1", "dir-1", "azure_ad", 0},
		{"account", models.WorkspaceType("ACCOUNT"), "123", "123", "aws", 0},
		{"management_group", models.WorkspaceType("MANAGEMENT_GROUP"), "providers/Microsoft.Management/managementGroups/root", "dir-456", "azure_resource", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := buildOnDemandRequest(&submitWorkspace{
				WorkspaceID:    tt.wsID,
				WorkspaceType:  tt.wt,
				OrganizationID: tt.orgID,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.PlatformName != tt.wantPlatform {
				t.Errorf("platform: got %q want %q", req.PlatformName, tt.wantPlatform)
			}
			if len(req.Ancestors) != tt.wantAnces {
				t.Errorf("ancestors: got %d want %d", len(req.Ancestors), tt.wantAnces)
			}
		})
	}
}

func TestRunRequestSubmit_InteractiveRoleSelection(t *testing.T) {
	origTarget := resolveSubmitTargetFn
	origRole := resolveRoleFn
	origTTY := ui.IsTerminalFunc
	defer func() {
		resolveSubmitTargetFn = origTarget
		resolveRoleFn = origRole
		ui.IsTerminalFunc = origTTY
	}()
	ui.IsTerminalFunc = func(fd uintptr) bool { return true }

	resolveSubmitTargetFn = func(_ context.Context, _, _ string) (*submitWorkspace, error) {
		return &submitWorkspace{
			WorkspaceName:  "Dir",
			WorkspaceID:    "dir-1",
			WorkspaceType:  models.WorkspaceType("DIRECTORY"),
			CSP:            models.CSPAzure,
			OrganizationID: "dir-1",
		}, nil
	}
	resolveRoleFn = func(_ context.Context, ws *submitWorkspace) (string, string, error) {
		if ws.WorkspaceID != "dir-1" {
			t.Errorf("expected ws dir-1, got %s", ws.WorkspaceID)
		}
		return "arn:aws:iam::1:role/Admin", "Admin", nil
	}

	svc := &mockAccessRequestService{
		submitResult: &wfmodels.AccessRequest{RequestID: "req-x", RequestState: wfmodels.RequestStatePending},
	}
	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "submit",
		"--reason", "test", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00",
		"--yes")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	submitted := svc.submitRequest
	if submitted == nil {
		t.Fatal("expected a submitted request")
	}
	if submitted.RequestDetails["roleId"] != "arn:aws:iam::1:role/Admin" {
		t.Errorf("roleId: got %v", submitted.RequestDetails["roleId"])
	}
	if submitted.RequestDetails["roleName"] != "Admin" {
		t.Errorf("roleName: got %v", submitted.RequestDetails["roleName"])
	}
}

func TestResolveSubmitFields_Interactive(t *testing.T) {
	originalPrompt := submitPromptFn
	defer func() { submitPromptFn = originalPrompt }()

	submitPromptFn = func(_ *submitFields) (*submitFields, error) {
		return &submitFields{
			reason:   "prompted reason",
			priority: "High",
			date:     "2026-05-01",
			timezone: "America/Chicago",
			timeFrom: "10:00",
			timeTo:   "18:00",
		}, nil
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("reason", "", "")
	cmd.Flags().String("priority", "Medium", "")
	cmd.Flags().String("date", "", "")
	cmd.Flags().String("timezone", "", "")
	cmd.Flags().String("from", "", "")
	cmd.Flags().String("to", "", "")

	originalTTY := ui.IsTerminalFunc
	defer func() { ui.IsTerminalFunc = originalTTY }()
	ui.IsTerminalFunc = func(fd uintptr) bool { return true }

	f, err := resolveSubmitFields(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.reason != "prompted reason" {
		t.Errorf("reason: got %q", f.reason)
	}
	if f.priority != "High" {
		t.Errorf("priority: got %q", f.priority)
	}
	if f.date != "2026-05-01" {
		t.Errorf("date: got %q", f.date)
	}
}

func TestResolveSubmitFields_FlagOverridesPrompt(t *testing.T) {
	originalPrompt := submitPromptFn
	defer func() { submitPromptFn = originalPrompt }()

	submitPromptFn = func(_ *submitFields) (*submitFields, error) {
		return &submitFields{
			reason:   "prompted",
			priority: "Low",
			date:     "2026-05-01",
			timezone: "America/Chicago",
			timeFrom: "10:00",
			timeTo:   "18:00",
		}, nil
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("reason", "", "")
	cmd.Flags().String("priority", "Medium", "")
	cmd.Flags().String("date", "", "")
	cmd.Flags().String("timezone", "", "")
	cmd.Flags().String("from", "", "")
	cmd.Flags().String("to", "", "")
	// Simulate user passing --reason flag
	cmd.SetArgs([]string{"--reason", "flag reason"})
	_ = cmd.Execute()

	originalTTY := ui.IsTerminalFunc
	defer func() { ui.IsTerminalFunc = originalTTY }()
	ui.IsTerminalFunc = func(fd uintptr) bool { return true }

	f, err := resolveSubmitFields(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.reason != "flag reason" {
		t.Errorf("reason: got %q, want 'flag reason'", f.reason)
	}
}

func TestResolveSubmitFields_NonInteractive_Error(t *testing.T) {
	originalTTY := ui.IsTerminalFunc
	defer func() { ui.IsTerminalFunc = originalTTY }()
	ui.IsTerminalFunc = func(fd uintptr) bool { return false }

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("reason", "", "")
	cmd.Flags().String("priority", "Medium", "")
	cmd.Flags().String("date", "", "")
	cmd.Flags().String("timezone", "", "")
	cmd.Flags().String("from", "", "")
	cmd.Flags().String("to", "", "")

	_, err := resolveSubmitFields(cmd)
	if err == nil {
		t.Fatal("expected error for non-interactive mode")
	}
	if !strings.Contains(err.Error(), "non-interactive") {
		t.Errorf("error %q does not mention non-interactive", err.Error())
	}
}

func TestResolveLocalTimezone(t *testing.T) {
	tz := resolveLocalTimezone()
	if tz == "Local" {
		t.Error("resolveLocalTimezone() returned 'Local'")
	}
	if tz == "" {
		t.Error("resolveLocalTimezone() returned empty string")
	}
}

func TestRunRequestSubmit_InvalidProvider(t *testing.T) {
	original := resolveSubmitTargetFn
	defer func() { resolveSubmitTargetFn = original }()

	resolveSubmitTargetFn = func(_ context.Context, _, _ string) (*submitWorkspace, error) {
		t.Fatal("resolveSubmitTarget should not be called with invalid provider")
		return nil, nil
	}

	svc := &mockAccessRequestService{}
	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "request", "submit",
		"--provider", "gcp",
		"--target", "Sub", "--role-id", "r1",
		"--reason", "test", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00",
		"--yes")
	if err == nil {
		t.Fatal("expected error for invalid provider")
	}
	if !strings.Contains(err.Error(), "invalid provider") {
		t.Errorf("error %q does not mention invalid provider", err.Error())
	}
}

func TestRunRequestSubmit_ConfirmationDenied(t *testing.T) {
	original := resolveSubmitTargetFn
	originalConfirm := confirmSubmitFn
	defer func() {
		resolveSubmitTargetFn = original
		confirmSubmitFn = originalConfirm
	}()

	resolveSubmitTargetFn = func(_ context.Context, _, _ string) (*submitWorkspace, error) {
		return &submitWorkspace{
			WorkspaceName:  "Test Sub",
			WorkspaceID:    "ws-1",
			CSP:            models.CSPAzure,
			OrganizationID: "org-1",
		}, nil
	}
	confirmSubmitFn = func() (bool, error) {
		return false, nil
	}

	originalTTY := ui.IsTerminalFunc
	defer func() { ui.IsTerminalFunc = originalTTY }()
	ui.IsTerminalFunc = func(fd uintptr) bool { return true }

	svc := &mockAccessRequestService{
		submitResult: &wfmodels.AccessRequest{RequestID: "should-not-reach"},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "submit",
		"--target", "Test Sub", "--role-id", "role-1",
		"--reason", "test", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "canceled") {
		t.Errorf("expected 'canceled' in output, got: %s", output)
	}
}

func TestRunRequestSubmit_YesFlagSkipsConfirmation(t *testing.T) {
	original := resolveSubmitTargetFn
	originalConfirm := confirmSubmitFn
	defer func() {
		resolveSubmitTargetFn = original
		confirmSubmitFn = originalConfirm
	}()

	resolveSubmitTargetFn = func(_ context.Context, _, _ string) (*submitWorkspace, error) {
		return &submitWorkspace{
			WorkspaceName:  "Test Sub",
			WorkspaceID:    "ws-1",
			CSP:            models.CSPAzure,
			OrganizationID: "org-1",
		}, nil
	}
	confirmSubmitFn = func() (bool, error) {
		t.Fatal("confirmSubmitFn should not be called with --yes")
		return false, nil
	}

	svc := &mockAccessRequestService{
		submitResult: &wfmodels.AccessRequest{
			RequestID:    "req-yes",
			RequestState: wfmodels.RequestStatePending,
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "submit",
		"--target", "Test Sub", "--role-id", "role-1",
		"--reason", "test", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00",
		"--yes")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}
	if !strings.Contains(output, "req-yes") {
		t.Errorf("expected request ID in output, got: %s", output)
	}
}

func TestDeduplicateWorkspaces(t *testing.T) {
	targets := []models.EligibleTarget{
		{WorkspaceName: "Sub A", WorkspaceID: "ws-a", CSP: models.CSPAzure, WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r1", Name: "Reader"}},
		{WorkspaceName: "Sub A", WorkspaceID: "ws-a", CSP: models.CSPAzure, WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r2", Name: "Contributor"}},
		{WorkspaceName: "Sub B", WorkspaceID: "ws-b", CSP: models.CSPAzure, WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r3", Name: "Reader"}},
		{WorkspaceName: "AWS Account", WorkspaceID: "ws-c", CSP: models.CSPAWS, WorkspaceType: models.WorkspaceTypeAccount, RoleInfo: models.RoleInfo{ID: "r4", Name: "Admin"}},
	}

	workspaces := deduplicateWorkspaces(targets)
	if len(workspaces) != 3 {
		t.Fatalf("expected 3 unique workspaces, got %d", len(workspaces))
	}

	names := make(map[string]bool)
	for _, ws := range workspaces {
		names[ws.WorkspaceName] = true
	}
	if !names["Sub A"] || !names["Sub B"] || !names["AWS Account"] {
		t.Errorf("unexpected workspace names: %v", names)
	}
}

func TestFormatWorkspaceOption(t *testing.T) {
	ws := submitWorkspace{
		WorkspaceName: "Production Account",
		WorkspaceType: models.WorkspaceTypeAccount,
		CSP:           models.CSPAWS,
	}
	got := formatWorkspaceOption(ws)
	want := "Account: Production Account (aws)"
	if got != want {
		t.Errorf("formatWorkspaceOption() = %q, want %q", got, want)
	}
}

func TestDefaultSubmitPrompt_NonInteractive(t *testing.T) {
	originalTTY := ui.IsTerminalFunc
	defer func() { ui.IsTerminalFunc = originalTTY }()
	ui.IsTerminalFunc = func(fd uintptr) bool { return false }

	_, err := defaultSubmitPrompt(&submitFields{})
	if err == nil {
		t.Fatal("expected error in non-interactive mode")
	}
	if !errors.Is(err, ui.ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive, got: %v", err)
	}
}

func TestResolveSubmitFields_PromptOnlyMissing(t *testing.T) {
	originalPrompt := submitPromptFn
	defer func() { submitPromptFn = originalPrompt }()

	var receivedExisting *submitFields
	submitPromptFn = func(existing *submitFields) (*submitFields, error) {
		receivedExisting = existing
		return &submitFields{
			reason:   "prompted",
			priority: "High",
			date:     "2026-05-01",
			timezone: "America/Chicago",
			timeFrom: "10:00",
			timeTo:   "18:00",
		}, nil
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("reason", "", "")
	cmd.Flags().String("priority", "Medium", "")
	cmd.Flags().String("date", "", "")
	cmd.Flags().String("timezone", "", "")
	cmd.Flags().String("from", "", "")
	cmd.Flags().String("to", "", "")
	cmd.SetArgs([]string{"--reason", "my reason", "--date", "2026-06-01"})
	_ = cmd.Execute()

	originalTTY := ui.IsTerminalFunc
	defer func() { ui.IsTerminalFunc = originalTTY }()
	ui.IsTerminalFunc = func(fd uintptr) bool { return true }

	f, err := resolveSubmitFields(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedExisting == nil {
		t.Fatal("submitPromptFn was not called with existing fields")
	}
	if receivedExisting.reason != "my reason" {
		t.Errorf("existing.reason: got %q, want 'my reason'", receivedExisting.reason)
	}
	if receivedExisting.date != "2026-06-01" {
		t.Errorf("existing.date: got %q, want '2026-06-01'", receivedExisting.date)
	}
	// Flag values should override prompted values
	if f.reason != "my reason" {
		t.Errorf("f.reason: got %q, want 'my reason'", f.reason)
	}
	if f.date != "2026-06-01" {
		t.Errorf("f.date: got %q, want '2026-06-01'", f.date)
	}
}
