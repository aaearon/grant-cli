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
		{"empty optional fields", &submitFields{"reason", "Medium", "", "", "", ""}, false},
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
		{"2025-08-12T09:41:00.594008", "2025-08-12T09:41:00"},
		{"2025-08-12T09:41:00", "2025-08-12T09:41:00"},
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

	resolveSubmitTargetFn = func(_ context.Context, _, _, _ string) (*models.EligibleTarget, error) {
		return &models.EligibleTarget{
			WorkspaceName: "Test Sub",
			WorkspaceID:   "ws-1",
			WorkspaceType: models.WorkspaceTypeSubscription,
			CSP:           models.CSPAzure,
			RoleInfo:      models.RoleInfo{ID: "role-1", Name: "Contributor"},
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
		"--target", "Test Sub", "--role", "Contributor",
		"--reason", "need access", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00")
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

	resolveSubmitTargetFn = func(_ context.Context, _, _, _ string) (*models.EligibleTarget, error) {
		return &models.EligibleTarget{
			WorkspaceName: "Test Sub",
			WorkspaceID:   "ws-1",
			CSP:           models.CSPAzure,
			RoleInfo:      models.RoleInfo{ID: "role-1", Name: "Contributor"},
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
		"--target", "Test Sub", "--role", "Contributor",
		"--reason", "test", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00",
		"--output", "json")
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

	resolveSubmitTargetFn = func(_ context.Context, _, _, _ string) (*models.EligibleTarget, error) {
		return &models.EligibleTarget{
			WorkspaceName: "Sub",
			WorkspaceID:   "ws-1",
			CSP:           models.CSPAzure,
			RoleInfo:      models.RoleInfo{ID: "r1", Name: "Reader"},
		}, nil
	}

	svc := &mockAccessRequestService{
		submitErr: errors.New("API failure"),
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "request", "submit",
		"--target", "Sub", "--role", "Reader",
		"--reason", "test", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00")
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

	resolveSubmitTargetFn = func(_ context.Context, _, _, _ string) (*models.EligibleTarget, error) {
		return &models.EligibleTarget{
			WorkspaceName: "Sub",
			WorkspaceID:   "ws-1",
			CSP:           models.CSPAzure,
			RoleInfo:      models.RoleInfo{ID: "r1", Name: "Reader"},
		}, nil
	}

	svc := &mockAccessRequestService{}
	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "request", "submit",
		"--target", "Sub", "--role", "Reader",
		"--reason", "test")
	if err == nil {
		t.Fatal("expected error for missing --date/--timezone/--from/--to, got nil")
	}
	if !strings.Contains(err.Error(), "non-interactive") {
		t.Errorf("error %q does not mention non-interactive", err.Error())
	}
}

func TestResolveSubmitFields_Interactive(t *testing.T) {
	originalPrompt := submitPromptFn
	defer func() { submitPromptFn = originalPrompt }()

	submitPromptFn = func() (*submitFields, error) {
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

	submitPromptFn = func() (*submitFields, error) {
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
