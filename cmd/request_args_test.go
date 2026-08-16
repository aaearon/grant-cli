package cmd

// Argument-capture tests for the `grant request` subcommands.
//
// Each test names the mutation it kills. The pre-existing tests in
// request_test.go assert on printed text that the command generates locally
// (e.g. "rejected" comes from decisionPastTense, not from the wire), so they
// survive mutations to what is actually sent to the API.
//
// Fixture values are deliberately distinguishable — a swap mutation only dies
// when the two values differ. Do not "tidy" them back to a shared constant.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
)

// TestRequestReject_SendsRejectedDecision kills REQ-01: hardcoding the decision
// argument at cmd/request_finalize.go:100 (e.g. always "APPROVED"). The
// existing tests only assert the printed verb, which decisionPastTense derives
// from the local literal and not from what was sent.
func TestRequestReject_SendsRejectedDecision(t *testing.T) {
	svc := &mockAccessRequestService{
		finalizeResult: &wfmodels.AccessRequest{
			RequestID:     "req-reject-1",
			RequestResult: wfmodels.RequestResultRejected,
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "reject", "req-reject-1", "--reason", "insufficient justification")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	if len(svc.finalizeCalls) != 1 {
		t.Fatalf("expected exactly 1 FinalizeRequest call, got %d", len(svc.finalizeCalls))
	}
	got := svc.lastFinalize()
	if got.decision != "REJECTED" {
		t.Errorf("decision sent = %q, want REJECTED", got.decision)
	}
	if got.requestID != "req-reject-1" {
		t.Errorf("requestId sent = %q, want req-reject-1", got.requestID)
	}
	if !got.reasonSet || got.reason != "insufficient justification" {
		t.Errorf("reason sent = %q (set=%v), want %q", got.reason, got.reasonSet, "insufficient justification")
	}
}

// TestRequestApprove_SendsApprovedDecision is the companion to the reject case:
// together they make a swap of the two literals fail.
func TestRequestApprove_SendsApprovedDecision(t *testing.T) {
	svc := &mockAccessRequestService{
		finalizeResult: &wfmodels.AccessRequest{
			RequestID:     "req-approve-1",
			RequestResult: wfmodels.RequestResultApproved,
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "approve", "req-approve-1")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	got := svc.lastFinalize()
	if got == nil {
		t.Fatal("FinalizeRequest was never called")
	}
	if got.decision != "APPROVED" {
		t.Errorf("decision sent = %q, want APPROVED", got.decision)
	}
	if got.requestID != "req-approve-1" {
		t.Errorf("requestId sent = %q, want req-approve-1", got.requestID)
	}
	// No --reason: the command must send nil, not an empty string.
	if got.reasonSet {
		t.Errorf("reason should be nil when --reason is absent, got %q", got.reason)
	}
}

// TestRequestFinalize_EmptyReasonCollapsesToUnset pins the deliberate
// behavior of runFinalize's `if v != "" { reason = &v }`: an explicitly empty
// --reason is indistinguishable from no --reason at all on the wire. The mock's
// reasonSet flag is what makes the two expressible, so the distinction is
// asserted rather than merely representable.
func TestRequestFinalize_EmptyReasonCollapsesToUnset(t *testing.T) {
	svc := &mockAccessRequestService{
		finalizeResult: &wfmodels.AccessRequest{
			RequestID:     "req-approve-2",
			RequestResult: wfmodels.RequestResultApproved,
		},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "approve", "req-approve-2", "--reason", "")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	if len(svc.finalizeCalls) != 1 {
		t.Fatalf("expected exactly 1 FinalizeRequest call, got %d", len(svc.finalizeCalls))
	}
	got := svc.lastFinalize()
	if got.reasonSet {
		t.Errorf(`--reason "" must collapse to a nil reason, got %q`, got.reason)
	}
}

// TestRequestCancel_PassesRequestID kills REQ-02: sending anything other than
// the requested ID at cmd/request_cancel.go:60.
func TestRequestCancel_PassesRequestID(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantReason    string
		wantReasonSet bool
	}{
		{name: "without reason", args: []string{"request", "cancel", "req-cancel-7"}},
		{
			name:          "with reason",
			args:          []string{"request", "cancel", "req-cancel-7", "--reason", "changed my mind"},
			wantReason:    "changed my mind",
			wantReasonSet: true,
		},
		{
			// runRequestCancel deliberately collapses an explicitly empty
			// --reason into "unset" (`if v != "" { reason = &v }`), so the API
			// sees nil rather than a pointer to "". Pinned so that a future
			// change to that collapse cannot slip through unnoticed.
			name: "explicitly empty reason collapses to unset",
			args: []string{"request", "cancel", "req-cancel-7", "--reason", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAccessRequestService{
				cancelResult: &wfmodels.AccessRequest{
					RequestID:     "req-cancel-7",
					RequestResult: wfmodels.RequestResultCanceled,
				},
			}

			cmd := NewRequestCommandWithDeps(svc)
			root := newTestRootCommand()
			root.AddCommand(cmd)

			output, err := executeCommand(root, tt.args...)
			if err != nil {
				t.Fatalf("unexpected error: %v\noutput: %s", err, output)
			}

			if len(svc.cancelCalls) != 1 {
				t.Fatalf("expected exactly 1 CancelRequest call, got %d", len(svc.cancelCalls))
			}
			got := svc.lastCancel()
			if got.requestID != "req-cancel-7" {
				t.Errorf("requestId sent = %q, want req-cancel-7", got.requestID)
			}
			if got.reasonSet != tt.wantReasonSet || got.reason != tt.wantReason {
				t.Errorf("reason sent = %q (set=%v), want %q (set=%v)",
					got.reason, got.reasonSet, tt.wantReason, tt.wantReasonSet)
			}
		})
	}
}

// TestRequestGet_PassesRequestID kills REQ-03: sending anything other than the
// requested ID at cmd/request_get.go:53.
func TestRequestGet_PassesRequestID(t *testing.T) {
	svc := &mockAccessRequestService{
		getResult: &wfmodels.AccessRequest{
			RequestID:     "req-get-42",
			RequestState:  wfmodels.RequestStateFinished,
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

	output, err := executeCommand(root, "request", "get", "req-get-42")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	if len(svc.getCalls) != 1 {
		t.Fatalf("expected exactly 1 GetRequest call, got %d", len(svc.getCalls))
	}
	if svc.getCalls[0] != "req-get-42" {
		t.Errorf("requestId sent = %q, want req-get-42", svc.getCalls[0])
	}
}

// TestRequestList_ParamsFromFlags kills REQ-04, REQ-06 and REQ-07: the
// --state filter, --search free text and the asc/desc sort direction must all
// reach ListRequestsParams.
func TestRequestList_ParamsFromFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantSort string
		wantFilt string
		wantFree string
		wantRole string
	}{
		{
			name:     "default sort is descending",
			args:     []string{"request", "list"},
			wantSort: "createdAt desc",
		},
		{
			name:     "desc=false sorts ascending",
			args:     []string{"request", "list", "--desc=false"},
			wantSort: "createdAt asc",
		},
		{
			name:     "sort field is honored",
			args:     []string{"request", "list", "--sort", "updatedAt", "--desc=false"},
			wantSort: "updatedAt asc",
		},
		{
			name:     "state becomes a filter",
			args:     []string{"request", "list", "--state", "pending"},
			wantSort: "createdAt desc",
			wantFilt: "((requestState eq PENDING))",
		},
		{
			name:     "search becomes free text",
			args:     []string{"request", "list", "--search", "prod-eastus"},
			wantSort: "createdAt desc",
			wantFree: "prod-eastus",
		},
		{
			name:     "role is uppercased and passed",
			args:     []string{"request", "list", "--role", "approver"},
			wantSort: "createdAt desc",
			wantRole: "APPROVER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAccessRequestService{}

			cmd := NewRequestCommandWithDeps(svc)
			root := newTestRootCommand()
			root.AddCommand(cmd)

			output, err := executeCommand(root, tt.args...)
			if err != nil {
				t.Fatalf("unexpected error: %v\noutput: %s", err, output)
			}

			if len(svc.listCalls) != 1 {
				t.Fatalf("expected exactly 1 ListRequests call, got %d", len(svc.listCalls))
			}
			got := svc.lastListParams()
			if got.Sort != tt.wantSort {
				t.Errorf("Sort = %q, want %q", got.Sort, tt.wantSort)
			}
			if got.Filter != tt.wantFilt {
				t.Errorf("Filter = %q, want %q", got.Filter, tt.wantFilt)
			}
			if got.FreeText != tt.wantFree {
				t.Errorf("FreeText = %q, want %q", got.FreeText, tt.wantFree)
			}
			if got.RequestRole != tt.wantRole {
				t.Errorf("RequestRole = %q, want %q", got.RequestRole, tt.wantRole)
			}
		})
	}
}

// TestRequestList_RejectsInvalidRole kills REQ-05: dropping the --role
// validation at cmd/request_list.go:82 would forward an arbitrary role string
// to the API instead of failing locally.
func TestRequestList_RejectsInvalidRole(t *testing.T) {
	svc := &mockAccessRequestService{}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "request", "list", "--role", "AUDITOR")
	if err == nil {
		t.Fatal("expected an error for an invalid --role")
	}
	if !strings.Contains(err.Error(), "--role must be CREATOR or APPROVER") {
		t.Errorf("error = %v, want the --role validation message", err)
	}
	if len(svc.listCalls) != 0 {
		t.Errorf("ListRequests must not be called, got params %+v", svc.listCalls)
	}
}

// submitStub points resolveSubmitTargetFn at a fixed workspace and fails the
// test if role resolution is reached.
func submitStubWorkspace(t *testing.T, ws *submitWorkspace) {
	t.Helper()
	origTarget := resolveSubmitTargetFn
	origRole := resolveRoleFn
	t.Cleanup(func() {
		resolveSubmitTargetFn = origTarget
		resolveRoleFn = origRole
	})
	resolveSubmitTargetFn = func(_ context.Context, _, _ string, _ bool) (*submitWorkspace, error) {
		return ws, nil
	}
	resolveRoleFn = func(_ context.Context, _ *submitWorkspace, _ bool) (string, string, error) {
		t.Fatal("role resolution must not run when --role-id is supplied")
		return "", "", nil
	}
}

// TestRunRequestSubmit_SubmitPayload kills REQ-08, REQ-09 and REQ-10: the
// hardcoded TargetCategory, the workspace ID in the request details, and the
// timeFrom/timeTo pair (distinct values, so a swap dies).
//
// Table over both CSPs that buildRequestDetails special-cases. The AWS row is
// the load-bearing one: "AWS" is exactly where locationType stops being a
// naive string(ws.CSP), so an Azure-only fixture leaves that mapping unpinned.
//
// The assertion is exhaustive, not a subset: comparing len(RequestDetails)
// against len(wantDetails) is what makes an *extra* key fail too.
func TestRunRequestSubmit_SubmitPayload(t *testing.T) {
	tests := []struct {
		name             string
		csp              models.CSP
		workspaceType    models.WorkspaceType
		wantLocationType string
	}{
		{
			name:             "azure subscription",
			csp:              models.CSPAzure,
			workspaceType:    models.WorkspaceTypeSubscription,
			wantLocationType: "Azure",
		},
		{
			name:             "aws account",
			csp:              models.CSPAWS,
			workspaceType:    models.WorkspaceTypeAccount,
			wantLocationType: "AWS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submitStubWorkspace(t, &submitWorkspace{
				WorkspaceName:  "Prod-EastUS",
				WorkspaceID:    "ws-payload-1",
				WorkspaceType:  tt.workspaceType,
				CSP:            tt.csp,
				OrganizationID: "org-payload-9",
			})

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
				"--target", "Prod-EastUS", "--role-id", "role-payload-3", "--role", "Contributor",
				"--reason", "need access", "--date", "2026-04-21",
				"--timezone", "UTC",
				// Distinguishable on purpose: identical values would not kill a swap.
				"--from", "08:15", "--to", "19:45",
				"--yes")
			if err != nil {
				t.Fatalf("unexpected error: %v\noutput: %s", err, output)
			}

			if len(svc.submitCalls) != 1 {
				t.Fatalf("expected exactly 1 SubmitRequest call, got %d", len(svc.submitCalls))
			}
			sent := svc.lastSubmit()
			if sent.TargetCategory != "CLOUD_CONSOLE" {
				t.Errorf("targetCategory = %q, want CLOUD_CONSOLE", sent.TargetCategory)
			}

			wantDetails := map[string]interface{}{
				"locationType":  tt.wantLocationType,
				"roleId":        "role-payload-3",
				"roleName":      "Contributor",
				"workspaceId":   "ws-payload-1",
				"workspaceName": "Prod-EastUS",
				"workspaceType": string(tt.workspaceType),
				"orgId":         "org-payload-9",
				"reason":        "need access",
				"priority":      "Medium",
				"requestDate":   "2026-04-21",
				"timezone":      "UTC",
				"timeFrom":      "08:15",
				"timeTo":        "19:45",
			}
			if len(sent.RequestDetails) != len(wantDetails) {
				t.Errorf("requestDetails has %d keys, want %d: got %v",
					len(sent.RequestDetails), len(wantDetails), sent.RequestDetails)
			}
			for key, want := range wantDetails {
				if got := sent.RequestDetails[key]; got != want {
					t.Errorf("requestDetails[%q] = %v, want %v", key, got, want)
				}
			}
		})
	}
}

// TestRunRequestSubmit_InvokesValidation kills REQ-11: deleting the
// validateSubmitFields call site at cmd/request_submit.go:274. The existing
// coverage calls validateSubmitFields directly, so it cannot see the call site
// disappear. --priority is validated nowhere else in the flow.
func TestRunRequestSubmit_InvokesValidation(t *testing.T) {
	submitStubWorkspace(t, &submitWorkspace{
		WorkspaceName:  "Prod-EastUS",
		WorkspaceID:    "ws-1",
		WorkspaceType:  models.WorkspaceTypeSubscription,
		CSP:            models.CSPAzure,
		OrganizationID: "org-1",
	})

	svc := &mockAccessRequestService{
		submitResult: &wfmodels.AccessRequest{RequestID: "must-not-be-reached"},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "request", "submit",
		"--target", "Prod-EastUS", "--role-id", "role-1",
		"--reason", "need access", "--priority", "Urgent",
		"--date", "2026-04-21", "--timezone", "UTC",
		"--from", "09:00", "--to", "17:00",
		"--yes")
	if err == nil {
		t.Fatal("expected a validation error for --priority Urgent")
	}
	if !strings.Contains(err.Error(), "--priority must be High, Medium, or Low") {
		t.Errorf("error = %v, want the --priority validation message", err)
	}
	// len(submitCalls) rather than lastSubmit(): the latter cannot tell
	// "never called" apart from "called with a nil request".
	if len(svc.submitCalls) != 0 {
		t.Errorf("nothing may be submitted after a validation failure, got %+v", svc.submitCalls)
	}
}

// TestValidateSubmitFields_ErrorMessages kills REQ-12: the existing table only
// checks that an error occurred, so any message can be swapped for any other.
func TestValidateSubmitFields_ErrorMessages(t *testing.T) {
	valid := submitFields{
		reason: "need access", priority: "Medium", date: "2026-04-21",
		timezone: "UTC", timeFrom: "09:00", timeTo: "17:00",
	}

	tests := []struct {
		name    string
		mutate  func(*submitFields)
		wantErr string
	}{
		{"missing reason", func(f *submitFields) { f.reason = "" }, "--reason is required"},
		{"bad priority", func(f *submitFields) { f.priority = "Urgent" }, `--priority must be High, Medium, or Low (got "Urgent")`},
		{"missing date", func(f *submitFields) { f.date = "" }, "--date is required"},
		{"bad date", func(f *submitFields) { f.date = "21-04-2026" }, `--date must be in YYYY-MM-DD format (got "21-04-2026")`},
		{"missing timezone", func(f *submitFields) { f.timezone = "" }, "--timezone is required"},
		{"bad timezone", func(f *submitFields) { f.timezone = "Eastern" }, `--timezone must be a valid TZ identifier`},
		{"missing from", func(f *submitFields) { f.timeFrom = "" }, "--from is required"},
		{"bad from", func(f *submitFields) { f.timeFrom = "9am" }, `--from must be in HH:MM format (got "9am")`},
		{"missing to", func(f *submitFields) { f.timeTo = "" }, "--to is required"},
		{"bad to", func(f *submitFields) { f.timeTo = "5pm" }, `--to must be in HH:MM format (got "5pm")`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := valid
			tt.mutate(&f)
			err := validateSubmitFields(&f)
			if err == nil {
				t.Fatalf("expected an error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}

	if err := validateSubmitFields(&valid); err != nil {
		t.Errorf("the valid fixture must pass, got %v", err)
	}
}

// TestRequestNonInteractiveRequiresID kills REQ-13, REQ-14 and REQ-15: the
// early non-interactive guard on get/approve/reject. Only cancel had coverage.
//
// Each command is built with a nil service so that, if the guard is disabled,
// the flow reaches bootstrap and returns the bootstrap sentinel instead — a
// different error, which is exactly what makes the mutant die.
func TestRequestNonInteractiveRequiresID(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
	}{
		{name: "get", cmd: "get"},
		{name: "approve", cmd: "approve"},
		{name: "reject", cmd: "reject"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withInteractiveTTY(t, false)

			cmd := NewRequestCommandWithDeps(nil)
			root := newTestRootCommand()
			root.AddCommand(cmd)

			_, err := executeCommand(root, "request", tt.cmd)
			if err == nil {
				t.Fatalf("expected an error for %q without a request ID", tt.cmd)
			}
			if !errors.Is(err, ui.ErrNotInteractive) {
				t.Errorf("expected ErrNotInteractive (bootstrap not reached), got %v", err)
			}
			if !strings.Contains(err.Error(), "grant request list") {
				t.Errorf("error should hint at 'grant request list', got %v", err)
			}
		})
	}
}

// TestRejectGCPWorkspace_CSPTagOnly kills REQ-16. The existing fixture sets
// both a GCP CSP tag and a GCP workspace type, so the workspace-type switch
// masks the loss of the CSP arm. Here the workspace type is a non-GCP one, so
// only the CSP check can reject it.
func TestRejectGCPWorkspace_CSPTagOnly(t *testing.T) {
	err := rejectGCPWorkspace(&submitWorkspace{
		WorkspaceName: "Mislabelled",
		WorkspaceID:   "ws-1",
		WorkspaceType: models.WorkspaceTypeSubscription, // deliberately NOT a GCP type
		CSP:           models.CSPGCP,
	})
	if err == nil {
		t.Fatal("a GCP-tagged workspace must be rejected on the CSP tag alone")
	}
	if !errors.Is(err, errGCPRequestUnsupported) {
		t.Errorf("error = %v, want errGCPRequestUnsupported", err)
	}

	// The companion arm: a GCP workspace type with no CSP tag.
	if err := rejectGCPWorkspace(&submitWorkspace{
		WorkspaceType: models.WorkspaceTypeFolder,
	}); !errors.Is(err, errGCPRequestUnsupported) {
		t.Errorf("GCP workspace type must be rejected, got %v", err)
	}

	// And a plain Azure workspace must still pass.
	if err := rejectGCPWorkspace(&submitWorkspace{
		WorkspaceType: models.WorkspaceTypeSubscription,
		CSP:           models.CSPAzure,
	}); err != nil {
		t.Errorf("an Azure workspace must not be rejected, got %v", err)
	}
}

// TestRunRequestSubmit_NonInteractiveRequiresRoleID kills REQ-22: dropping the
// interactivity guard at cmd/request_submit.go:251 would drop a non-interactive
// caller into the interactive role picker.
func TestRunRequestSubmit_NonInteractiveRequiresRoleID(t *testing.T) {
	withInteractiveTTY(t, false)
	submitStubWorkspace(t, &submitWorkspace{
		WorkspaceName:  "Prod-EastUS",
		WorkspaceID:    "ws-1",
		WorkspaceType:  models.WorkspaceTypeSubscription,
		CSP:            models.CSPAzure,
		OrganizationID: "org-1",
	})

	svc := &mockAccessRequestService{
		submitResult: &wfmodels.AccessRequest{RequestID: "must-not-be-reached"},
	}

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "request", "submit",
		"--target", "Prod-EastUS",
		"--reason", "need access", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00",
		"--yes")
	if err == nil {
		t.Fatal("expected an error when --role-id is absent in non-interactive mode")
	}
	if !strings.Contains(err.Error(), "requires --role-id") {
		t.Errorf("error = %v, want it to demand --role-id", err)
	}
	// len(submitCalls) rather than lastSubmit(): the latter cannot tell
	// "never called" apart from "called with a nil request".
	if len(svc.submitCalls) != 0 {
		t.Errorf("nothing may be submitted, got %+v", svc.submitCalls)
	}
}
