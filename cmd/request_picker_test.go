package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/ui"
	"github.com/aaearon/grant-cli/internal/workflows"
	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
)

// capturingMockAccessRequestService embeds mockAccessRequestService and captures list params.
type capturingMockAccessRequestService struct {
	mockAccessRequestService
	lastListParams workflows.ListRequestsParams
}

func (m *capturingMockAccessRequestService) ListRequests(_ context.Context, params workflows.ListRequestsParams) ([]wfmodels.AccessRequest, int, error) {
	m.lastListParams = params
	return m.listItems, m.listTotalCount, m.listErr
}

func withInteractiveTTY(t *testing.T, interactive bool) {
	t.Helper()
	orig := ui.IsTerminalFunc
	t.Cleanup(func() { ui.IsTerminalFunc = orig })
	ui.IsTerminalFunc = func(_ uintptr) bool { return interactive }
}

func TestResolveRequestIDInteractive_NonInteractive(t *testing.T) {
	withInteractiveTTY(t, false)

	svc := &capturingMockAccessRequestService{}
	_, err := resolveRequestIDInteractive(t.Context(), svc, pickerScope{emptyMsg: "access requests"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ui.ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive, got %v", err)
	}
	if !strings.Contains(err.Error(), "grant request list") {
		t.Errorf("expected hint to 'grant request list', got %v", err)
	}
}

func TestResolveRequestIDInteractive_JSONMode(t *testing.T) {
	withInteractiveTTY(t, false)
	orig := outputFormat
	outputFormat = "json"
	t.Cleanup(func() { outputFormat = orig })

	svc := &capturingMockAccessRequestService{}
	_, err := resolveRequestIDInteractive(t.Context(), svc, pickerScope{emptyMsg: "access requests"})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ui.ErrNotInteractive) {
		t.Errorf("JSON mode error should not wrap ErrNotInteractive")
	}
	if !strings.Contains(err.Error(), "--output json") {
		t.Errorf("expected --output json hint, got %v", err)
	}
	if strings.Contains(err.Error(), "requires a terminal") {
		t.Errorf("JSON mode error should not mention terminal: %v", err)
	}
}

func TestResolveRequestIDInteractive_EmptyList(t *testing.T) {
	withInteractiveTTY(t, true)

	svc := &capturingMockAccessRequestService{}
	_, err := resolveRequestIDInteractive(t.Context(), svc, pickerScope{
		filter:      "(requestState eq PENDING)",
		requestRole: "APPROVER",
		emptyMsg:    "pending requests assigned to you",
	})
	if err == nil {
		t.Fatal("expected error on empty list")
	}
	if !strings.Contains(err.Error(), "pending requests assigned to you") {
		t.Errorf("expected emptyMsg in error, got %v", err)
	}
	if svc.lastListParams.Filter != "(requestState eq PENDING)" {
		t.Errorf("filter: got %q", svc.lastListParams.Filter)
	}
	if svc.lastListParams.RequestRole != "APPROVER" {
		t.Errorf("requestRole: got %q", svc.lastListParams.RequestRole)
	}
	if svc.lastListParams.Sort != "createdAt desc" {
		t.Errorf("sort: got %q", svc.lastListParams.Sort)
	}
}

func TestResolveRequestIDInteractive_ListError(t *testing.T) {
	withInteractiveTTY(t, true)

	svc := &capturingMockAccessRequestService{
		mockAccessRequestService: mockAccessRequestService{listErr: errors.New("boom")},
	}
	_, err := resolveRequestIDInteractive(t.Context(), svc, pickerScope{emptyMsg: "x"})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected list error, got %v", err)
	}
}

// stubResolver replaces resolveRequestIDFn for testing the command integration.
func stubResolver(t *testing.T, id string, err error) *struct {
	scope  pickerScope
	called bool
} {
	t.Helper()
	capture := &struct {
		scope  pickerScope
		called bool
	}{}
	orig := resolveRequestIDFn
	t.Cleanup(func() { resolveRequestIDFn = orig })
	resolveRequestIDFn = func(_ context.Context, _ accessRequestService, scope pickerScope) (string, error) {
		capture.called = true
		capture.scope = scope
		return id, err
	}
	return capture
}

func TestRequestCancel_PickerFallback(t *testing.T) {
	withInteractiveTTY(t, true)
	svc := &mockAccessRequestService{
		cancelResult: &wfmodels.AccessRequest{RequestID: "picked-id", RequestResult: wfmodels.RequestResultCanceled},
	}
	capture := stubResolver(t, "picked-id", nil)

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "cancel")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}
	if !capture.called {
		t.Fatal("resolver was not called")
	}
	if capture.scope.requestRole != "CREATOR" {
		t.Errorf("expected CREATOR scope, got %q", capture.scope.requestRole)
	}
	if !strings.Contains(capture.scope.filter, "STARTING") {
		t.Errorf("expected filter with STARTING, got %q", capture.scope.filter)
	}
	if !strings.Contains(output, "picked-id") {
		t.Errorf("expected picked-id in output: %s", output)
	}
}

func TestRequestApprove_PickerFallback(t *testing.T) {
	withInteractiveTTY(t, true)
	svc := &mockAccessRequestService{
		finalizeResult: &wfmodels.AccessRequest{RequestID: "picked-id", RequestResult: wfmodels.RequestResultApproved},
	}
	capture := stubResolver(t, "picked-id", nil)

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "approve")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}
	if !capture.called {
		t.Fatal("resolver was not called")
	}
	if capture.scope.requestRole != "APPROVER" {
		t.Errorf("expected APPROVER scope, got %q", capture.scope.requestRole)
	}
	if capture.scope.filter != "(requestState eq PENDING)" {
		t.Errorf("unexpected filter: %q", capture.scope.filter)
	}
	if !strings.Contains(output, "approved") {
		t.Errorf("expected approved in output: %s", output)
	}
}

func TestRequestReject_PickerFallback(t *testing.T) {
	withInteractiveTTY(t, true)
	svc := &mockAccessRequestService{
		finalizeResult: &wfmodels.AccessRequest{RequestID: "picked-id", RequestResult: wfmodels.RequestResultRejected},
	}
	capture := stubResolver(t, "picked-id", nil)

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "reject")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}
	if capture.scope.requestRole != "APPROVER" {
		t.Errorf("expected APPROVER scope, got %q", capture.scope.requestRole)
	}
	if !strings.Contains(output, "rejected") {
		t.Errorf("expected rejected in output: %s", output)
	}
}

func TestRequestGet_PickerFallback(t *testing.T) {
	withInteractiveTTY(t, true)
	svc := &mockAccessRequestService{
		getResult: &wfmodels.AccessRequest{
			RequestID:     "picked-id",
			RequestState:  wfmodels.RequestStateFinished,
			RequestResult: wfmodels.RequestResultApproved,
			CreatedBy:     "user@test",
			CreatedAt:     "t",
			UpdatedBy:     "SYSTEM",
			UpdatedAt:     "t",
		},
	}
	capture := stubResolver(t, "picked-id", nil)

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "request", "get")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}
	if capture.scope.filter != "" {
		t.Errorf("get scope should have no filter, got %q", capture.scope.filter)
	}
	if capture.scope.requestRole != "" {
		t.Errorf("get scope should have no requestRole, got %q", capture.scope.requestRole)
	}
	if !strings.Contains(output, "picked-id") {
		t.Errorf("expected picked-id in output: %s", output)
	}
}

func TestRequestCancel_PickerError(t *testing.T) {
	withInteractiveTTY(t, true)
	svc := &mockAccessRequestService{}
	stubResolver(t, "", errors.New("no open requests"))

	cmd := NewRequestCommandWithDeps(svc)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "request", "cancel")
	if err == nil {
		t.Fatal("expected error from picker")
	}
	if !strings.Contains(err.Error(), "no open requests") {
		t.Errorf("expected picker error, got %v", err)
	}
}

func TestEarlyNonInteractiveCheck_NoID(t *testing.T) {
	withInteractiveTTY(t, false)
	err := earlyNonInteractiveCheck("")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ui.ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive, got %v", err)
	}
	if !strings.Contains(err.Error(), "grant request list") {
		t.Errorf("expected hint to 'grant request list', got %v", err)
	}
}

func TestEarlyNonInteractiveCheck_WithID(t *testing.T) {
	withInteractiveTTY(t, false)
	if err := earlyNonInteractiveCheck("some-id"); err != nil {
		t.Errorf("expected nil when ID provided, got %v", err)
	}
}

func TestEarlyNonInteractiveCheck_Interactive(t *testing.T) {
	withInteractiveTTY(t, true)
	if err := earlyNonInteractiveCheck(""); err != nil {
		t.Errorf("expected nil in interactive mode, got %v", err)
	}
}

// TestRequestCancel_NonInteractiveNoArgs verifies bootstrap is not reached when
// stdin is non-interactive and no requestID is provided.
func TestRequestCancel_NonInteractiveNoArgs(t *testing.T) {
	withInteractiveTTY(t, false)

	// Pass nil svc so bootstrap would be attempted if early check is bypassed.
	cmd := newRequestCancelCommand(nil)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "cancel")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ui.ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive (bootstrap not reached), got %v", err)
	}
}
