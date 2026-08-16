package workflows

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/workflows/models"
)

// errorResponse builds a non-200 whose body still decodes cleanly into every
// response model. That is deliberate: if the checkResponse guard is removed,
// the operation succeeds and returns an empty value rather than failing, which
// is exactly the escape this table exists to catch.
func errorResponse(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(`{"message":"internal server error"}`)),
		Header:     make(http.Header),
	}
}

// TestWorkflows_Non200 drives a 500 through all six checkResponse call sites.
// TestCheckResponse_Error only calls the helper directly, which proves it
// formats an error but not that any operation invokes it — so deleting any of
// the six guards survived. The user-visible consequence at the submit site: a
// 500 decodes as an empty AccessRequest and `grant request submit` prints a
// blank request and exits 0.
func TestWorkflows_Non200(t *testing.T) {
	tests := []struct {
		name          string
		call          func(svc *AccessRequestService) error
		wantOperation string
	}{
		{
			name: "request forms",
			call: func(svc *AccessRequestService) error {
				_, err := svc.GetRequestForms(t.Context(), "CLOUD_CONSOLE", "ON_DEMAND")
				return err
			},
			wantOperation: "request forms",
		},
		{
			name: "list requests",
			call: func(svc *AccessRequestService) error {
				_, _, err := svc.ListRequests(t.Context(), ListRequestsParams{})
				return err
			},
			wantOperation: "list requests",
		},
		{
			name: "get request",
			call: func(svc *AccessRequestService) error {
				_, err := svc.GetRequest(t.Context(), "req-500")
				return err
			},
			wantOperation: "get request",
		},
		{
			name: "submit request",
			call: func(svc *AccessRequestService) error {
				_, err := svc.SubmitRequest(t.Context(), &models.SubmitAccessRequest{TargetCategory: "CLOUD_CONSOLE"})
				return err
			},
			wantOperation: "submit request",
		},
		{
			name: "cancel request",
			call: func(svc *AccessRequestService) error {
				_, err := svc.CancelRequest(t.Context(), "req-500", nil)
				return err
			},
			wantOperation: "cancel request",
		},
		{
			name: "finalize request",
			call: func(svc *AccessRequestService) error {
				_, err := svc.FinalizeRequest(t.Context(), "req-500", "APPROVED", nil)
				return err
			},
			wantOperation: "finalize request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHTTPClient{
				getFn: func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					return errorResponse(http.StatusInternalServerError), nil
				},
				postFn: func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					return errorResponse(http.StatusInternalServerError), nil
				},
			}
			svc := NewAccessRequestServiceWithClient(mock)

			err := tt.call(svc)
			if err == nil {
				t.Fatalf("%s returned nil error on HTTP 500", tt.wantOperation)
			}
			if !strings.Contains(err.Error(), tt.wantOperation) {
				t.Errorf("error = %v, want it to name the operation %q", err, tt.wantOperation)
			}
			if !strings.Contains(err.Error(), "500") {
				t.Errorf("error = %v, want it to carry the HTTP status", err)
			}
		})
	}
}

// TestFinalizeRequest_ExactRouteAndReason supersedes the HasSuffix("/finalize")
// check in service_test.go, which let the request ID drop out of the route and
// let the approver's reason be dropped from the body. That looser check is still
// present there; the redundancy is harmless. The cancel twin already asserts both.
func TestFinalizeRequest_ExactRouteAndReason(t *testing.T) {
	tests := []struct {
		name   string
		result string
		reason *string
	}{
		{name: "approve with reason", result: "APPROVED", reason: strPtr("approved because it is justified")},
		{name: "reject with reason", result: "REJECTED", reason: strPtr("rejected because scope is too broad")},
		{name: "no reason", result: "APPROVED", reason: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHTTPClient{
				postResponse: jsonResponse(200, models.AccessRequest{RequestID: "req-finalize-1"}),
			}
			svc := NewAccessRequestServiceWithClient(mock)

			if _, err := svc.FinalizeRequest(t.Context(), "req-finalize-1", tt.result, tt.reason); err != nil {
				t.Fatalf("FinalizeRequest: %v", err)
			}

			const wantRoute = "/api/workflows/requests/req-finalize-1/finalize"
			if mock.gotRoute != wantRoute {
				t.Errorf("route = %q, want %q", mock.gotRoute, wantRoute)
			}
			body, ok := mock.gotBody.(*models.FinalizeAccessRequest)
			if !ok {
				t.Fatalf("body = %#v (%T), want *models.FinalizeAccessRequest", mock.gotBody, mock.gotBody)
			}
			if body.Result != tt.result {
				t.Errorf("result = %q, want %q", body.Result, tt.result)
			}
			switch {
			case tt.reason == nil && body.FinalizationReason != nil:
				t.Errorf("finalizationReason = %q, want nil", *body.FinalizationReason)
			case tt.reason != nil && body.FinalizationReason == nil:
				t.Errorf("finalizationReason = nil, want %q", *tt.reason)
			case tt.reason != nil && *body.FinalizationReason != *tt.reason:
				t.Errorf("finalizationReason = %q, want %q", *body.FinalizationReason, *tt.reason)
			}
		})
	}
}

func strPtr(s string) *string { return &s }

// TestListRequests_SendsLimit pins the route and the limit query parameter.
// Offset pagination is already well covered; limit was never asserted, so
// deleting it, or changing defaultPageSize, went unnoticed. The route was the
// only unpinned route in either service — the mock already recorded it and no
// test looked, so `grant request list` could have been pointed anywhere.
func TestListRequests_SendsLimit(t *testing.T) {
	tests := []struct {
		name      string
		params    ListRequestsParams
		wantLimit string
	}{
		{name: "no limit uses defaultPageSize", params: ListRequestsParams{}, wantLimit: "50"},
		{name: "zero limit uses defaultPageSize", params: ListRequestsParams{Limit: 0}, wantLimit: "50"},
		{name: "negative limit uses defaultPageSize", params: ListRequestsParams{Limit: -3}, wantLimit: "50"},
		{name: "caller limit is sent verbatim", params: ListRequestsParams{Limit: 7}, wantLimit: "7"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHTTPClient{
				getResponses: []*http.Response{jsonResponse(200, models.ListRequestsResponse{
					Items: []models.AccessRequest{{RequestID: "id-1"}}, Count: 1, TotalCount: 1,
				})},
			}
			svc := NewAccessRequestServiceWithClient(mock)

			if _, _, err := svc.ListRequests(t.Context(), tt.params); err != nil {
				t.Fatalf("ListRequests: %v", err)
			}

			if mock.gotRoute != "/api/workflows/requests" {
				t.Errorf("route = %q, want %q", mock.gotRoute, "/api/workflows/requests")
			}
			qp, ok := mock.gotParams.(map[string]string)
			if !ok {
				t.Fatalf("params = %#v (%T), want map[string]string", mock.gotParams, mock.gotParams)
			}
			if got := qp["limit"]; got != tt.wantLimit {
				t.Errorf("limit = %q, want %q", got, tt.wantLimit)
			}
		})
	}
}

// TestListRequests_PropagatesContextCancellation covers the ctx argument of the
// pagination loop's GET; every mock ignores ctx, so swapping it for
// context.Background() otherwise survives.
func TestListRequests_PropagatesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	mock := &mockHTTPClient{
		getFn: func(ctx context.Context, _ string, _ interface{}) (*http.Response, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return jsonResponse(200, models.ListRequestsResponse{}), nil
		},
	}
	svc := NewAccessRequestServiceWithClient(mock)

	_, _, err := svc.ListRequests(ctx, ListRequestsParams{})
	if err == nil {
		t.Fatal("expected the canceled context to reach the HTTP client, got nil error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

// TestGetRequest_PropagatesDecodeError guards the decode error return in
// GetRequest: swallowing it would return a blank request as a success.
func TestGetRequest_PropagatesDecodeError(t *testing.T) {
	mock := &mockHTTPClient{
		getFn: func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"requestId": 12345}`)),
				Header:     make(http.Header),
			}, nil
		},
	}
	svc := NewAccessRequestServiceWithClient(mock)

	result, err := svc.GetRequest(t.Context(), "req-decode-1")
	if err == nil {
		t.Fatalf("expected a decode error, got nil (result = %#v)", result)
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("error = %v, want it to name the decode failure", err)
	}
}

// TestGetRequestForms_SendsExactParams pins the query params for the forms
// endpoint alongside its route.
func TestGetRequestForms_SendsExactParams(t *testing.T) {
	mock := &mockHTTPClient{
		getResponses: []*http.Response{jsonResponse(200, models.RequestFormResponse{})},
	}
	svc := NewAccessRequestServiceWithClient(mock)

	if _, err := svc.GetRequestForms(t.Context(), "CLOUD_CONSOLE", "ON_DEMAND"); err != nil {
		t.Fatalf("GetRequestForms: %v", err)
	}
	if mock.gotRoute != "/api/workflows/request-forms" {
		t.Errorf("route = %q, want %q", mock.gotRoute, "/api/workflows/request-forms")
	}
	want := map[string]string{"targetCategory": "CLOUD_CONSOLE", "requestType": "ON_DEMAND"}
	if !reflect.DeepEqual(mock.gotParams, want) {
		t.Errorf("params = %#v, want %#v", mock.gotParams, want)
	}
}

// TestSubmitRequest_SendsExactRouteAndBody pins the submit wire contract.
// TestSubmitRequest asserts only TargetCategory, so RequestDetails — reason,
// role, target, dates, priority, i.e. the entire substance of
// `grant request submit` — could be dropped at the service boundary and every
// test still passed. Mirrors TestElevate_SendsExactRouteAndBody in internal/sca.
func TestSubmitRequest_SendsExactRouteAndBody(t *testing.T) {
	mock := &mockHTTPClient{
		postResponse: jsonResponse(200, models.AccessRequest{RequestID: "req-submit-1"}),
	}
	svc := NewAccessRequestServiceWithClient(mock)

	// Distinguishable values: no two keys share a value, so a swap cannot be
	// masked. Do not "tidy" these to "test".
	req := &models.SubmitAccessRequest{
		TargetCategory: "CLOUD_CONSOLE",
		RequestDetails: map[string]interface{}{
			"reason":      "reason-submit-2",
			"roleId":      "role-id-submit-3",
			"roleName":    "Role Name Submit Four",
			"targetId":    "target-submit-5",
			"priority":    "priority-submit-6",
			"startDate":   "2025-08-12T09:41:00",
			"endDate":     "2025-08-12T17:41:00",
			"timezone":    "timezone-submit-7",
			"provider":    "provider-submit-8",
			"workspaceId": "ws-submit-9",
		},
	}
	if _, err := svc.SubmitRequest(t.Context(), req); err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}

	if mock.gotRoute != "/api/workflows/requests" {
		t.Errorf("route = %q, want %q", mock.gotRoute, "/api/workflows/requests")
	}
	got, ok := mock.gotBody.(*models.SubmitAccessRequest)
	if !ok {
		t.Fatalf("body = %#v (%T), want *models.SubmitAccessRequest", mock.gotBody, mock.gotBody)
	}
	if !reflect.DeepEqual(got, req) {
		t.Errorf("body = %#v, want %#v", got, req)
	}
}
