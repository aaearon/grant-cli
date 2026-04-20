package workflows

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/workflows/models"
)

type mockHTTPClient struct {
	getFn  func(ctx context.Context, route string, params interface{}) (*http.Response, error)
	postFn func(ctx context.Context, route string, body interface{}) (*http.Response, error)
}

func (m *mockHTTPClient) Get(ctx context.Context, route string, params interface{}) (*http.Response, error) {
	return m.getFn(ctx, route, params)
}

func (m *mockHTTPClient) Post(ctx context.Context, route string, body interface{}) (*http.Response, error) {
	return m.postFn(ctx, route, body)
}

func jsonResponse(status int, body interface{}) *http.Response {
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(string(b))),
		Header:     make(http.Header),
	}
}

func TestGetRequestForms(t *testing.T) {
	expected := models.RequestFormResponse{
		RequestForms: []models.RequestFormEntry{
			{
				TargetCategory: "CLOUD_CONSOLE",
				RequestType:    "ON_DEMAND",
				RequestForm: models.RequestForm{
					Questions: []models.FormQuestion{
						{Key: "reason", Title: "Reason", ValueType: "TEXT"},
					},
				},
			},
		},
	}

	mock := &mockHTTPClient{
		getFn: func(_ context.Context, route string, params interface{}) (*http.Response, error) {
			if route != "/api/workflows/request-forms" {
				t.Errorf("unexpected route: %s", route)
			}
			p := params.(map[string]string)
			if p["targetCategory"] != "CLOUD_CONSOLE" {
				t.Errorf("expected targetCategory CLOUD_CONSOLE, got %s", p["targetCategory"])
			}
			if p["requestType"] != "ON_DEMAND" {
				t.Errorf("expected requestType ON_DEMAND, got %s", p["requestType"])
			}
			return jsonResponse(200, expected), nil
		},
	}

	svc := NewAccessRequestServiceWithClient(mock)
	result, err := svc.GetRequestForms(t.Context(), "CLOUD_CONSOLE", "ON_DEMAND")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.RequestForms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(result.RequestForms))
	}
	if result.RequestForms[0].RequestForm.Questions[0].Key != "reason" {
		t.Errorf("unexpected question key: %s", result.RequestForms[0].RequestForm.Questions[0].Key)
	}
}

func TestListRequests(t *testing.T) {
	callCount := 0
	mock := &mockHTTPClient{
		getFn: func(_ context.Context, _ string, params interface{}) (*http.Response, error) {
			callCount++
			p := params.(map[string]string)

			if callCount == 1 {
				if p["offset"] != "0" {
					t.Errorf("first call offset: got %s, want 0", p["offset"])
				}
				return jsonResponse(200, models.ListRequestsResponse{
					Items: []models.AccessRequest{
						{RequestID: "id-1", CreatedBy: "user@test"},
						{RequestID: "id-2", CreatedBy: "user@test"},
					},
					Count:      2,
					TotalCount: 3,
				}), nil
			}

			if p["offset"] != "2" {
				t.Errorf("second call offset: got %s, want 2", p["offset"])
			}
			return jsonResponse(200, models.ListRequestsResponse{
				Items:      []models.AccessRequest{{RequestID: "id-3", CreatedBy: "user@test"}},
				Count:      1,
				TotalCount: 3,
			}), nil
		},
	}

	svc := NewAccessRequestServiceWithClient(mock)
	items, total, err := svc.ListRequests(t.Context(), ListRequestsParams{Limit: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 3 {
		t.Errorf("expected 3 items, got %d", len(items))
	}
	if total != 3 {
		t.Errorf("expected totalCount 3, got %d", total)
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls, got %d", callCount)
	}
}

func TestListRequests_WithFilters(t *testing.T) {
	mock := &mockHTTPClient{
		getFn: func(_ context.Context, _ string, params interface{}) (*http.Response, error) {
			p := params.(map[string]string)
			if p["filter"] != "(requestState eq PENDING)" {
				t.Errorf("filter: got %q", p["filter"])
			}
			if p["freeText"] != "azure" {
				t.Errorf("freeText: got %q", p["freeText"])
			}
			if p["requestRole"] != "CREATOR" {
				t.Errorf("requestRole: got %q", p["requestRole"])
			}
			if p["sort"] != "createdAt desc" {
				t.Errorf("sort: got %q", p["sort"])
			}
			return jsonResponse(200, models.ListRequestsResponse{
				Items:      []models.AccessRequest{{RequestID: "id-1"}},
				Count:      1,
				TotalCount: 1,
			}), nil
		},
	}

	svc := NewAccessRequestServiceWithClient(mock)
	items, _, err := svc.ListRequests(t.Context(), ListRequestsParams{
		Filter:      "(requestState eq PENDING)",
		FreeText:    "azure",
		RequestRole: "CREATOR",
		Sort:        "createdAt desc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("expected 1 item, got %d", len(items))
	}
}

func TestGetRequest(t *testing.T) {
	expected := models.AccessRequest{
		RequestID:    "8a45155d-0273-4bc8-8d45-9fe3f4d4de6d",
		RequestState: models.RequestStateFinished,
		RequestResult: models.RequestResultApproved,
		CreatedBy:    "user@test",
		CreatedAt:    "2025-08-12T09:41:00",
		UpdatedBy:    "SYSTEM",
		UpdatedAt:    "2025-08-12T09:42:31",
	}

	mock := &mockHTTPClient{
		getFn: func(_ context.Context, route string, _ interface{}) (*http.Response, error) {
			if route != "/api/workflows/requests/8a45155d-0273-4bc8-8d45-9fe3f4d4de6d" {
				t.Errorf("unexpected route: %s", route)
			}
			return jsonResponse(200, expected), nil
		},
	}

	svc := NewAccessRequestServiceWithClient(mock)
	result, err := svc.GetRequest(t.Context(), "8a45155d-0273-4bc8-8d45-9fe3f4d4de6d")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequestID != expected.RequestID {
		t.Errorf("requestId: got %q, want %q", result.RequestID, expected.RequestID)
	}
	if result.RequestState != models.RequestStateFinished {
		t.Errorf("state: got %q", result.RequestState)
	}
}

func TestSubmitRequest(t *testing.T) {
	mock := &mockHTTPClient{
		postFn: func(_ context.Context, route string, body interface{}) (*http.Response, error) {
			if route != "/api/workflows/requests" {
				t.Errorf("unexpected route: %s", route)
			}
			req := body.(*models.SubmitAccessRequest)
			if req.TargetCategory != "CLOUD_CONSOLE" {
				t.Errorf("targetCategory: got %q", req.TargetCategory)
			}
			return jsonResponse(200, models.AccessRequest{
				RequestID:    "new-id",
				RequestState: models.RequestStateStarting,
				RequestResult: models.RequestResultUnknown,
				CreatedBy:    "user@test",
				CreatedAt:    "2025-08-12T09:41:00",
				UpdatedBy:    "SYSTEM",
				UpdatedAt:    "2025-08-12T09:41:00",
			}), nil
		},
	}

	svc := NewAccessRequestServiceWithClient(mock)
	result, err := svc.SubmitRequest(t.Context(), &models.SubmitAccessRequest{
		TargetCategory: "CLOUD_CONSOLE",
		RequestDetails: map[string]interface{}{"reason": "need access"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequestID != "new-id" {
		t.Errorf("requestId: got %q", result.RequestID)
	}
	if result.RequestState != models.RequestStateStarting {
		t.Errorf("state: got %q", result.RequestState)
	}
}

func TestSubmitRequest_NilRequest(t *testing.T) {
	svc := NewAccessRequestServiceWithClient(&mockHTTPClient{})
	_, err := svc.SubmitRequest(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestCancelRequest(t *testing.T) {
	mock := &mockHTTPClient{
		postFn: func(_ context.Context, route string, body interface{}) (*http.Response, error) {
			if route != "/api/workflows/requests/req-id/cancel" {
				t.Errorf("unexpected route: %s", route)
			}
			cancelReq := body.(*models.CancelAccessRequest)
			if cancelReq.CancelReason == nil || *cancelReq.CancelReason != "no longer needed" {
				t.Errorf("unexpected cancel reason")
			}
			return jsonResponse(200, models.AccessRequest{
				RequestID:     "req-id",
				RequestState:  models.RequestStateRunning,
				RequestResult: models.RequestResultCanceled,
				CreatedBy:     "user@test",
				CreatedAt:     "t",
				UpdatedBy:     "SYSTEM",
				UpdatedAt:     "t",
			}), nil
		},
	}

	svc := NewAccessRequestServiceWithClient(mock)
	reason := "no longer needed"
	result, err := svc.CancelRequest(t.Context(), "req-id", &reason)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequestResult != models.RequestResultCanceled {
		t.Errorf("result: got %q", result.RequestResult)
	}
}

func TestFinalizeRequest(t *testing.T) {
	tests := []struct {
		name       string
		result     string
		wantResult models.RequestResult
	}{
		{"approve", "APPROVED", models.RequestResultApproved},
		{"reject", "REJECTED", models.RequestResultRejected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHTTPClient{
				postFn: func(_ context.Context, route string, body interface{}) (*http.Response, error) {
					if !strings.HasSuffix(route, "/finalize") {
						t.Errorf("route should end with /finalize: %s", route)
					}
					fin := body.(*models.FinalizeAccessRequest)
					if fin.Result != tt.result {
						t.Errorf("result: got %q, want %q", fin.Result, tt.result)
					}
					return jsonResponse(200, models.AccessRequest{
						RequestID:     "req-id",
						RequestState:  models.RequestStateRunning,
						RequestResult: models.RequestResult(tt.result),
						CreatedBy:     "user@test",
						CreatedAt:     "t",
						UpdatedBy:     "SYSTEM",
						UpdatedAt:     "t",
					}), nil
				},
			}

			svc := NewAccessRequestServiceWithClient(mock)
			reason := "looks good"
			result, err := svc.FinalizeRequest(t.Context(), "req-id", tt.result, &reason)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.RequestResult != tt.wantResult {
				t.Errorf("result: got %q, want %q", result.RequestResult, tt.wantResult)
			}
		})
	}
}

func TestCheckResponse_Error(t *testing.T) {
	resp := &http.Response{
		StatusCode: 401,
		Body:       io.NopCloser(strings.NewReader(`{"code":"UNAUTHORIZED","message":"Unauthorized"}`)),
	}
	err := checkResponse(resp, "test operation")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should contain status code: %v", err)
	}
	if !strings.Contains(err.Error(), "UNAUTHORIZED") {
		t.Errorf("error should contain response body: %v", err)
	}
}
