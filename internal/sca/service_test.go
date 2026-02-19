package sca

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

// mockHTTPClient is a simple mock that returns pre-configured responses
type mockHTTPClient struct {
	getResponse  *http.Response
	getError     error
	postResponse *http.Response
	postError    error
}

func (m *mockHTTPClient) Get(ctx context.Context, route string, params interface{}) (*http.Response, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	return m.getResponse, nil
}

func (m *mockHTTPClient) Post(ctx context.Context, route string, body interface{}) (*http.Response, error) {
	if m.postError != nil {
		return nil, m.postError
	}
	return m.postResponse, nil
}

func TestListEligibility_Success(t *testing.T) {
	resp := models.EligibilityResponse{
		Response: []models.EligibleTarget{
			{
				OrganizationID: "org1",
				WorkspaceID:    "sub1",
				WorkspaceName:  "Subscription 1",
				WorkspaceType:  models.WorkspaceTypeSubscription,
				RoleInfo: models.RoleInfo{
					ID:   "role1",
					Name: "Contributor",
				},
			},
		},
		NextToken: nil,
		Total:     1,
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		getResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.ListEligibility(context.Background(), models.CSPAzure)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Response) != 1 {
		t.Errorf("expected 1 target, got %d", len(result.Response))
	}
	if result.Response[0].WorkspaceID != "sub1" {
		t.Errorf("expected workspace sub1, got %s", result.Response[0].WorkspaceID)
	}
}

func TestListEligibility_Empty(t *testing.T) {
	resp := models.EligibilityResponse{
		Response:  []models.EligibleTarget{},
		NextToken: nil,
		Total:     0,
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		getResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.ListEligibility(context.Background(), models.CSPAzure)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Response) != 0 {
		t.Errorf("expected 0 targets, got %d", len(result.Response))
	}
	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
}

func TestListEligibility_WithPagination(t *testing.T) {
	nextToken := "token123"
	resp := models.EligibilityResponse{
		Response: []models.EligibleTarget{
			{
				OrganizationID: "org1",
				WorkspaceID:    "sub1",
				WorkspaceName:  "Subscription 1",
				WorkspaceType:  models.WorkspaceTypeSubscription,
				RoleInfo: models.RoleInfo{
					ID:   "role1",
					Name: "Owner",
				},
			},
		},
		NextToken: &nextToken,
		Total:     10,
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		getResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.ListEligibility(context.Background(), models.CSPAzure)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.NextToken == nil {
		t.Fatal("expected non-nil NextToken")
	}
	if *result.NextToken != nextToken {
		t.Errorf("expected NextToken %s, got %s", nextToken, *result.NextToken)
	}
	if result.Total != 10 {
		t.Errorf("expected total 10, got %d", result.Total)
	}
}

func TestListEligibility_HTTPError(t *testing.T) {
	mock := &mockHTTPClient{
		getResponse: &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader(`{"error": "unauthorized"}`)),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	_, err := svc.ListEligibility(context.Background(), models.CSPAzure)

	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected error to mention status code 401, got: %v", err)
	}
}

func TestElevate_Success(t *testing.T) {
	req := &models.ElevateRequest{
		CSP:            models.CSPAzure,
		OrganizationID: "org1",
		Targets: []models.ElevateTarget{
			{
				WorkspaceID: "sub1",
				RoleID:      "role1",
			},
		},
	}

	resp := models.ElevateResponse{
		Response: models.ElevateAccessResult{
			CSP:            models.CSPAzure,
			OrganizationID: "org1",
			Results: []models.ElevateTargetResult{
				{
					WorkspaceID:       "sub1",
					RoleID:            "role1",
					SessionID:         "session1",
					AccessCredentials: nil,
					ErrorInfo:         nil,
				},
			},
		},
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		postResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.Elevate(context.Background(), req)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Response.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Response.Results))
	}
	if result.Response.Results[0].SessionID != "session1" {
		t.Errorf("expected session ID session1, got %s", result.Response.Results[0].SessionID)
	}
}

func TestElevate_PartialSuccess(t *testing.T) {
	req := &models.ElevateRequest{
		CSP:            models.CSPAzure,
		OrganizationID: "org1",
		Targets: []models.ElevateTarget{
			{WorkspaceID: "sub1", RoleID: "role1"},
			{WorkspaceID: "sub2", RoleID: "role2"},
		},
	}

	resp := models.ElevateResponse{
		Response: models.ElevateAccessResult{
			CSP:            models.CSPAzure,
			OrganizationID: "org1",
			Results: []models.ElevateTargetResult{
				{
					WorkspaceID:       "sub1",
					RoleID:            "role1",
					SessionID:         "session1",
					AccessCredentials: nil,
					ErrorInfo:         nil,
				},
				{
					WorkspaceID:       "sub2",
					RoleID:            "role2",
					SessionID:         "",
					AccessCredentials: nil,
					ErrorInfo: &models.ErrorInfo{
						Code:        "ERR_INELIGIBLE",
						Message:     "Not eligible",
						Description: "User not eligible for this role",
					},
				},
			},
		},
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		postResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.Elevate(context.Background(), req)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Response.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(result.Response.Results))
	}
	if result.Response.Results[0].ErrorInfo != nil {
		t.Errorf("expected first result to succeed, got error: %v", result.Response.Results[0].ErrorInfo)
	}
	if result.Response.Results[1].ErrorInfo == nil {
		t.Error("expected second result to fail")
	}
}

func TestElevate_NilRequest(t *testing.T) {
	mock := &mockHTTPClient{}
	svc := &SCAAccessService{httpClient: mock}

	_, err := svc.Elevate(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected error to mention nil, got: %v", err)
	}
}

func TestElevate_EmptyTargets(t *testing.T) {
	req := &models.ElevateRequest{
		CSP:            models.CSPAzure,
		OrganizationID: "org1",
		Targets:        []models.ElevateTarget{},
	}

	mock := &mockHTTPClient{}
	svc := &SCAAccessService{httpClient: mock}

	_, err := svc.Elevate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty targets")
	}
	if !strings.Contains(err.Error(), "empty") && !strings.Contains(err.Error(), "target") {
		t.Errorf("expected error about empty targets, got: %v", err)
	}
}

func TestRevokeSessions_Success(t *testing.T) {
	resp := models.RevokeResponse{
		Response: []models.RevocationResult{
			{
				SessionID:        "session-1",
				RevocationStatus: models.RevocationSuccessful,
			},
		},
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		postResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.RevokeSessions(context.Background(), &models.RevokeRequest{
		SessionIDs: []string{"session-1"},
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Response) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Response))
	}
	if result.Response[0].SessionID != "session-1" {
		t.Errorf("expected session ID session-1, got %s", result.Response[0].SessionID)
	}
	if result.Response[0].RevocationStatus != models.RevocationSuccessful {
		t.Errorf("expected status %s, got %s", models.RevocationSuccessful, result.Response[0].RevocationStatus)
	}
}

func TestRevokeSessions_Multiple(t *testing.T) {
	resp := models.RevokeResponse{
		Response: []models.RevocationResult{
			{SessionID: "session-1", RevocationStatus: models.RevocationSuccessful},
			{SessionID: "session-2", RevocationStatus: models.RevocationInProgress},
		},
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		postResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.RevokeSessions(context.Background(), &models.RevokeRequest{
		SessionIDs: []string{"session-1", "session-2"},
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Response) != 2 {
		t.Errorf("expected 2 results, got %d", len(result.Response))
	}
}

func TestRevokeSessions_NilRequest(t *testing.T) {
	mock := &mockHTTPClient{}
	svc := &SCAAccessService{httpClient: mock}

	_, err := svc.RevokeSessions(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected error to mention nil, got: %v", err)
	}
}

func TestRevokeSessions_EmptySessionIDs(t *testing.T) {
	mock := &mockHTTPClient{}
	svc := &SCAAccessService{httpClient: mock}

	_, err := svc.RevokeSessions(context.Background(), &models.RevokeRequest{
		SessionIDs: []string{},
	})
	if err == nil {
		t.Fatal("expected error for empty session IDs")
	}
	if !strings.Contains(err.Error(), "session ID") {
		t.Errorf("expected error about session IDs, got: %v", err)
	}
}

func TestRevokeSessions_HTTPError(t *testing.T) {
	mock := &mockHTTPClient{
		postResponse: &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(strings.NewReader(`{"error": "forbidden"}`)),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	_, err := svc.RevokeSessions(context.Background(), &models.RevokeRequest{
		SessionIDs: []string{"session-1"},
	})

	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected error to mention status code 403, got: %v", err)
	}
}

func TestListSessions_Success(t *testing.T) {
	resp := models.SessionsResponse{
		Response: []models.SessionInfo{
			{
				SessionID:       "session1",
				UserID:          "user1",
				CSP:             models.CSPAzure,
				WorkspaceID:     "sub1",
				RoleID:          "role1",
				SessionDuration: 3600,
			},
		},
		NextToken: nil,
		Total:     1,
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		getResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.ListSessions(context.Background(), nil)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Response) != 1 {
		t.Errorf("expected 1 session, got %d", len(result.Response))
	}
	if result.Response[0].SessionID != "session1" {
		t.Errorf("expected session ID session1, got %s", result.Response[0].SessionID)
	}
}

func TestListSessions_Empty(t *testing.T) {
	resp := models.SessionsResponse{
		Response:  []models.SessionInfo{},
		NextToken: nil,
		Total:     0,
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		getResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.ListSessions(context.Background(), nil)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Response) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(result.Response))
	}
	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
}

func TestListSessions_WithCSPFilter(t *testing.T) {
	csp := models.CSPAzure
	resp := models.SessionsResponse{
		Response: []models.SessionInfo{
			{
				SessionID:       "session1",
				UserID:          "user1",
				CSP:             models.CSPAzure,
				WorkspaceID:     "sub1",
				RoleID:          "role1",
				SessionDuration: 3600,
			},
		},
		NextToken: nil,
		Total:     1,
	}

	body, _ := json.Marshal(resp)
	mock := &mockHTTPClient{
		getResponse: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		},
	}

	svc := &SCAAccessService{httpClient: mock}
	result, err := svc.ListSessions(context.Background(), &csp)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Response) != 1 {
		t.Errorf("expected 1 session, got %d", len(result.Response))
	}
	if result.Response[0].CSP != models.CSPAzure {
		t.Errorf("expected CSP AZURE, got %s", result.Response[0].CSP)
	}
}
