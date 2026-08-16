package sca

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

// Wire contracts: what grant actually *sends*. The mocks used to discard the
// route, the body and the query params, so a typo'd path or a nil body was
// invisible to every test in this package.

func okBody(v interface{}) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(string(b))),
	}
}

func TestElevate_SendsExactRouteAndBody(t *testing.T) {
	mock := &mockHTTPClient{
		postResponse: okBody(models.ElevateResponse{}),
	}
	svc := &SCAAccessService{httpClient: mock}

	// Distinguishable values: every field differs from every other so a swap
	// or a dropped field cannot be masked. Do not "tidy" these to "test".
	req := &models.ElevateRequest{
		CSP:            models.CSPAzure,
		OrganizationID: "org-elevate-1",
		Targets: []models.ElevateTarget{
			{WorkspaceID: "ws-elevate-2", RoleID: "role-elevate-3", RoleName: "Role Elevate Four"},
		},
	}
	if _, err := svc.Elevate(t.Context(), req); err != nil {
		t.Fatalf("Elevate: %v", err)
	}

	if mock.gotRoute != "/api/access/elevate" {
		t.Errorf("route = %q, want %q", mock.gotRoute, "/api/access/elevate")
	}
	got, ok := mock.gotBody.(*models.ElevateRequest)
	if !ok {
		t.Fatalf("body = %#v (%T), want *models.ElevateRequest", mock.gotBody, mock.gotBody)
	}
	if !reflect.DeepEqual(got, req) {
		t.Errorf("body = %#v, want %#v", got, req)
	}
}

func TestRevokeSessions_SendsExactRouteAndBody(t *testing.T) {
	mock := &mockHTTPClient{
		postResponse: okBody(models.RevokeResponse{}),
	}
	svc := &SCAAccessService{httpClient: mock}

	req := &models.RevokeRequest{SessionIDs: []string{"sess-revoke-1", "sess-revoke-2"}}
	if _, err := svc.RevokeSessions(t.Context(), req); err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}

	if mock.gotRoute != "/api/access/sessions/revoke" {
		t.Errorf("route = %q, want %q", mock.gotRoute, "/api/access/sessions/revoke")
	}
	got, ok := mock.gotBody.(*models.RevokeRequest)
	if !ok {
		t.Fatalf("body = %#v (%T), want *models.RevokeRequest", mock.gotBody, mock.gotBody)
	}
	if !reflect.DeepEqual(got.SessionIDs, req.SessionIDs) {
		t.Errorf("sessionIds = %#v, want %#v", got.SessionIDs, req.SessionIDs)
	}
}

func TestElevateGroups_SendsExactRouteAndBody(t *testing.T) {
	mock := &mockHTTPClient{
		postResponse: okBody(map[string]interface{}{"response": models.GroupsElevateResponse{}}),
	}
	svc := &SCAAccessService{httpClient: mock}

	req := &models.GroupsElevateRequest{
		DirectoryID: "dir-groups-1",
		CSP:         models.CSPAzure,
		Targets: []models.GroupsElevateTarget{
			{GroupID: "grp-groups-2"},
		},
	}
	if _, err := svc.ElevateGroups(t.Context(), req); err != nil {
		t.Fatalf("ElevateGroups: %v", err)
	}

	if mock.gotRoute != "/api/access/elevate/groups" {
		t.Errorf("route = %q, want %q", mock.gotRoute, "/api/access/elevate/groups")
	}
	got, ok := mock.gotBody.(*models.GroupsElevateRequest)
	if !ok {
		t.Fatalf("body = %#v (%T), want *models.GroupsElevateRequest", mock.gotBody, mock.gotBody)
	}
	if !reflect.DeepEqual(got, req) {
		t.Errorf("body = %#v, want %#v", got, req)
	}
}

func TestGetRoutes_Exact(t *testing.T) {
	tests := []struct {
		name      string
		call      func(svc *SCAAccessService) error
		wantRoute string
	}{
		{
			name: "list sessions",
			call: func(svc *SCAAccessService) error {
				_, err := svc.ListSessions(t.Context(), nil)
				return err
			},
			wantRoute: "/api/access/sessions",
		},
		{
			name: "list eligibility",
			call: func(svc *SCAAccessService) error {
				_, err := svc.ListEligibility(t.Context(), models.CSPAzure)
				return err
			},
			wantRoute: "/api/access/AZURE/eligibility",
		},
		{
			name: "list groups eligibility",
			call: func(svc *SCAAccessService) error {
				_, err := svc.ListGroupsEligibility(t.Context(), models.CSPAzure)
				return err
			},
			wantRoute: "/api/access/AZURE/eligibility/groups",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHTTPClient{
				getFunc: func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"response":[],"total":0}`)),
					}, nil
				},
			}
			svc := &SCAAccessService{httpClient: mock}
			if err := tt.call(svc); err != nil {
				t.Fatalf("call: %v", err)
			}
			if mock.gotRoute != tt.wantRoute {
				t.Errorf("route = %q, want %q", mock.gotRoute, tt.wantRoute)
			}
		})
	}
}

// TestListOnDemandResources_ExactQueryParams pins the literal values grant puts
// on the wire for the on-demand role endpoints. It deliberately asserts only the
// values sent: the semantics of pageSize -1 are not documented in this repo, the
// pinned SDK, or CyberArk's published material, so no consequence is claimed.
func TestListOnDemandResources_ExactQueryParams(t *testing.T) {
	t.Run("GET search object", func(t *testing.T) {
		mock := &mockHTTPClient{
			getResponse: okBody([]models.OnDemandResource{}),
		}
		svc := &SCAAccessService{httpClient: mock}

		_, err := svc.ListOnDemandResources(t.Context(), models.OnDemandRequest{
			WorkspaceID:  "ws-ondemand-1",
			PlatformName: "azure_ad",
			OrgID:        "org-ondemand-2",
		})
		if err != nil {
			t.Fatalf("ListOnDemandResources: %v", err)
		}

		if mock.gotRoute != "/api/cloud/resources/ondemand" {
			t.Errorf("route = %q, want %q", mock.gotRoute, "/api/cloud/resources/ondemand")
		}
		params, ok := mock.gotParams.(map[string]string)
		if !ok {
			t.Fatalf("params = %#v (%T), want map[string]string", mock.gotParams, mock.gotParams)
		}
		var search map[string]interface{}
		if err := json.Unmarshal([]byte(params["search"]), &search); err != nil {
			t.Fatalf("search param is not JSON: %v (%q)", err, params["search"])
		}
		want := map[string]interface{}{
			"workspaceId":     "ws-ondemand-1",
			"pageNumber":      float64(-1),
			"pageSize":        float64(-1),
			"platformName":    "azure_ad",
			"org_id":          "org-ondemand-2",
			"target_category": "cloud_console",
		}
		if !reflect.DeepEqual(search, want) {
			t.Errorf("search = %#v, want %#v", search, want)
		}
	})

	t.Run("POST body", func(t *testing.T) {
		mock := &mockHTTPClient{
			postResponse: okBody([]models.OnDemandResource{}),
		}
		svc := &SCAAccessService{httpClient: mock}

		_, err := svc.ListOnDemandResources(t.Context(), models.OnDemandRequest{
			WorkspaceID:  "ws-ondemand-3",
			PlatformName: "azure_resource",
			OrgID:        "org-ondemand-4",
			ResourceType: "management_group",
			Ancestors:    []string{"/org-ondemand-4", "/mg-ondemand-5"},
		})
		if err != nil {
			t.Fatalf("ListOnDemandResources: %v", err)
		}

		if mock.gotRoute != "/api/cloud/cloud-roles/ondemand" {
			t.Errorf("route = %q, want %q", mock.gotRoute, "/api/cloud/cloud-roles/ondemand")
		}
		body, ok := mock.gotBody.(map[string]interface{})
		if !ok {
			t.Fatalf("body = %#v (%T), want map[string]interface{}", mock.gotBody, mock.gotBody)
		}
		want := map[string]interface{}{
			"workspaceId":     "ws-ondemand-3",
			"resourceType":    "management_group",
			"pageNumber":      -1,
			"pageSize":        -1,
			"platformName":    "azure_resource",
			"org_id":          "org-ondemand-4",
			"ancestors":       []string{"/org-ondemand-4", "/mg-ondemand-5"},
			"target_category": "cloud_console",
		}
		if !reflect.DeepEqual(body, want) {
			t.Errorf("body = %#v, want %#v", body, want)
		}
	})
}

// TestPaginate_PropagatesContextCancellation covers the ctx argument of the
// paginated GET. Every mock in this package ignores ctx, so replacing it with
// context.Background() otherwise survives untouched.
func TestPaginate_PropagatesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	mock := &mockHTTPClient{
		getFunc: func(ctx context.Context, _ string, _ interface{}) (*http.Response, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return okBody(models.SessionsResponse{}), nil
		},
	}
	svc := &SCAAccessService{httpClient: mock}

	_, err := svc.ListSessions(ctx, nil)
	if err == nil {
		t.Fatal("expected the canceled context to reach the HTTP client, got nil error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

// TestPaginate_PropagatesDecodeError covers all three paginated decode closures.
// Swallowing the decode error there would turn a malformed payload into an
// empty, successful result.
func TestPaginate_PropagatesDecodeError(t *testing.T) {
	tests := []struct {
		name string
		call func(svc *SCAAccessService) error
	}{
		{
			name: "eligibility",
			call: func(svc *SCAAccessService) error {
				_, err := svc.ListEligibility(t.Context(), models.CSPAzure)
				return err
			},
		},
		{
			name: "sessions",
			call: func(svc *SCAAccessService) error {
				_, err := svc.ListSessions(t.Context(), nil)
				return err
			},
		},
		{
			name: "groups eligibility",
			call: func(svc *SCAAccessService) error {
				_, err := svc.ListGroupsEligibility(t.Context(), models.CSPAzure)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHTTPClient{
				getFunc: func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"response": "not-an-array"}`)),
					}, nil
				},
			}
			svc := &SCAAccessService{httpClient: mock}

			err := tt.call(svc)
			if err == nil {
				t.Fatal("expected a decode error, got nil")
			}
			if !strings.Contains(err.Error(), "failed to decode") {
				t.Errorf("error = %v, want it to name the decode failure", err)
			}
		})
	}
}
