// Package workflows provides the CyberArk Access Requests API client.
package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/aaearon/grant-cli/internal/workflows/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

type httpClient interface {
	Get(ctx context.Context, route string, params interface{}) (*http.Response, error)
	Post(ctx context.Context, route string, body interface{}) (*http.Response, error)
}

// AccessRequestService provides access to the Access Requests API endpoints.
type AccessRequestService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth    *auth.IdsecISPAuth
	httpClient httpClient
}

// NewAccessRequestService creates a new Access Request Service instance.
func NewAccessRequestService(authenticators ...auth.IdsecAuth) (*AccessRequestService, error) {
	svc := &AccessRequestService{}
	var svcIface services.IdsecService = svc

	base, err := services.NewIdsecBaseService(svcIface, authenticators...)
	if err != nil {
		return nil, fmt.Errorf("failed to create base service: %w", err)
	}
	svc.IdsecBaseService = base

	ispAuthIface, err := base.Authenticator("isp")
	if err != nil {
		return nil, fmt.Errorf("isp authenticator required: %w", err)
	}

	ispAuth, ok := ispAuthIface.(*auth.IdsecISPAuth)
	if !ok {
		return nil, errors.New("authenticator is not *auth.IdsecISPAuth")
	}
	svc.ispAuth = ispAuth

	client, err := isp.FromISPAuth(ispAuth, "uar", ".", "", svc.refreshAuth, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ISP client: %w", err)
	}

	svc.httpClient = newLoggingClient(client, common.GetLogger("grant", -1))

	return svc, nil
}

// NewAccessRequestServiceWithClient creates a service with a custom HTTP client for testing.
func NewAccessRequestServiceWithClient(client httpClient) *AccessRequestService {
	return &AccessRequestService{
		httpClient: client,
	}
}

func (s *AccessRequestService) refreshAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ispAuth)
}

// ServiceConfig returns the service configuration.
func (s *AccessRequestService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig()
}

// GetRequestForms retrieves the access request form structure.
// GET /api/workflows/request-forms
func (s *AccessRequestService) GetRequestForms(ctx context.Context, targetCategory, requestType string) (*models.RequestFormResponse, error) {
	params := map[string]string{
		"targetCategory": targetCategory,
		"requestType":    requestType,
	}

	resp, err := s.httpClient.Get(ctx, "/api/workflows/request-forms", params)
	if err != nil {
		return nil, fmt.Errorf("failed to get request forms: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp, "request forms"); err != nil {
		return nil, err
	}

	var result models.RequestFormResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode request forms response: %w", err)
	}

	return &result, nil
}

// ListRequestsParams holds query parameters for listing access requests.
type ListRequestsParams struct {
	Filter      string
	FreeText    string
	Limit       int
	Offset      int
	RequestRole string
	Sort        string
}

const defaultPageSize = 50

// ListRequests retrieves all access requests matching the given parameters,
// fetching all pages via offset/limit pagination.
// GET /api/workflows/requests
func (s *AccessRequestService) ListRequests(ctx context.Context, params ListRequestsParams) ([]models.AccessRequest, int, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = defaultPageSize
	}

	var allItems []models.AccessRequest
	totalCount := 0
	offset := params.Offset

	for range maxPages {
		qp := make(map[string]string)
		qp["limit"] = strconv.Itoa(limit)
		qp["offset"] = strconv.Itoa(offset)
		if params.Filter != "" {
			qp["filter"] = params.Filter
		}
		if params.FreeText != "" {
			qp["freeText"] = params.FreeText
		}
		if params.RequestRole != "" {
			qp["requestRole"] = params.RequestRole
		}
		if params.Sort != "" {
			qp["sort"] = params.Sort
		}

		resp, err := s.httpClient.Get(ctx, "/api/workflows/requests", qp)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to list requests: %w", err)
		}

		if err := checkResponse(resp, "list requests"); err != nil {
			resp.Body.Close()
			return nil, 0, err
		}

		var page models.ListRequestsResponse
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("failed to decode list requests response: %w", err)
		}
		resp.Body.Close()

		allItems = append(allItems, page.Items...)
		totalCount = page.TotalCount

		if len(allItems) >= page.TotalCount || len(page.Items) < limit {
			return allItems, totalCount, nil
		}
		offset += len(page.Items)
	}

	return nil, 0, errPaginationLimit
}

// GetRequest retrieves a single access request by ID.
// GET /api/workflows/requests/{requestId}
func (s *AccessRequestService) GetRequest(ctx context.Context, requestID string) (*models.AccessRequest, error) {
	route := "/api/workflows/requests/" + requestID

	resp, err := s.httpClient.Get(ctx, route, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp, "get request"); err != nil {
		return nil, err
	}

	var result models.AccessRequest
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode request response: %w", err)
	}

	return &result, nil
}

// SubmitRequest creates a new access request.
// POST /api/workflows/requests
func (s *AccessRequestService) SubmitRequest(ctx context.Context, req *models.SubmitAccessRequest) (*models.AccessRequest, error) {
	if req == nil {
		return nil, errors.New("submit request cannot be nil")
	}

	resp, err := s.httpClient.Post(ctx, "/api/workflows/requests", req)
	if err != nil {
		return nil, fmt.Errorf("failed to submit request: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp, "submit request"); err != nil {
		return nil, err
	}

	var result models.AccessRequest
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode submit response: %w", err)
	}

	return &result, nil
}

// CancelRequest cancels an open access request.
// POST /api/workflows/requests/{requestId}/cancel
func (s *AccessRequestService) CancelRequest(ctx context.Context, requestID string, reason *string) (*models.AccessRequest, error) {
	route := fmt.Sprintf("/api/workflows/requests/%s/cancel", requestID)
	body := &models.CancelAccessRequest{CancelReason: reason}

	resp, err := s.httpClient.Post(ctx, route, body)
	if err != nil {
		return nil, fmt.Errorf("failed to cancel request: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp, "cancel request"); err != nil {
		return nil, err
	}

	var result models.AccessRequest
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode cancel response: %w", err)
	}

	return &result, nil
}

// FinalizeRequest approves or rejects an access request.
// POST /api/workflows/requests/{requestId}/finalize
func (s *AccessRequestService) FinalizeRequest(ctx context.Context, requestID, result string, reason *string) (*models.AccessRequest, error) {
	route := fmt.Sprintf("/api/workflows/requests/%s/finalize", requestID)
	body := &models.FinalizeAccessRequest{
		Result:             result,
		FinalizationReason: reason,
	}

	resp, err := s.httpClient.Post(ctx, route, body)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize request: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp, "finalize request"); err != nil {
		return nil, err
	}

	var reqResult models.AccessRequest
	if err := json.NewDecoder(resp.Body).Decode(&reqResult); err != nil {
		return nil, fmt.Errorf("failed to decode finalize response: %w", err)
	}

	return &reqResult, nil
}

const maxPages = 100

// errPaginationLimit is returned when ListRequests exhausts the maximum number of
// page fetches without completing pagination.
var errPaginationLimit = errors.New("list requests pagination exceeded maximum page limit")

func checkResponse(resp *http.Response, operation string) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		body = []byte("(failed to read response body)")
	}
	return fmt.Errorf("%s failed with status %d: %s", operation, resp.StatusCode, string(body))
}
