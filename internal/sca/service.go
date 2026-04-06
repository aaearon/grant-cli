// Package sca provides the CyberArk SCA Access API client.
package sca

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// httpClient is an interface for making HTTP requests.
// It allows dependency injection for testing.
type httpClient interface {
	Get(ctx context.Context, route string, params interface{}) (*http.Response, error)
	Post(ctx context.Context, route string, body interface{}) (*http.Response, error)
}

// SCAAccessService provides access to SCA API endpoints.
type SCAAccessService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth    *auth.IdsecISPAuth
	httpClient httpClient
}

// NewSCAAccessService creates a new SCA Access Service instance.
// It follows the SDK service pattern with ISP authentication.
func NewSCAAccessService(authenticators ...auth.IdsecAuth) (*SCAAccessService, error) {
	svc := &SCAAccessService{}
	var svcIface services.IdsecService = svc

	base, err := services.NewIdsecBaseService(svcIface, authenticators...)
	if err != nil {
		return nil, fmt.Errorf("failed to create base service: %w", err)
	}
	svc.IdsecBaseService = base

	// Extract ISP authenticator
	ispAuthIface, err := base.Authenticator("isp")
	if err != nil {
		return nil, fmt.Errorf("isp authenticator required: %w", err)
	}

	ispAuth, ok := ispAuthIface.(*auth.IdsecISPAuth)
	if !ok {
		return nil, errors.New("authenticator is not *auth.IdsecISPAuth")
	}
	svc.ispAuth = ispAuth

	// Create ISP client
	client, err := isp.FromISPAuth(ispAuth, "sca", ".", "", svc.refreshAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to create ISP client: %w", err)
	}

	// Set required API version header
	client.SetHeader("X-API-Version", "2.0")

	// Wrap with logging — SDK logger level-gates based on IDSEC_LOG_LEVEL env
	svc.httpClient = newLoggingClient(client, common.GetLogger("grant", -1))

	return svc, nil
}

// NewSCAAccessServiceWithClient creates a service with a custom HTTP client.
// This is primarily for testing with mock clients.
func NewSCAAccessServiceWithClient(client httpClient) *SCAAccessService {
	return &SCAAccessService{
		httpClient: client,
	}
}

// refreshAuth is the callback for refreshing authentication tokens.
func (s *SCAAccessService) refreshAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ispAuth)
}

// ServiceConfig returns the service configuration.
func (s *SCAAccessService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig()
}

// checkResponse returns an error if the HTTP response status is not 200 OK.
// It reads up to 4 KB of the response body to include in the error message.
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

// maxPages is the upper bound on pagination requests to guard against infinite loops.
const maxPages = 100

// paginate fetches all pages of a paginated GET endpoint using nextToken cursor.
// buildParams returns the query parameters for each request (nextToken is added automatically).
// decode extracts the items, nextToken pointer, and total from each page response.
// The total is captured from the first page only.
func paginate[T any](
	ctx context.Context,
	s *SCAAccessService,
	route string,
	buildParams func() map[string]string,
	decode func(io.Reader) ([]T, *string, int, error),
	errPrefix string,
) (allItems []T, total int, _ error) {
	var nextToken *string

	for page := range maxPages {
		params := buildParams()
		if nextToken != nil {
			if params == nil {
				params = make(map[string]string)
			}
			params["nextToken"] = *nextToken
		}

		var p interface{}
		if len(params) > 0 {
			p = params
		}

		resp, err := s.httpClient.Get(ctx, route, p)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get %s: %w", errPrefix, err)
		}

		if err := checkResponse(resp, errPrefix+" request"); err != nil {
			resp.Body.Close()
			return nil, 0, err
		}

		pageItems, nt, pageTotal, decErr := decode(resp.Body)
		resp.Body.Close()
		if decErr != nil {
			return nil, 0, fmt.Errorf("failed to decode %s response: %w", errPrefix, decErr)
		}

		allItems = append(allItems, pageItems...)
		if page == 0 {
			total = pageTotal
		}
		nextToken = nt

		if nextToken == nil {
			return allItems, total, nil
		}
	}

	return nil, 0, fmt.Errorf("%s pagination exceeded maximum page limit", errPrefix)
}

// ListEligibility retrieves all eligible targets for the specified CSP,
// automatically paginating through all pages via nextToken.
// GET /api/access/{CSP}/eligibility
func (s *SCAAccessService) ListEligibility(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
	route := fmt.Sprintf("/api/access/%s/eligibility", csp)

	items, total, err := paginate(ctx, s, route,
		func() map[string]string { return nil },
		func(r io.Reader) ([]models.EligibleTarget, *string, int, error) {
			var page models.EligibilityResponse
			if err := json.NewDecoder(r).Decode(&page); err != nil {
				return nil, nil, 0, err
			}
			return page.Response, page.NextToken, page.Total, nil
		},
		"eligibility",
	)
	if err != nil {
		return nil, err
	}

	return &models.EligibilityResponse{Response: items, Total: total}, nil
}

// Elevate requests JIT elevation for the specified targets.
// POST /api/access/elevate
func (s *SCAAccessService) Elevate(ctx context.Context, req *models.ElevateRequest) (*models.ElevateResponse, error) {
	if req == nil {
		return nil, errors.New("elevate request cannot be nil")
	}
	if len(req.Targets) == 0 {
		return nil, errors.New("elevate request must contain at least one target")
	}

	resp, err := s.httpClient.Post(ctx, "/api/access/elevate", req)
	if err != nil {
		return nil, fmt.Errorf("failed to elevate: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp, "elevate request"); err != nil {
		return nil, err
	}

	var result models.ElevateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode elevate response: %w", err)
	}

	return &result, nil
}

// RevokeSessions revokes one or more active sessions by their IDs.
// POST /api/access/sessions/revoke
func (s *SCAAccessService) RevokeSessions(ctx context.Context, req *models.RevokeRequest) (*models.RevokeResponse, error) {
	if req == nil {
		return nil, errors.New("revoke request cannot be nil")
	}
	if len(req.SessionIDs) == 0 {
		return nil, errors.New("revoke request must contain at least one session ID")
	}

	resp, err := s.httpClient.Post(ctx, "/api/access/sessions/revoke", req)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke sessions: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp, "revoke sessions request"); err != nil {
		return nil, err
	}

	var result models.RevokeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode revoke response: %w", err)
	}

	return &result, nil
}

// ListSessions retrieves all active elevated sessions, optionally filtered by CSP,
// automatically paginating through all pages via nextToken.
// GET /api/access/sessions
func (s *SCAAccessService) ListSessions(ctx context.Context, csp *models.CSP) (*models.SessionsResponse, error) {
	items, total, err := paginate(ctx, s, "/api/access/sessions",
		func() map[string]string {
			if csp != nil {
				return map[string]string{"csp": string(*csp)}
			}
			return nil
		},
		func(r io.Reader) ([]models.SessionInfo, *string, int, error) {
			var page models.SessionsResponse
			if err := json.NewDecoder(r).Decode(&page); err != nil {
				return nil, nil, 0, err
			}
			return page.Response, page.NextToken, page.Total, nil
		},
		"sessions",
	)
	if err != nil {
		return nil, err
	}

	return &models.SessionsResponse{Response: items, Total: total}, nil
}

// ListGroupsEligibility retrieves all eligible Entra ID groups for the specified CSP,
// automatically paginating through all pages via nextToken.
// GET /api/access/{CSP}/eligibility/groups
func (s *SCAAccessService) ListGroupsEligibility(ctx context.Context, csp models.CSP) (*models.GroupsEligibilityResponse, error) {
	route := fmt.Sprintf("/api/access/%s/eligibility/groups", csp)

	items, total, err := paginate(ctx, s, route,
		func() map[string]string { return nil },
		func(r io.Reader) ([]models.GroupsEligibleTarget, *string, int, error) {
			var page models.GroupsEligibilityResponse
			if err := json.NewDecoder(r).Decode(&page); err != nil {
				return nil, nil, 0, err
			}
			return page.Response, page.NextToken, page.Total, nil
		},
		"groups eligibility",
	)
	if err != nil {
		return nil, err
	}

	return &models.GroupsEligibilityResponse{Response: items, Total: total}, nil
}

// ElevateGroups requests JIT elevation for the specified Entra ID groups.
// POST /api/access/elevate/groups
func (s *SCAAccessService) ElevateGroups(ctx context.Context, req *models.GroupsElevateRequest) (*models.GroupsElevateResponse, error) {
	if req == nil {
		return nil, errors.New("groups elevate request cannot be nil")
	}
	if len(req.Targets) == 0 {
		return nil, errors.New("groups elevate request must contain at least one target")
	}

	resp, err := s.httpClient.Post(ctx, "/api/access/elevate/groups", req)
	if err != nil {
		return nil, fmt.Errorf("failed to elevate groups: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp, "groups elevate request"); err != nil {
		return nil, err
	}

	var wrapper struct {
		Response models.GroupsElevateResponse `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("failed to decode groups elevate response: %w", err)
	}

	return &wrapper.Response, nil
}
