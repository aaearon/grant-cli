package sca

import (
	"context"
	"encoding/json"
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
		return nil, fmt.Errorf("authenticator is not *auth.IdsecISPAuth")
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

// ListEligibility retrieves eligible targets for the specified CSP.
// GET /api/access/{CSP}/eligibility
func (s *SCAAccessService) ListEligibility(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
	route := fmt.Sprintf("/api/access/%s/eligibility", csp)

	resp, err := s.httpClient.Get(ctx, route, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get eligibility: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			body = []byte("(failed to read response body)")
		}
		return nil, fmt.Errorf("eligibility request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result models.EligibilityResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode eligibility response: %w", err)
	}

	return &result, nil
}

// Elevate requests JIT elevation for the specified targets.
// POST /api/access/elevate
func (s *SCAAccessService) Elevate(ctx context.Context, req *models.ElevateRequest) (*models.ElevateResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("elevate request cannot be nil")
	}
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("elevate request must contain at least one target")
	}

	resp, err := s.httpClient.Post(ctx, "/api/access/elevate", req)
	if err != nil {
		return nil, fmt.Errorf("failed to elevate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			body = []byte("(failed to read response body)")
		}
		return nil, fmt.Errorf("elevate request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result models.ElevateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode elevate response: %w", err)
	}

	return &result, nil
}

// ListSessions retrieves active elevated sessions, optionally filtered by CSP.
// GET /api/access/sessions
func (s *SCAAccessService) ListSessions(ctx context.Context, csp *models.CSP) (*models.SessionsResponse, error) {
	route := "/api/access/sessions"

	var params interface{}
	if csp != nil {
		params = map[string]string{"csp": string(*csp)}
	}

	resp, err := s.httpClient.Get(ctx, route, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			body = []byte("(failed to read response body)")
		}
		return nil, fmt.Errorf("sessions request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result models.SessionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode sessions response: %w", err)
	}

	return &result, nil
}
