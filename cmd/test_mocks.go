package cmd

import (
	"context"

	"github.com/aaearon/grant-cli/internal/sca/models"
	sdk_models "github.com/cyberark/idsec-sdk-golang/pkg/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// mockAuthLoader implements the authLoader interface for testing
type mockAuthLoader struct {
	loadFunc func(profile *sdk_models.IdsecProfile, cacheAuthentication bool) (*auth_models.IdsecToken, error)
	token    *auth_models.IdsecToken
	loadErr  error
}

func (m *mockAuthLoader) LoadAuthentication(profile *sdk_models.IdsecProfile, cacheAuthentication bool) (*auth_models.IdsecToken, error) {
	if m.loadFunc != nil {
		return m.loadFunc(profile, cacheAuthentication)
	}
	return m.token, m.loadErr
}

// mockSessionLister implements the sessionLister interface for testing
type mockSessionLister struct {
	listFunc func(ctx context.Context, csp *models.CSP) (*models.SessionsResponse, error)
	sessions *models.SessionsResponse
	listErr  error
}

func (m *mockSessionLister) ListSessions(ctx context.Context, csp *models.CSP) (*models.SessionsResponse, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, csp)
	}
	return m.sessions, m.listErr
}

// mockEligibilityLister implements the eligibilityLister interface for testing
type mockEligibilityLister struct {
	listFunc func(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error)
	response *models.EligibilityResponse
	listErr  error
}

func (m *mockEligibilityLister) ListEligibility(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, csp)
	}
	return m.response, m.listErr
}

// mockElevateService implements the elevateService interface for testing
type mockElevateService struct {
	elevateFunc func(ctx context.Context, req *models.ElevateRequest) (*models.ElevateResponse, error)
	response    *models.ElevateResponse
	elevateErr  error
}

func (m *mockElevateService) Elevate(ctx context.Context, req *models.ElevateRequest) (*models.ElevateResponse, error) {
	if m.elevateFunc != nil {
		return m.elevateFunc(ctx, req)
	}
	return m.response, m.elevateErr
}

// mockTargetSelector implements the targetSelector interface for testing
type mockTargetSelector struct {
	selectFunc func(targets []models.AzureEligibleTarget) (*models.AzureEligibleTarget, error)
	target     *models.AzureEligibleTarget
	selectErr  error
}

func (m *mockTargetSelector) SelectTarget(targets []models.AzureEligibleTarget) (*models.AzureEligibleTarget, error) {
	if m.selectFunc != nil {
		return m.selectFunc(targets)
	}
	return m.target, m.selectErr
}

// mockAuthenticator implements the authenticator interface for testing
type mockAuthenticator struct {
	authenticateFunc func(profile *sdk_models.IdsecProfile, authProfile *auth_models.IdsecAuthProfile, secret *auth_models.IdsecSecret, force bool, refreshAuth bool) (*auth_models.IdsecToken, error)
	token            *auth_models.IdsecToken
	authErr          error
}

func (m *mockAuthenticator) Authenticate(profile *sdk_models.IdsecProfile, authProfile *auth_models.IdsecAuthProfile, secret *auth_models.IdsecSecret, force bool, refreshAuth bool) (*auth_models.IdsecToken, error) {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(profile, authProfile, secret, force, refreshAuth)
	}
	return m.token, m.authErr
}

// mockProfileSaver implements profileSaver interface for testing
type mockProfileSaver struct {
	saveFunc func(*sdk_models.IdsecProfile) error
	saveErr  error
}

func (m *mockProfileSaver) SaveProfile(profile *sdk_models.IdsecProfile) error {
	if m.saveFunc != nil {
		return m.saveFunc(profile)
	}
	return m.saveErr
}

// mockKeyringClearer implements keyringClearer interface for testing
type mockKeyringClearer struct {
	clearFunc func() error
	clearErr  error
}

func (m *mockKeyringClearer) ClearAllPasswords() error {
	if m.clearFunc != nil {
		return m.clearFunc()
	}
	return m.clearErr
}
