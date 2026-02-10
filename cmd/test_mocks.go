package cmd

import (
	"context"

	"github.com/aaearon/sca-cli/internal/sca/models"
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
	listFunc  func(ctx context.Context, csp *models.CSP) (*models.SessionsResponse, error)
	sessions  *models.SessionsResponse
	listErr   error
}

func (m *mockSessionLister) ListSessions(ctx context.Context, csp *models.CSP) (*models.SessionsResponse, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, csp)
	}
	return m.sessions, m.listErr
}
