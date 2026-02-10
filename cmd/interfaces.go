package cmd

import (
	"context"

	"github.com/aaearon/grant-cli/internal/sca/models"
	sdk_models "github.com/cyberark/idsec-sdk-golang/pkg/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// authLoader interface for loading authentication
type authLoader interface {
	LoadAuthentication(profile *sdk_models.IdsecProfile, cacheAuthentication bool) (*auth_models.IdsecToken, error)
}

// eligibilityLister interface for listing eligible targets
type eligibilityLister interface {
	ListEligibility(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error)
}

// elevateService interface for elevation operations
type elevateService interface {
	Elevate(ctx context.Context, req *models.ElevateRequest) (*models.ElevateResponse, error)
}

// targetSelector interface for interactive target selection
type targetSelector interface {
	SelectTarget(targets []models.AzureEligibleTarget) (*models.AzureEligibleTarget, error)
}

// sessionLister interface for listing sessions
type sessionLister interface {
	ListSessions(ctx context.Context, csp *models.CSP) (*models.SessionsResponse, error)
}
