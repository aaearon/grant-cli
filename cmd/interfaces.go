package cmd

import (
	"context"

	"github.com/aaearon/grant-cli/internal/sca/models"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// authLoader interface for loading authentication
type authLoader interface {
	LoadAuthentication(profile *sdkmodels.IdsecProfile, cacheAuthentication bool) (*authmodels.IdsecToken, error)
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
	SelectTarget(targets []models.EligibleTarget) (*models.EligibleTarget, error)
}

// sessionLister interface for listing sessions
type sessionLister interface {
	ListSessions(ctx context.Context, csp *models.CSP) (*models.SessionsResponse, error)
}

// sessionRevoker interface for revoking sessions
type sessionRevoker interface {
	RevokeSessions(ctx context.Context, req *models.RevokeRequest) (*models.RevokeResponse, error)
}

// sessionSelector interface for interactive session selection
type sessionSelector interface {
	SelectSessions(sessions []models.SessionInfo, nameMap map[string]string) ([]models.SessionInfo, error)
}

// confirmPrompter interface for confirmation prompts
type confirmPrompter interface {
	ConfirmRevocation(count int) (bool, error)
}

// keyringClearer interface for clearing keyring passwords
type keyringClearer interface {
	ClearAllPasswords() error
}

// namePrompter interface for prompting the user for a favorite name
type namePrompter interface {
	PromptName() (string, error)
}

// authenticator is the interface for authentication operations
type authenticator interface {
	Authenticate(profile *sdkmodels.IdsecProfile, authProfile *authmodels.IdsecAuthProfile, secret *authmodels.IdsecSecret, force bool, refreshAuth bool) (*authmodels.IdsecToken, error)
}

// profileSaver interface for saving SDK profiles
type profileSaver interface {
	SaveProfile(profile *sdkmodels.IdsecProfile) error
}
