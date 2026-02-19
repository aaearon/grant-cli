package cmd

import (
	"context"
	"errors"

	"github.com/aaearon/grant-cli/internal/sca/models"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// errNotAuthenticated is a sentinel error used in tests to simulate
// a missing cached token from the auth loader.
var errNotAuthenticated = errors.New("no cached token")

// mockAuthLoader implements the authLoader interface for testing
type mockAuthLoader struct {
	loadFunc func(profile *sdkmodels.IdsecProfile, cacheAuthentication bool) (*authmodels.IdsecToken, error)
	token    *authmodels.IdsecToken
	loadErr  error
}

func (m *mockAuthLoader) LoadAuthentication(profile *sdkmodels.IdsecProfile, cacheAuthentication bool) (*authmodels.IdsecToken, error) {
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
	selectFunc func(targets []models.EligibleTarget) (*models.EligibleTarget, error)
	target     *models.EligibleTarget
	selectErr  error
}

func (m *mockTargetSelector) SelectTarget(targets []models.EligibleTarget) (*models.EligibleTarget, error) {
	if m.selectFunc != nil {
		return m.selectFunc(targets)
	}
	return m.target, m.selectErr
}

// mockSessionRevoker implements the sessionRevoker interface for testing
type mockSessionRevoker struct {
	revokeFunc func(ctx context.Context, req *models.RevokeRequest) (*models.RevokeResponse, error)
	response   *models.RevokeResponse
	revokeErr  error
}

func (m *mockSessionRevoker) RevokeSessions(ctx context.Context, req *models.RevokeRequest) (*models.RevokeResponse, error) {
	if m.revokeFunc != nil {
		return m.revokeFunc(ctx, req)
	}
	return m.response, m.revokeErr
}

// mockSessionSelector implements the sessionSelector interface for testing
type mockSessionSelector struct {
	selectFunc func(sessions []models.SessionInfo, nameMap map[string]string) ([]models.SessionInfo, error)
	sessions   []models.SessionInfo
	selectErr  error
}

func (m *mockSessionSelector) SelectSessions(sessions []models.SessionInfo, nameMap map[string]string) ([]models.SessionInfo, error) {
	if m.selectFunc != nil {
		return m.selectFunc(sessions, nameMap)
	}
	return m.sessions, m.selectErr
}

// mockConfirmPrompter implements the confirmPrompter interface for testing
type mockConfirmPrompter struct {
	confirmFunc func(count int) (bool, error)
	confirmed   bool
	confirmErr  error
}

func (m *mockConfirmPrompter) ConfirmRevocation(count int) (bool, error) {
	if m.confirmFunc != nil {
		return m.confirmFunc(count)
	}
	return m.confirmed, m.confirmErr
}

// mockAuthenticator implements the authenticator interface for testing
type mockAuthenticator struct {
	authenticateFunc func(profile *sdkmodels.IdsecProfile, authProfile *authmodels.IdsecAuthProfile, secret *authmodels.IdsecSecret, force bool, refreshAuth bool) (*authmodels.IdsecToken, error)
	token            *authmodels.IdsecToken
	authErr          error
}

func (m *mockAuthenticator) Authenticate(profile *sdkmodels.IdsecProfile, authProfile *authmodels.IdsecAuthProfile, secret *authmodels.IdsecSecret, force bool, refreshAuth bool) (*authmodels.IdsecToken, error) {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(profile, authProfile, secret, force, refreshAuth)
	}
	return m.token, m.authErr
}

// mockProfileSaver implements profileSaver interface for testing
type mockProfileSaver struct {
	saveFunc func(*sdkmodels.IdsecProfile) error
	saveErr  error
}

func (m *mockProfileSaver) SaveProfile(profile *sdkmodels.IdsecProfile) error {
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

// mockNamePrompter implements namePrompter interface for testing
type mockNamePrompter struct {
	promptFunc func() (string, error)
	name       string
	promptErr  error
}

func (m *mockNamePrompter) PromptName() (string, error) {
	if m.promptFunc != nil {
		return m.promptFunc()
	}
	return m.name, m.promptErr
}

// mockGroupsEligibilityLister implements groupsEligibilityLister for testing
type mockGroupsEligibilityLister struct {
	listFunc func(ctx context.Context, csp models.CSP) (*models.GroupsEligibilityResponse, error)
	response *models.GroupsEligibilityResponse
	listErr  error
}

func (m *mockGroupsEligibilityLister) ListGroupsEligibility(ctx context.Context, csp models.CSP) (*models.GroupsEligibilityResponse, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, csp)
	}
	return m.response, m.listErr
}

// mockGroupsElevator implements groupsElevator for testing
type mockGroupsElevator struct {
	elevateFunc func(ctx context.Context, req *models.GroupsElevateRequest) (*models.GroupsElevateResponse, error)
	response    *models.GroupsElevateResponse
	elevateErr  error
}

func (m *mockGroupsElevator) ElevateGroups(ctx context.Context, req *models.GroupsElevateRequest) (*models.GroupsElevateResponse, error) {
	if m.elevateFunc != nil {
		return m.elevateFunc(ctx, req)
	}
	return m.response, m.elevateErr
}

// mockGroupSelector implements groupSelector for testing
type mockGroupSelector struct {
	selectFunc func(groups []models.GroupsEligibleTarget) (*models.GroupsEligibleTarget, error)
	group      *models.GroupsEligibleTarget
	selectErr  error
}

func (m *mockGroupSelector) SelectGroup(groups []models.GroupsEligibleTarget) (*models.GroupsEligibleTarget, error) {
	if m.selectFunc != nil {
		return m.selectFunc(groups)
	}
	return m.group, m.selectErr
}
