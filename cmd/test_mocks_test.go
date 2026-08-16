package cmd

import (
	"context"
	"errors"
	"sync"

	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/workflows"
	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
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

// mockElevateService implements the elevateService interface for testing.
//
// Capture convention (see mockSessionRevoker): the request is recorded in the
// method body *before* dispatching to elevateFunc, so a test that supplies a
// callback still gets the history.
//
// No mutex, deliberately. The only mocks reached from more than one goroutine
// are the eligibility listers, via the fan-outs in fetchEligibility and
// fetchGroupsEligibility (cmd/root.go), resolveAndElevateUnifiedPath
// (cmd/root.go) and fetchAllTargets/fetchAllGroups (cmd/helpers.go). Every
// Elevate call site is sequential — resolveAndElevate and elevateCloud, the
// latter reached only after those fan-out channels have been joined.
// `make test-race` is what keeps that assumption honest.
//
// Function names, not line numbers: an unrelated insertion elsewhere in
// cmd/root.go already invalidated the line-number form of this comment once.
type mockElevateService struct {
	elevateFunc func(ctx context.Context, req *models.ElevateRequest) (*models.ElevateResponse, error)
	response    *models.ElevateResponse
	elevateErr  error

	// elevateCalls records every request sent, defensively copied so a later
	// mutation by production code cannot rewrite history.
	elevateCalls []models.ElevateRequest
}

func (m *mockElevateService) Elevate(ctx context.Context, req *models.ElevateRequest) (*models.ElevateResponse, error) {
	if req != nil {
		captured := *req
		captured.Targets = append([]models.ElevateTarget(nil), req.Targets...)
		m.elevateCalls = append(m.elevateCalls, captured)
	}
	if m.elevateFunc != nil {
		return m.elevateFunc(ctx, req)
	}
	return m.response, m.elevateErr
}

// lastElevate returns the most recent request, or nil if Elevate never ran.
func (m *mockElevateService) lastElevate() *models.ElevateRequest {
	if len(m.elevateCalls) == 0 {
		return nil
	}
	return &m.elevateCalls[len(m.elevateCalls)-1]
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
	// calls records the session IDs sent on every invocation, so batching
	// behavior can be asserted.
	calls [][]string
}

func (m *mockSessionRevoker) RevokeSessions(ctx context.Context, req *models.RevokeRequest) (*models.RevokeResponse, error) {
	if req != nil {
		m.calls = append(m.calls, append([]string(nil), req.SessionIDs...))
	}
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

func (m *mockAuthenticator) Authenticate(profile *sdkmodels.IdsecProfile, authProfile *authmodels.IdsecAuthProfile, secret *authmodels.IdsecSecret, force, refreshAuth bool) (*authmodels.IdsecToken, error) {
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

// mockGroupsElevator implements groupsElevator for testing.
// Same capture convention and same no-mutex reasoning as mockElevateService:
// the sole call site, elevateGroup (cmd/root.go), is sequential.
type mockGroupsElevator struct {
	elevateFunc func(ctx context.Context, req *models.GroupsElevateRequest) (*models.GroupsElevateResponse, error)
	response    *models.GroupsElevateResponse
	elevateErr  error

	elevateCalls []models.GroupsElevateRequest
}

func (m *mockGroupsElevator) ElevateGroups(ctx context.Context, req *models.GroupsElevateRequest) (*models.GroupsElevateResponse, error) {
	if req != nil {
		captured := *req
		captured.Targets = append([]models.GroupsElevateTarget(nil), req.Targets...)
		m.elevateCalls = append(m.elevateCalls, captured)
	}
	if m.elevateFunc != nil {
		return m.elevateFunc(ctx, req)
	}
	return m.response, m.elevateErr
}

// lastElevateGroups returns the most recent request, or nil if never called.
func (m *mockGroupsElevator) lastElevateGroups() *models.GroupsElevateRequest {
	if len(m.elevateCalls) == 0 {
		return nil
	}
	return &m.elevateCalls[len(m.elevateCalls)-1]
}

// mockUnifiedSelector implements unifiedSelector for testing
type mockUnifiedSelector struct {
	selectFunc func(items []selectionItem) (*selectionItem, error)
	item       *selectionItem
	selectErr  error
}

func (m *mockUnifiedSelector) SelectItem(items []selectionItem) (*selectionItem, error) {
	if m.selectFunc != nil {
		return m.selectFunc(items)
	}
	return m.item, m.selectErr
}

// mockSelfUpdater implements selfUpdater interface for testing
type mockSelfUpdater struct {
	updateSelfFn func(ctx context.Context, current string) (string, bool, error)
	newVersion   string
	updated      bool
	updateErr    error
	gotCurrent   string
}

func (m *mockSelfUpdater) UpdateSelf(ctx context.Context, current string) (newVersion string, updated bool, err error) {
	m.gotCurrent = current
	if m.updateSelfFn != nil {
		return m.updateSelfFn(ctx, current)
	}
	return m.newVersion, m.updated, m.updateErr
}

// cancelCall records one CancelRequest invocation.
//
// The optional *string reason is flattened into a value plus a set flag:
// runRequestCancel passes nil when --reason is empty, and a test must be able
// to tell nil from "".
type cancelCall struct {
	requestID string
	reason    string
	reasonSet bool
}

// finalizeCall records one FinalizeRequest invocation, with the same *string
// flattening as cancelCall.
type finalizeCall struct {
	requestID string
	decision  string
	reason    string
	reasonSet bool
}

// mockAccessRequestService implements accessRequestService for testing.
//
// Every method records its arguments before returning, so tests assert on what
// the command actually sent rather than on the canned return value. This is the
// only access-request mock: an arg-blind variant would silently opt future
// tests out of that.
//
// No mutex, deliberately — all five methods are invoked from strictly
// sequential command paths (cmd/request_{list,get,submit,cancel,finalize}.go
// and cmd/request_picker.go). Only the eligibility listers fan out across
// goroutines. `make test-race` guards the assumption.
type mockAccessRequestService struct {
	listItems      []wfmodels.AccessRequest
	listTotalCount int
	listErr        error
	getResult      *wfmodels.AccessRequest
	getErr         error
	submitResult   *wfmodels.AccessRequest
	submitErr      error
	cancelResult   *wfmodels.AccessRequest
	cancelErr      error
	finalizeResult *wfmodels.AccessRequest
	finalizeErr    error

	// Call histories. A history (rather than a single "last" field) is what
	// lets a test assert "called exactly once".
	listCalls     []workflows.ListRequestsParams
	getCalls      []string
	submitCalls   []wfmodels.SubmitAccessRequest
	cancelCalls   []cancelCall
	finalizeCalls []finalizeCall
}

func (m *mockAccessRequestService) ListRequests(_ context.Context, params workflows.ListRequestsParams) ([]wfmodels.AccessRequest, int, error) {
	m.listCalls = append(m.listCalls, params)
	return m.listItems, m.listTotalCount, m.listErr
}

func (m *mockAccessRequestService) GetRequest(_ context.Context, requestID string) (*wfmodels.AccessRequest, error) {
	m.getCalls = append(m.getCalls, requestID)
	return m.getResult, m.getErr
}

func (m *mockAccessRequestService) SubmitRequest(_ context.Context, req *wfmodels.SubmitAccessRequest) (*wfmodels.AccessRequest, error) {
	if req != nil {
		captured := *req
		captured.RequestDetails = make(map[string]interface{}, len(req.RequestDetails))
		for k, v := range req.RequestDetails {
			captured.RequestDetails[k] = v
		}
		m.submitCalls = append(m.submitCalls, captured)
	}
	return m.submitResult, m.submitErr
}

func (m *mockAccessRequestService) CancelRequest(_ context.Context, requestID string, reason *string) (*wfmodels.AccessRequest, error) {
	call := cancelCall{requestID: requestID}
	if reason != nil {
		call.reason, call.reasonSet = *reason, true
	}
	m.cancelCalls = append(m.cancelCalls, call)
	return m.cancelResult, m.cancelErr
}

func (m *mockAccessRequestService) FinalizeRequest(_ context.Context, requestID, decision string, reason *string) (*wfmodels.AccessRequest, error) {
	call := finalizeCall{requestID: requestID, decision: decision}
	if reason != nil {
		call.reason, call.reasonSet = *reason, true
	}
	m.finalizeCalls = append(m.finalizeCalls, call)
	return m.finalizeResult, m.finalizeErr
}

// lastListParams returns the most recent ListRequests params, or the zero value
// if ListRequests never ran.
func (m *mockAccessRequestService) lastListParams() workflows.ListRequestsParams {
	if len(m.listCalls) == 0 {
		return workflows.ListRequestsParams{}
	}
	return m.listCalls[len(m.listCalls)-1]
}

// lastSubmit returns the most recent submitted request, or nil if never called.
func (m *mockAccessRequestService) lastSubmit() *wfmodels.SubmitAccessRequest {
	if len(m.submitCalls) == 0 {
		return nil
	}
	return &m.submitCalls[len(m.submitCalls)-1]
}

// lastCancel returns the most recent cancel call, or nil if never called.
func (m *mockAccessRequestService) lastCancel() *cancelCall {
	if len(m.cancelCalls) == 0 {
		return nil
	}
	return &m.cancelCalls[len(m.cancelCalls)-1]
}

// lastFinalize returns the most recent finalize call, or nil if never called.
func (m *mockAccessRequestService) lastFinalize() *finalizeCall {
	if len(m.finalizeCalls) == 0 {
		return nil
	}
	return &m.finalizeCalls[len(m.finalizeCalls)-1]
}

// countingEligibilityLister wraps an eligibilityLister and counts calls per CSP.
// Thread-safe for concurrent access from goroutines in fetchStatusData etc.
type countingEligibilityLister struct {
	inner  eligibilityLister
	mu     sync.Mutex
	counts map[models.CSP]int
}

func newCountingEligibilityLister(inner eligibilityLister) *countingEligibilityLister {
	return &countingEligibilityLister{inner: inner, counts: make(map[models.CSP]int)}
}

func (c *countingEligibilityLister) ListEligibility(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
	c.mu.Lock()
	c.counts[csp]++
	c.mu.Unlock()
	return c.inner.ListEligibility(ctx, csp)
}

func (c *countingEligibilityLister) CallCount(csp models.CSP) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[csp]
}
