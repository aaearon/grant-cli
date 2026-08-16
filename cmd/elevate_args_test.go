package cmd

// Argument-capture and guard tests for the elevation paths (root, env,
// selection). Each test names the mutation it kills.
//
// Fixture IDs are deliberately distinct from one another — a swap mutation
// only dies when the two values differ. Do not collapse them.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// failingTargetSelector fails the test if interactive selection is reached.
func failingTargetSelector(t *testing.T) *mockTargetSelector {
	t.Helper()
	return &mockTargetSelector{
		selectFunc: func([]models.EligibleTarget) (*models.EligibleTarget, error) {
			t.Error("interactive target selection must not be reached")
			return nil, errors.New("selector must not be called")
		},
	}
}

// awsFixtureTarget is the single eligible target used by the env tests.
func awsFixtureTarget() models.EligibleTarget {
	return models.EligibleTarget{
		OrganizationID: "o-env-1",
		WorkspaceID:    "111122223333",
		WorkspaceName:  "AWS Mgmt",
		WorkspaceType:  models.WorkspaceTypeAccount,
		RoleInfo:       models.RoleInfo{ID: "role-env-9", Name: "AdminAccess"},
	}
}

const envCredsJSON = `{"aws_access_key":"ASIAENV","aws_secret_access_key":"env-secret","aws_session_token":"env-token"}`

func awsFixtureElevator() *mockElevateService {
	return &mockElevateService{
		elevateFunc: func(_ context.Context, _ *models.ElevateRequest) (*models.ElevateResponse, error) {
			creds := envCredsJSON
			return &models.ElevateResponse{Response: models.ElevateAccessResult{
				CSP:            models.CSPAWS,
				OrganizationID: "o-env-1",
				Results: []models.ElevateTargetResult{{
					WorkspaceID: "111122223333", RoleID: "role-env-9",
					SessionID: "sess-env-1", AccessCredentials: &creds,
				}},
			}}, nil
		},
	}
}

func awsFixtureLister() *mockEligibilityLister {
	return &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{awsFixtureTarget()},
			Total:    1,
		},
	}
}

func authedLoader() *mockAuthLoader {
	return &mockAuthLoader{token: &authmodels.IdsecToken{Token: "test-jwt"}}
}

// TestFindItemByDisplay_ReturnsMatchingItem kills ELV-01: returning
// &items[0] instead of &items[i] at cmd/selection.go:78. The existing test only
// asserts the result is non-nil, so it never notices that the wrong target
// would be elevated under a display line naming the right one.
func TestFindItemByDisplay_ReturnsMatchingItem(t *testing.T) {
	first := &models.EligibleTarget{
		WorkspaceName: "Aardvark-Sub",
		WorkspaceType: models.WorkspaceTypeSubscription,
		RoleInfo:      models.RoleInfo{ID: "role-first", Name: "Reader"},
	}
	second := &models.EligibleTarget{
		WorkspaceName: "Zulu-Sub",
		WorkspaceType: models.WorkspaceTypeSubscription,
		RoleInfo:      models.RoleInfo{ID: "role-second", Name: "Owner"},
	}
	group := &models.GroupsEligibleTarget{DirectoryName: "Contoso", GroupName: "Engineering"}

	items := []selectionItem{
		{kind: selectionCloud, cloud: first},
		{kind: selectionCloud, cloud: second},
		{kind: selectionGroup, group: group},
	}

	got, err := findItemByDisplay(items, formatSelectionItem(items[1]))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.cloud != second {
		t.Errorf("got workspace %q (role %q), want Zulu-Sub / role-second",
			got.cloud.WorkspaceName, got.cloud.RoleInfo.ID)
	}

	gotGroup, err := findItemByDisplay(items, formatSelectionItem(items[2]))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotGroup.kind != selectionGroup || gotGroup.group != group {
		t.Errorf("got %+v, want the group item", gotGroup)
	}
}

// TestElevateCloud_RequestPayload kills ELV-02 and ELV-03: swapping
// WorkspaceID/RoleID, or blanking CSP/OrganizationID, in the elevateCloud
// request builder in elevateCloud (cmd/root.go).
func TestElevateCloud_RequestPayload(t *testing.T) {
	target := &models.EligibleTarget{
		CSP:            models.CSPAWS,
		OrganizationID: "o-cloud-77",
		WorkspaceID:    "ws-cloud-A",
		WorkspaceName:  "AWS Sandbox",
		RoleInfo:       models.RoleInfo{ID: "role-cloud-B", Name: "ReadOnly"},
	}
	elevator := &mockElevateService{
		response: &models.ElevateResponse{Response: models.ElevateAccessResult{
			CSP:     models.CSPAWS,
			Results: []models.ElevateTargetResult{{SessionID: "sess-1"}},
		}},
	}

	if _, _, err := elevateCloud(t.Context(), target, elevator); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertElevateRequest(t, elevator, models.CSPAWS, "o-cloud-77", "ws-cloud-A", "role-cloud-B")
}

// TestResolveAndElevate_RequestPayload kills ELV-04: the same swap in the
// second, byte-identical builder in resolveAndElevate, used by grant env.
//
// The duplication between the two builders is real; extracting a shared helper
// is a refactor and is filed as follow-up, not done here.
func TestResolveAndElevate_RequestPayload(t *testing.T) {
	target := models.EligibleTarget{
		CSP:            models.CSPAWS,
		OrganizationID: "o-env-88",
		WorkspaceID:    "ws-env-A",
		WorkspaceName:  "AWS Mgmt",
		WorkspaceType:  models.WorkspaceTypeAccount,
		RoleInfo:       models.RoleInfo{ID: "role-env-B", Name: "AdminAccess"},
	}
	lister := &mockEligibilityLister{
		response: &models.EligibilityResponse{Response: []models.EligibleTarget{target}, Total: 1},
	}
	creds := envCredsJSON
	elevator := &mockElevateService{
		response: &models.ElevateResponse{Response: models.ElevateAccessResult{
			CSP: models.CSPAWS,
			Results: []models.ElevateTargetResult{{
				SessionID: "sess-env", AccessCredentials: &creds,
			}},
		}},
	}

	flags := &elevateFlags{provider: "aws", target: "AWS Mgmt", role: "AdminAccess"}
	if _, err := resolveAndElevate(flags, nil, authedLoader(), lister, elevator,
		failingTargetSelector(t), config.DefaultConfig(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertElevateRequest(t, elevator, models.CSPAWS, "o-env-88", "ws-env-A", "role-env-B")
}

func assertElevateRequest(t *testing.T, elevator *mockElevateService, csp models.CSP, orgID, workspaceID, roleID string) {
	t.Helper()
	if len(elevator.elevateCalls) != 1 {
		t.Fatalf("expected exactly 1 Elevate call, got %d", len(elevator.elevateCalls))
	}
	req := elevator.lastElevate()
	if req.CSP != csp {
		t.Errorf("CSP = %q, want %q", req.CSP, csp)
	}
	if req.OrganizationID != orgID {
		t.Errorf("OrganizationID = %q, want %q", req.OrganizationID, orgID)
	}
	if len(req.Targets) != 1 {
		t.Fatalf("expected 1 target in the request, got %d", len(req.Targets))
	}
	if req.Targets[0].WorkspaceID != workspaceID {
		t.Errorf("Targets[0].WorkspaceID = %q, want %q", req.Targets[0].WorkspaceID, workspaceID)
	}
	if req.Targets[0].RoleID != roleID {
		t.Errorf("Targets[0].RoleID = %q, want %q", req.Targets[0].RoleID, roleID)
	}
}

// envConfigWithFavorites builds a config carrying the named favorites.
func envConfigWithFavorites(favs map[string]config.Favorite) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Favorites = favs
	return cfg
}

// TestEnv_FavoriteMode kills ELV-05: the `--favorite` branch in
// resolveAndElevate (cmd/root.go) is registered and advertised by grant env
// but was exercised by no test at all.
func TestEnv_FavoriteMode(t *testing.T) {
	elevator := awsFixtureElevator()
	cfg := envConfigWithFavorites(map[string]config.Favorite{
		"aws-fav": {Provider: "aws", Target: "AWS Mgmt", Role: "AdminAccess"},
	})

	cmd := NewEnvCommandWithDeps(nil, authedLoader(), awsFixtureLister(), elevator, failingTargetSelector(t), cfg)
	output, err := executeCommand(cmd, "--favorite", "aws-fav")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}
	if !strings.Contains(output, "export AWS_ACCESS_KEY_ID='ASIAENV'") {
		t.Errorf("expected AWS exports from the favorite, got:\n%s", output)
	}
	assertElevateRequest(t, elevator, models.CSPAWS, "o-env-1", "111122223333", "role-env-9")
}

// TestEnv_RejectsGroupFavorite kills ELV-06: the group-favorite rejection in
// resolveAndElevate's --favorite branch (cmd/root.go).
func TestEnv_RejectsGroupFavorite(t *testing.T) {
	elevator := awsFixtureElevator()
	cfg := envConfigWithFavorites(map[string]config.Favorite{
		"grp-fav": {Type: config.FavoriteTypeGroups, Provider: "azure", Group: "Cloud Admins"},
	})

	cmd := NewEnvCommandWithDeps(nil, authedLoader(), awsFixtureLister(), elevator, failingTargetSelector(t), cfg)
	_, err := executeCommand(cmd, "--favorite", "grp-fav")
	if err == nil {
		t.Fatal("expected a group favorite to be rejected")
	}
	if !strings.Contains(err.Error(), "is a group favorite") {
		t.Errorf("error = %v, want the group-favorite rejection", err)
	}
	if len(elevator.elevateCalls) != 0 {
		t.Errorf("no elevation may be issued, got %+v", elevator.elevateCalls)
	}
}

// TestEnv_FavoriteProviderMismatch kills ELV-07: the provider-mismatch check in
// resolveAndElevate's --favorite branch (cmd/root.go).
func TestEnv_FavoriteProviderMismatch(t *testing.T) {
	elevator := awsFixtureElevator()
	cfg := envConfigWithFavorites(map[string]config.Favorite{
		"aws-fav": {Provider: "aws", Target: "AWS Mgmt", Role: "AdminAccess"},
	})

	cmd := NewEnvCommandWithDeps(nil, authedLoader(), awsFixtureLister(), elevator, failingTargetSelector(t), cfg)
	_, err := executeCommand(cmd, "--favorite", "aws-fav", "--provider", "azure")
	if err == nil {
		t.Fatal("expected a provider mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "does not match favorite provider") {
		t.Errorf("error = %v, want the provider-mismatch rejection", err)
	}
	if len(elevator.elevateCalls) != 0 {
		t.Errorf("no elevation may be issued, got %+v", elevator.elevateCalls)
	}
}

// TestEnv_RequiresBothTargetAndRole kills ELV-08: the paired --target/--role
// validation in resolveAndElevate (cmd/root.go).
func TestEnv_RequiresBothTargetAndRole(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "target without role", args: []string{"--provider", "aws", "--target", "AWS Mgmt"}},
		{name: "role without target", args: []string{"--provider", "aws", "--role", "AdminAccess"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elevator := awsFixtureElevator()
			cmd := NewEnvCommandWithDeps(nil, authedLoader(), awsFixtureLister(), elevator,
				failingTargetSelector(t), config.DefaultConfig())

			_, err := executeCommand(cmd, tt.args...)
			if err == nil {
				t.Fatal("expected an error when only one of --target/--role is given")
			}
			if !strings.Contains(err.Error(), "both --target and --role must be provided") {
				t.Errorf("error = %v, want the paired-flag validation", err)
			}
			if len(elevator.elevateCalls) != 0 {
				t.Errorf("no elevation may be issued, got %+v", elevator.elevateCalls)
			}
		})
	}
}

// TestResolveFavoriteFlags_DetectsGroupFavorite kills ELV-09: the group
// detection in resolveFavoriteFlags (cmd/root.go), which is the root
// command's equivalent of the env check above and is separately unpinned.
func TestResolveFavoriteFlags_DetectsGroupFavorite(t *testing.T) {
	cfg := envConfigWithFavorites(map[string]config.Favorite{
		"grp-fav": {
			Type: config.FavoriteTypeGroups, Provider: "azure",
			Group: "Cloud Admins", DirectoryID: "dir-abc",
		},
	})

	flags := &elevateFlags{favorite: "grp-fav"}
	rf, err := resolveFavoriteFlags(flags, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rf.isGroupFavorite {
		t.Error("isGroupFavorite = false, want true")
	}
	if flags.group != "Cloud Admins" {
		t.Errorf("flags.group = %q, want Cloud Admins", flags.group)
	}
	if rf.favDirectoryID != "dir-abc" {
		t.Errorf("favDirectoryID = %q, want dir-abc", rf.favDirectoryID)
	}
	if rf.targetName != "" || rf.roleName != "" {
		t.Errorf("a group favorite must not populate target/role, got %q/%q", rf.targetName, rf.roleName)
	}
}

// TestElevateGroup_SurfacesErrorInfo kills ELV-10: dropping the ErrorInfo check
// in elevateGroup (cmd/root.go) makes a policy denial print as a success
// and exit 0.
func TestElevateGroup_SurfacesErrorInfo(t *testing.T) {
	elevator := &mockGroupsElevator{
		response: &models.GroupsElevateResponse{
			DirectoryID: "dir-1",
			CSP:         models.CSPAzure,
			Results: []models.GroupsElevateTargetResult{{
				GroupID: "grp-1",
				ErrorInfo: &models.ErrorInfo{
					Code:        "POLICY_DENIED",
					Message:     "elevation denied by policy",
					Description: "no matching policy",
				},
			}},
		},
	}

	_, _, err := elevateGroup(t.Context(), &models.GroupsEligibleTarget{
		DirectoryID: "dir-1", GroupID: "grp-1", GroupName: "Cloud Admins",
	}, elevator)
	if err == nil {
		t.Fatal("a denied group elevation must not be reported as success")
	}
	if !strings.Contains(err.Error(), "POLICY_DENIED") || !strings.Contains(err.Error(), "elevation denied by policy") {
		t.Errorf("error = %v, want the ErrorInfo code and message", err)
	}
}

// TestEnv_SurfacesErrorInfo kills ELV-11: the same check on the env path, in
// resolveAndElevate (cmd/root.go).
func TestEnv_SurfacesErrorInfo(t *testing.T) {
	// Credentials are present alongside the error so that dropping the guard
	// produces the real false-success — exports printed, exit 0 — rather than
	// tripping the downstream "no credentials" fallback.
	creds := envCredsJSON
	elevator := &mockElevateService{
		response: &models.ElevateResponse{Response: models.ElevateAccessResult{
			CSP: models.CSPAWS,
			Results: []models.ElevateTargetResult{{
				WorkspaceID:       "111122223333",
				AccessCredentials: &creds,
				ErrorInfo: &models.ErrorInfo{
					Code:        "POLICY_DENIED",
					Message:     "elevation denied by policy",
					Description: "no matching policy",
				},
			}},
		}},
	}

	cmd := NewEnvCommandWithDeps(nil, authedLoader(), awsFixtureLister(), elevator,
		failingTargetSelector(t), config.DefaultConfig())
	output, _, err := executeCommandStreams(cmd, "--provider", "aws", "--target", "AWS Mgmt", "--role", "AdminAccess")
	if err == nil {
		t.Fatal("a denied elevation must not be reported as success")
	}
	if !strings.Contains(err.Error(), "POLICY_DENIED") {
		t.Errorf("error = %v, want the ErrorInfo code", err)
	}
	if strings.Contains(output, "export AWS_") {
		t.Errorf("no credentials may be printed on a denied elevation, got:\n%s", output)
	}
}

// TestElevate_EmptyResultsGuards kills ELV-12, ELV-13 and ELV-14: all three
// "no results returned" guards. Without them the next line indexes Results[0]
// and panics.
func TestElevate_EmptyResultsGuards(t *testing.T) {
	t.Run("elevateCloud", func(t *testing.T) {
		elevator := &mockElevateService{
			response: &models.ElevateResponse{Response: models.ElevateAccessResult{
				CSP: models.CSPAzure, Results: nil,
			}},
		}
		_, _, err := elevateCloud(t.Context(), &models.EligibleTarget{CSP: models.CSPAzure}, elevator)
		if err == nil {
			t.Fatal("expected an error for an empty results list")
		}
		if !strings.Contains(err.Error(), "no results returned") {
			t.Errorf("error = %v, want 'no results returned'", err)
		}
	})

	t.Run("elevateGroup", func(t *testing.T) {
		elevator := &mockGroupsElevator{
			response: &models.GroupsElevateResponse{DirectoryID: "dir-1", Results: nil},
		}
		_, _, err := elevateGroup(t.Context(), &models.GroupsEligibleTarget{
			DirectoryID: "dir-1", GroupID: "grp-1",
		}, elevator)
		if err == nil {
			t.Fatal("expected an error for an empty results list")
		}
		if !strings.Contains(err.Error(), "no results returned") {
			t.Errorf("error = %v, want 'no results returned'", err)
		}
	})

	t.Run("env path", func(t *testing.T) {
		elevator := &mockElevateService{
			response: &models.ElevateResponse{Response: models.ElevateAccessResult{
				CSP: models.CSPAWS, Results: nil,
			}},
		}
		cmd := NewEnvCommandWithDeps(nil, authedLoader(), awsFixtureLister(), elevator,
			failingTargetSelector(t), config.DefaultConfig())
		_, err := executeCommand(cmd, "--provider", "aws", "--target", "AWS Mgmt", "--role", "AdminAccess")
		if err == nil {
			t.Fatal("expected an error for an empty results list")
		}
		if !strings.Contains(err.Error(), "no results returned") {
			t.Errorf("error = %v, want 'no results returned'", err)
		}
	})
}

// TestFetchEligibility_AllCSPsFail kills ELV-19: the aggregate guard at
// the end of fetchEligibility's multi-CSP branch (cmd/root.go). Without it a
// total multi-CSP failure returns (nil, nil) and
// each caller substitutes its own, less accurate message.
func TestFetchEligibility_AllCSPsFail(t *testing.T) {
	lister := &mockEligibilityLister{
		listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
			return nil, errors.New(string(csp) + " is down")
		},
	}

	targets, err := fetchEligibility(t.Context(), lister, "")
	if err == nil {
		t.Fatal("expected an error when every CSP fails")
	}
	if !strings.Contains(err.Error(), "no eligible targets found, check your SCA policies") {
		t.Errorf("error = %v, want the aggregate SCA-policy message", err)
	}
	if targets != nil {
		t.Errorf("expected no targets, got %+v", targets)
	}
}

// TestEnv_SlowPromptTimeout kills ELV-20: elevating on the original ctx rather
// than a fresh one, in resolveAndElevate (cmd/root.go). A user who takes
// longer than apiTimeout
// to pick a target would get a deadline error instead of an elevation. Root's
// three dispatch paths have this coverage; env did not.
func TestEnv_SlowPromptTimeout(t *testing.T) {
	origTimeout := apiTimeout
	apiTimeout = 50 * time.Millisecond
	t.Cleanup(func() { apiTimeout = origTimeout })

	slowSelector := &mockTargetSelector{
		selectFunc: func(targets []models.EligibleTarget) (*models.EligibleTarget, error) {
			time.Sleep(100 * time.Millisecond) // 2x apiTimeout
			return &targets[0], nil
		},
	}

	contextAware := &mockElevateService{
		elevateFunc: func(ctx context.Context, _ *models.ElevateRequest) (*models.ElevateResponse, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			creds := envCredsJSON
			return &models.ElevateResponse{Response: models.ElevateAccessResult{
				CSP: models.CSPAWS,
				Results: []models.ElevateTargetResult{{
					SessionID: "sess-slow", AccessCredentials: &creds,
				}},
			}}, nil
		},
	}

	cmd := NewEnvCommandWithDeps(nil, authedLoader(), awsFixtureLister(), contextAware,
		slowSelector, config.DefaultConfig())
	output, err := executeCommand(cmd, "--provider", "aws")
	if err != nil {
		t.Fatalf("elevation should succeed after a slow prompt, got: %v", err)
	}
	if !strings.Contains(output, "export AWS_ACCESS_KEY_ID='ASIAENV'") {
		t.Errorf("unexpected output:\n%s", output)
	}
}

// TestAuthCacheFlag kills ELV-21 and ELV-22: both elevation paths must load
// authentication with cacheAuthentication=true, otherwise every invocation
// re-authenticates instead of reusing the cached token.
func TestAuthCacheFlag(t *testing.T) {
	t.Run("env path", func(t *testing.T) {
		var got []bool
		loader := &mockAuthLoader{
			loadFunc: func(_ *sdkmodels.IdsecProfile, cacheAuthentication bool) (*authmodels.IdsecToken, error) {
				got = append(got, cacheAuthentication)
				return &authmodels.IdsecToken{Token: "test-jwt"}, nil
			},
		}

		cmd := NewEnvCommandWithDeps(nil, loader, awsFixtureLister(), awsFixtureElevator(),
			failingTargetSelector(t), config.DefaultConfig())
		if _, err := executeCommand(cmd, "--provider", "aws", "--target", "AWS Mgmt", "--role", "AdminAccess"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertCachedAuth(t, got)
	})

	t.Run("root path", func(t *testing.T) {
		var got []bool
		loader := &mockAuthLoader{
			loadFunc: func(_ *sdkmodels.IdsecProfile, cacheAuthentication bool) (*authmodels.IdsecToken, error) {
				got = append(got, cacheAuthentication)
				return &authmodels.IdsecToken{Token: "test-jwt"}, nil
			},
		}
		elevator := &mockElevateService{
			response: &models.ElevateResponse{Response: models.ElevateAccessResult{
				CSP:     models.CSPAWS,
				Results: []models.ElevateTargetResult{{SessionID: "sess-root"}},
			}},
		}

		cmd := NewRootCommandWithDeps(nil, loader, awsFixtureLister(), elevator, nil,
			&mockGroupsEligibilityLister{response: &models.GroupsEligibilityResponse{}}, nil, config.DefaultConfig())
		if _, err := executeCommand(cmd, "--provider", "aws", "--target", "AWS Mgmt", "--role", "AdminAccess"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertCachedAuth(t, got)
	})
}

func assertCachedAuth(t *testing.T, got []bool) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 LoadAuthentication call, got %d", len(got))
	}
	if !got[0] {
		t.Error("cacheAuthentication = false, want true")
	}
}

// TestEnv_SelectorReceivesAllTargets kills ELV-23: passing nil (or anything
// else) to SelectTarget in resolveAndElevate (cmd/root.go). mockTargetSelector
// returns its
// canned target without looking at the slice, so nothing else notices.
func TestEnv_SelectorReceivesAllTargets(t *testing.T) {
	second := models.EligibleTarget{
		OrganizationID: "o-env-1",
		WorkspaceID:    "444455556666",
		WorkspaceName:  "AWS Sandbox",
		WorkspaceType:  models.WorkspaceTypeAccount,
		RoleInfo:       models.RoleInfo{ID: "role-env-2", Name: "ReadOnly"},
	}
	lister := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{awsFixtureTarget(), second},
			Total:    2,
		},
	}

	var offered []models.EligibleTarget
	selector := &mockTargetSelector{
		selectFunc: func(targets []models.EligibleTarget) (*models.EligibleTarget, error) {
			offered = append([]models.EligibleTarget(nil), targets...)
			if len(targets) == 0 {
				// Report rather than panic, so a mutation that passes nil
				// fails with a readable message.
				return nil, errors.New("selector received no targets")
			}
			return &targets[0], nil
		},
	}

	cmd := NewEnvCommandWithDeps(nil, authedLoader(), lister, awsFixtureElevator(), selector, config.DefaultConfig())
	if _, err := executeCommand(cmd, "--provider", "aws"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(offered) != 2 {
		t.Fatalf("selector received %d targets, want the 2 fetched", len(offered))
	}
	if offered[0].WorkspaceID != "111122223333" || offered[1].WorkspaceID != "444455556666" {
		t.Errorf("selector received %q/%q, want the fetched workspace IDs",
			offered[0].WorkspaceID, offered[1].WorkspaceID)
	}
}

// TestExecute_VerboseHintCondition kills ELV-24: inverting the hint condition
// at cmd/root.go. The pre-existing test reconstructs the logic in the test
// body, so it cannot see the production condition change; this asserts the
// extracted predicate that Execute() actually calls.
func TestExecute_VerboseHintCondition(t *testing.T) {
	tests := []struct {
		name                string
		verboseOn           bool
		argValidationPassed bool
		want                bool
	}{
		{name: "runtime error, verbose off", argValidationPassed: true, want: true},
		{name: "runtime error, verbose on", verboseOn: true, argValidationPassed: true, want: false},
		{name: "arg error, verbose off", want: false},
		{name: "arg error, verbose on", verboseOn: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldShowVerboseHint(tt.verboseOn, tt.argValidationPassed); got != tt.want {
				t.Errorf("shouldShowVerboseHint(%v, %v) = %v, want %v",
					tt.verboseOn, tt.argValidationPassed, got, tt.want)
			}
		})
	}
}

// TestRootElevate_GroupAndGroupsPrecedence kills ELV-25: --group and --groups
// are not mutually exclusive, so their dispatch order in
// resolveAndElevateUnified (cmd/root.go) is a
// real, user-visible policy. --group names a specific group and must win over
// the --groups interactive filter.
func TestRootElevate_GroupAndGroupsPrecedence(t *testing.T) {
	groupsLister := &mockGroupsEligibilityLister{
		response: &models.GroupsEligibilityResponse{
			Response: []models.GroupsEligibleTarget{
				{DirectoryID: "dir-1", GroupID: "grp-admins", GroupName: "Cloud Admins"},
				{DirectoryID: "dir-1", GroupID: "grp-readers", GroupName: "Cloud Readers"},
			},
			Total: 2,
		},
	}
	elevator := &mockGroupsElevator{
		response: &models.GroupsElevateResponse{
			DirectoryID: "dir-1",
			CSP:         models.CSPAzure,
			Results:     []models.GroupsElevateTargetResult{{GroupID: "grp-admins", SessionID: "sess-grp"}},
		},
	}
	selector := &mockUnifiedSelector{
		selectFunc: func([]selectionItem) (*selectionItem, error) {
			t.Error("--group must not fall through to the --groups interactive selector")
			return nil, errors.New("selector must not be called")
		},
	}

	cmd := NewRootCommandWithDeps(nil, authedLoader(), &mockEligibilityLister{
		response: &models.EligibilityResponse{},
	}, nil, selector, groupsLister, elevator, config.DefaultConfig())

	output, err := executeCommand(cmd, "--group", "Cloud Admins", "--groups")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	req := elevator.lastElevateGroups()
	if req == nil {
		t.Fatal("ElevateGroups was never called")
	}
	if len(req.Targets) != 1 || req.Targets[0].GroupID != "grp-admins" {
		t.Errorf("elevated %+v, want the group named by --group", req.Targets)
	}
	// Also pins the DirectoryID on the group elevate request.
	if req.DirectoryID != "dir-1" {
		t.Errorf("DirectoryID = %q, want dir-1", req.DirectoryID)
	}
}

// TestElevateGroup_RequestPayload pins the group elevation request body,
// including the DirectoryID that a blanking mutation would drop.
func TestElevateGroup_RequestPayload(t *testing.T) {
	elevator := &mockGroupsElevator{
		response: &models.GroupsElevateResponse{
			DirectoryID: "dir-payload",
			Results:     []models.GroupsElevateTargetResult{{GroupID: "grp-payload", SessionID: "sess-1"}},
		},
	}

	if _, _, err := elevateGroup(t.Context(), &models.GroupsEligibleTarget{
		DirectoryID: "dir-payload", GroupID: "grp-payload", GroupName: "Cloud Admins",
	}, elevator); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := elevator.lastElevateGroups()
	if req == nil {
		t.Fatal("ElevateGroups was never called")
	}
	if req.DirectoryID != "dir-payload" {
		t.Errorf("DirectoryID = %q, want dir-payload", req.DirectoryID)
	}
	if req.CSP != models.CSPAzure {
		t.Errorf("CSP = %q, want AZURE", req.CSP)
	}
	if len(req.Targets) != 1 || req.Targets[0].GroupID != "grp-payload" {
		t.Errorf("Targets = %+v, want the selected group", req.Targets)
	}
}
