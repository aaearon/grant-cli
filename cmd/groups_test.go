// NOTE: Do not use t.Parallel() in cmd/ tests due to package-level state
// (verbose, passedArgValidation) that is mutated during test execution.
package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/config"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func TestGroupsCommand(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	// newEligibleGroups returns a fresh copy to avoid mutation bleeding between tests
	// (runGroups sets DirectoryName in-place on the response slice).
	newEligibleGroups := func() *scamodels.GroupsEligibilityResponse {
		return &scamodels.GroupsEligibilityResponse{
			Response: []scamodels.GroupsEligibleTarget{
				{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
				{DirectoryID: "dir1", GroupID: "grp2", GroupName: "DevOps"},
			},
			Total: 2,
		}
	}

	// Cloud eligibility with DIRECTORY-type entry for name resolution
	cloudEligWithDir := &scamodels.EligibilityResponse{
		Response: []scamodels.EligibleTarget{
			{
				OrganizationID: "dir1",
				WorkspaceID:    "dir1",
				WorkspaceName:  "Contoso",
				WorkspaceType:  scamodels.WorkspaceTypeDirectory,
			},
		},
		Total: 1,
	}

	// Empty cloud eligibility (graceful degradation)
	emptyCloudElig := &scamodels.EligibilityResponse{Response: []scamodels.EligibleTarget{}, Total: 0}

	tests := []struct {
		name           string
		args           []string
		setupAuth      func() *mockAuthLoader
		setupCloudElig func() *mockEligibilityLister
		setupElig      func() *mockGroupsEligibilityLister
		setupElevator  func() *mockGroupsElevator
		setupSelector  func() *mockGroupSelector
		wantContain    []string
		wantErr        bool
	}{
		{
			name: "not authenticated",
			args: []string{},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{loadErr: errNotAuthenticated}
			},
			setupCloudElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupElig:      func() *mockGroupsEligibilityLister { return &mockGroupsEligibilityLister{} },
			setupElevator:  func() *mockGroupsElevator { return &mockGroupsElevator{} },
			setupSelector:  func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:    []string{"not authenticated"},
			wantErr:        true,
		},
		{
			name: "no eligible groups",
			args: []string{},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: emptyCloudElig}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{
					response: &scamodels.GroupsEligibilityResponse{Response: []scamodels.GroupsEligibleTarget{}, Total: 0},
				}
			},
			setupElevator: func() *mockGroupsElevator { return &mockGroupsElevator{} },
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"no eligible groups"},
			wantErr:       true,
		},
		{
			name: "interactive mode - success with directory name",
			args: []string{},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: cloudEligWithDir}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{response: newEligibleGroups()}
			},
			setupElevator: func() *mockGroupsElevator {
				return &mockGroupsElevator{
					response: &scamodels.GroupsElevateResponse{
						DirectoryID: "dir1",
						CSP:         scamodels.CSPAzure,
						Results: []scamodels.GroupsElevateTargetResult{
							{GroupID: "grp1", SessionID: "sess1"},
						},
					},
				}
			},
			setupSelector: func() *mockGroupSelector {
				return &mockGroupSelector{
					group: &scamodels.GroupsEligibleTarget{DirectoryID: "dir1", DirectoryName: "Contoso", GroupID: "grp1", GroupName: "Engineering"},
				}
			},
			wantContain: []string{"Elevated to group Engineering in Contoso", "Session ID: sess1"},
			wantErr:     false,
		},
		{
			name: "success without directory name (graceful degradation)",
			args: []string{"--group", "Engineering"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{listErr: errors.New("cloud eligibility unavailable")}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{response: newEligibleGroups()}
			},
			setupElevator: func() *mockGroupsElevator {
				return &mockGroupsElevator{
					response: &scamodels.GroupsElevateResponse{
						DirectoryID: "dir1",
						CSP:         scamodels.CSPAzure,
						Results: []scamodels.GroupsElevateTargetResult{
							{GroupID: "grp1", SessionID: "sess1"},
						},
					},
				}
			},
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"Elevated to group Engineering\n"},
			wantErr:       false,
		},
		{
			name: "direct mode with --group flag",
			args: []string{"--group", "Engineering"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: cloudEligWithDir}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{response: newEligibleGroups()}
			},
			setupElevator: func() *mockGroupsElevator {
				return &mockGroupsElevator{
					elevateFunc: func(ctx context.Context, req *scamodels.GroupsElevateRequest) (*scamodels.GroupsElevateResponse, error) {
						if req.Targets[0].GroupID != "grp1" {
							t.Errorf("expected group ID grp1, got %s", req.Targets[0].GroupID)
						}
						if req.DirectoryID != "dir1" {
							t.Errorf("expected directory ID dir1, got %s", req.DirectoryID)
						}
						return &scamodels.GroupsElevateResponse{
							DirectoryID: "dir1",
							CSP:         scamodels.CSPAzure,
							Results: []scamodels.GroupsElevateTargetResult{
								{GroupID: "grp1", SessionID: "sess1"},
							},
						}, nil
					},
				}
			},
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"Elevated to group Engineering in Contoso", "Session ID: sess1"},
			wantErr:       false,
		},
		{
			name: "direct mode - group not found",
			args: []string{"--group", "NonExistent"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: emptyCloudElig}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{response: newEligibleGroups()}
			},
			setupElevator: func() *mockGroupsElevator { return &mockGroupsElevator{} },
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"group \"NonExistent\" not found"},
			wantErr:       true,
		},
		{
			name: "direct mode - case insensitive match",
			args: []string{"--group", "engineering"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: emptyCloudElig}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{response: newEligibleGroups()}
			},
			setupElevator: func() *mockGroupsElevator {
				return &mockGroupsElevator{
					response: &scamodels.GroupsElevateResponse{
						DirectoryID: "dir1",
						CSP:         scamodels.CSPAzure,
						Results: []scamodels.GroupsElevateTargetResult{
							{GroupID: "grp1", SessionID: "sess1"},
						},
					},
				}
			},
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"Elevated to group Engineering"},
			wantErr:       false,
		},
		{
			name: "elevation error in result",
			args: []string{"--group", "Engineering"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: emptyCloudElig}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{response: newEligibleGroups()}
			},
			setupElevator: func() *mockGroupsElevator {
				return &mockGroupsElevator{
					response: &scamodels.GroupsElevateResponse{
						DirectoryID: "dir1",
						CSP:         scamodels.CSPAzure,
						Results: []scamodels.GroupsElevateTargetResult{
							{
								GroupID:   "grp1",
								SessionID: "",
								ErrorInfo: &scamodels.ErrorInfo{
									Code:        "ERR_INELIGIBLE",
									Message:     "Not eligible",
									Description: "User not eligible",
								},
							},
						},
					},
				}
			},
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"elevation failed", "ERR_INELIGIBLE", "Not eligible"},
			wantErr:       true,
		},
		{
			name: "eligibility API error",
			args: []string{},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: emptyCloudElig}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{listErr: errors.New("service unavailable")}
			},
			setupElevator: func() *mockGroupsElevator { return &mockGroupsElevator{} },
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"failed to fetch eligible groups"},
			wantErr:       true,
		},
		{
			name: "elevation API error",
			args: []string{"--group", "Engineering"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: emptyCloudElig}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{response: newEligibleGroups()}
			},
			setupElevator: func() *mockGroupsElevator {
				return &mockGroupsElevator{elevateErr: errors.New("API error: forbidden")}
			},
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"elevation request failed"},
			wantErr:       true,
		},
		{
			name: "interactive mode - selection error",
			args: []string{},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: emptyCloudElig}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{response: newEligibleGroups()}
			},
			setupElevator: func() *mockGroupsElevator { return &mockGroupsElevator{} },
			setupSelector: func() *mockGroupSelector {
				return &mockGroupSelector{selectErr: errors.New("prompt interrupted")}
			},
			wantContain: []string{"group selection failed"},
			wantErr:     true,
		},
		{
			name: "elevation returns no results",
			args: []string{"--group", "Engineering"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: emptyCloudElig}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{response: newEligibleGroups()}
			},
			setupElevator: func() *mockGroupsElevator {
				return &mockGroupsElevator{
					response: &scamodels.GroupsElevateResponse{
						DirectoryID: "dir1",
						CSP:         scamodels.CSPAzure,
						Results:     []scamodels.GroupsElevateTargetResult{},
					},
				}
			},
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"no results returned"},
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := tt.setupAuth()
			cloudElig := tt.setupCloudElig()
			elig := tt.setupElig()
			elevator := tt.setupElevator()
			selector := tt.setupSelector()

			cmd := NewGroupsCommandWithDeps(auth, cloudElig, elig, elevator, selector)
			output, err := executeCommand(cmd, tt.args...)

			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestGroupsCommandFavoriteMode(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	tests := []struct {
		name           string
		args           []string
		cfg            *config.Config
		setupAuth      func() *mockAuthLoader
		setupCloudElig func() *mockEligibilityLister
		setupElig      func() *mockGroupsEligibilityLister
		setupElevator  func() *mockGroupsElevator
		setupSelector  func() *mockGroupSelector
		wantContain    []string
		wantErr        bool
	}{
		{
			name: "favorite mode - success",
			args: []string{"--favorite", "my-grp"},
			cfg: func() *config.Config {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "my-grp", config.Favorite{
					Type:        config.FavoriteTypeGroups,
					Provider:    "azure",
					Group:       "Engineering",
					DirectoryID: "dir1",
				})
				return cfg
			}(),
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister {
				return &mockEligibilityLister{response: &scamodels.EligibilityResponse{Response: []scamodels.EligibleTarget{}}}
			},
			setupElig: func() *mockGroupsEligibilityLister {
				return &mockGroupsEligibilityLister{
					response: &scamodels.GroupsEligibilityResponse{
						Response: []scamodels.GroupsEligibleTarget{
							{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
						},
						Total: 1,
					},
				}
			},
			setupElevator: func() *mockGroupsElevator {
				return &mockGroupsElevator{
					response: &scamodels.GroupsElevateResponse{
						DirectoryID: "dir1",
						CSP:         scamodels.CSPAzure,
						Results: []scamodels.GroupsElevateTargetResult{
							{GroupID: "grp1", SessionID: "sess1"},
						},
					},
				}
			},
			setupSelector: func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:   []string{"Elevated to group Engineering", "Session ID: sess1"},
			wantErr:       false,
		},
		{
			name: "favorite not found",
			args: []string{"--favorite", "nonexistent"},
			cfg:  config.DefaultConfig(),
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupElig:      func() *mockGroupsEligibilityLister { return &mockGroupsEligibilityLister{} },
			setupElevator:  func() *mockGroupsElevator { return &mockGroupsElevator{} },
			setupSelector:  func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:    []string{"not found"},
			wantErr:        true,
		},
		{
			name: "cloud favorite is rejected",
			args: []string{"--favorite", "cloud-fav"},
			cfg: func() *config.Config {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "cloud-fav", config.Favorite{
					Provider: "azure",
					Target:   "sub-1",
					Role:     "Contributor",
				})
				return cfg
			}(),
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupCloudElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupElig:      func() *mockGroupsEligibilityLister { return &mockGroupsEligibilityLister{} },
			setupElevator:  func() *mockGroupsElevator { return &mockGroupsElevator{} },
			setupSelector:  func() *mockGroupSelector { return &mockGroupSelector{} },
			wantContain:    []string{"cloud favorite", "grant --favorite cloud-fav"},
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := tt.setupAuth()
			cloudElig := tt.setupCloudElig()
			elig := tt.setupElig()
			elevator := tt.setupElevator()
			selector := tt.setupSelector()

			cmd := NewGroupsCommandWithDeps(auth, cloudElig, elig, elevator, selector)
			cmd.SetContext(context.Background())

			// Inject config via the new cfg parameter
			// We need to use the test constructor that accepts config
			cmd = NewGroupsCommandWithDepsAndConfig(auth, cloudElig, elig, elevator, selector, tt.cfg)
			output, err := executeCommand(cmd, tt.args...)

			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none, output:\n%s", output)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestGroupsCommandUsage(t *testing.T) {
	cmd := NewGroupsCommand()

	if cmd.Use != "groups" {
		t.Errorf("expected Use='groups', got %q", cmd.Use)
	}
	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	groupFlag := cmd.Flags().Lookup("group")
	if groupFlag == nil {
		t.Fatal("expected --group flag")
	}
	if groupFlag.Shorthand != "g" {
		t.Errorf("expected -g shorthand, got %q", groupFlag.Shorthand)
	}

	favoriteFlag := cmd.Flags().Lookup("favorite")
	if favoriteFlag == nil {
		t.Fatal("expected --favorite flag")
	}
	if favoriteFlag.Shorthand != "f" {
		t.Errorf("expected -f shorthand, got %q", favoriteFlag.Shorthand)
	}
}
