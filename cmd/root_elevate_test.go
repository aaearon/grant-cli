package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/spf13/cobra"
)

func TestRootElevate_InteractiveMode(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockUnifiedSelector, *config.Config)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "interactive mode success",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockUnifiedSelector, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "test@example.com",
						ExpiresIn: commonmodels.IdsecRFC3339Time(time.Now().Add(1 * time.Hour)),
					},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{
							{
								OrganizationID: "org-123",
								WorkspaceID:    "sub-456",
								WorkspaceName:  "Prod-EastUS",
								WorkspaceType:  models.WorkspaceTypeSubscription,
								RoleInfo: models.RoleInfo{
									ID:   "role-789",
									Name: "Contributor",
								},
							},
						},
						Total: 1,
					},
				}

				elevateService := &mockElevateService{
					response: &models.ElevateResponse{
						Response: models.ElevateAccessResult{
							CSP:            models.CSPAzure,
							OrganizationID: "org-123",
							Results: []models.ElevateTargetResult{
								{
									WorkspaceID: "sub-456",
									RoleID:      "role-789",
									SessionID:   "session-abc",
								},
							},
						},
					},
				}

				selector := &mockUnifiedSelector{
					item: &selectionItem{kind: selectionCloud, cloud: &models.EligibleTarget{
						OrganizationID: "org-123",
						WorkspaceID:    "sub-456",
						WorkspaceName:  "Prod-EastUS",
						WorkspaceType:  models.WorkspaceTypeSubscription,
						RoleInfo: models.RoleInfo{
							ID:   "role-789",
							Name: "Contributor",
						},
					}},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, elevateService, selector, cfg
			},
			args: []string{},
			wantContain: []string{
				"Elevated to Contributor on Prod-EastUS",
				"Session ID: session-abc",
				"az CLI session",
			},
			wantErr: false,
		},
		{
			name: "AWS elevation success with credentials",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockUnifiedSelector, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "test@example.com",
						ExpiresIn: commonmodels.IdsecRFC3339Time(time.Now().Add(1 * time.Hour)),
					},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{
							{
								OrganizationID: "o-abc123",
								WorkspaceID:    "123456789012",
								WorkspaceName:  "AWS Management",
								WorkspaceType:  models.WorkspaceTypeAccount,
								RoleInfo: models.RoleInfo{
									ID:   "arn:aws:iam::123456789012:role/AdminAccess",
									Name: "AdminAccess",
								},
							},
						},
						Total: 1,
					},
				}

				credsJSON := `{"aws_access_key":"ASIAXXX","aws_secret_access_key":"secretkey","aws_session_token":"tokenval"}`
				elevateService := &mockElevateService{
					response: &models.ElevateResponse{
						Response: models.ElevateAccessResult{
							CSP:            models.CSPAWS,
							OrganizationID: "o-abc123",
							Results: []models.ElevateTargetResult{
								{
									WorkspaceID:       "123456789012",
									RoleID:            "AdminAccess",
									SessionID:         "session-aws-1",
									AccessCredentials: &credsJSON,
								},
							},
						},
					},
				}

				selector := &mockUnifiedSelector{
					item: &selectionItem{kind: selectionCloud, cloud: &models.EligibleTarget{
						OrganizationID: "o-abc123",
						WorkspaceID:    "123456789012",
						WorkspaceName:  "AWS Management",
						WorkspaceType:  models.WorkspaceTypeAccount,
						RoleInfo: models.RoleInfo{
							ID:   "arn:aws:iam::123456789012:role/AdminAccess",
							Name: "AdminAccess",
						},
					}},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, elevateService, selector, cfg
			},
			args: []string{"--provider", "aws"},
			wantContain: []string{
				"Elevated to AdminAccess on AWS Management",
				"Session ID: session-aws-1",
				"AWS_ACCESS_KEY_ID='ASIAXXX'",
				"AWS_SECRET_ACCESS_KEY='secretkey'",
				"AWS_SESSION_TOKEN='tokenval'",
			},
			wantErr: false,
		},
		{
			name: "multi-CSP interactive mode - mixed providers",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockUnifiedSelector, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "test@example.com",
						ExpiresIn: commonmodels.IdsecRFC3339Time(time.Now().Add(1 * time.Hour)),
					},
				}

				awsTarget := models.EligibleTarget{
					OrganizationID: "o-abc",
					WorkspaceID:    "111222333444",
					WorkspaceName:  "AWS Sandbox",
					WorkspaceType:  models.WorkspaceTypeAccount,
					RoleInfo:       models.RoleInfo{ID: "role-aws", Name: "ReadOnly"},
				}
				azureTarget := models.EligibleTarget{
					OrganizationID: "org-xyz",
					WorkspaceID:    "sub-999",
					WorkspaceName:  "Prod-EastUS",
					WorkspaceType:  models.WorkspaceTypeSubscription,
					RoleInfo:       models.RoleInfo{ID: "role-az", Name: "Contributor"},
				}

				// Return different targets per CSP
				eligibilityLister := &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
						switch csp {
						case models.CSPAzure:
							return &models.EligibilityResponse{Response: []models.EligibleTarget{azureTarget}, Total: 1}, nil
						case models.CSPAWS:
							return &models.EligibilityResponse{Response: []models.EligibleTarget{awsTarget}, Total: 1}, nil
						}
						return &models.EligibilityResponse{}, nil
					},
				}

				credsJSON := `{"aws_access_key":"ASIAXXX","aws_secret_access_key":"secret","aws_session_token":"token"}`
				elevateService := &mockElevateService{
					response: &models.ElevateResponse{
						Response: models.ElevateAccessResult{
							CSP:            models.CSPAWS,
							OrganizationID: "o-abc",
							Results: []models.ElevateTargetResult{
								{
									WorkspaceID:       "111222333444",
									RoleID:            "ReadOnly",
									SessionID:         "session-multi",
									AccessCredentials: &credsJSON,
								},
							},
						},
					},
				}

				// User selects the AWS target
				selector := &mockUnifiedSelector{
					item: &selectionItem{kind: selectionCloud, cloud: &awsTarget},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, elevateService, selector, cfg
			},
			args: []string{}, // no --provider
			wantContain: []string{
				"Elevated to ReadOnly on AWS Sandbox",
				"Session ID: session-multi",
				"AWS_ACCESS_KEY_ID",
			},
			wantErr: false,
		},
		{
			name: "multi-CSP concurrent fetch - parallel execution",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockUnifiedSelector, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "test@example.com",
						ExpiresIn: commonmodels.IdsecRFC3339Time(time.Now().Add(1 * time.Hour)),
					},
				}

				awsTarget := models.EligibleTarget{
					OrganizationID: "o-abc",
					WorkspaceID:    "111222333444",
					WorkspaceName:  "AWS Sandbox",
					WorkspaceType:  models.WorkspaceTypeAccount,
					RoleInfo:       models.RoleInfo{ID: "role-aws", Name: "ReadOnly"},
				}
				azureTarget := models.EligibleTarget{
					OrganizationID: "org-xyz",
					WorkspaceID:    "sub-999",
					WorkspaceName:  "Prod-EastUS",
					WorkspaceType:  models.WorkspaceTypeSubscription,
					RoleInfo:       models.RoleInfo{ID: "role-az", Name: "Contributor"},
				}

				// Each CSP call sleeps 200ms; if sequential total >= 400ms
				eligibilityLister := &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
						time.Sleep(200 * time.Millisecond)
						switch csp {
						case models.CSPAzure:
							return &models.EligibilityResponse{Response: []models.EligibleTarget{azureTarget}, Total: 1}, nil
						case models.CSPAWS:
							return &models.EligibilityResponse{Response: []models.EligibleTarget{awsTarget}, Total: 1}, nil
						}
						return &models.EligibilityResponse{}, nil
					},
				}

				credsJSON := `{"aws_access_key":"ASIAXXX","aws_secret_access_key":"secret","aws_session_token":"token"}`
				elevateService := &mockElevateService{
					response: &models.ElevateResponse{
						Response: models.ElevateAccessResult{
							CSP:            models.CSPAWS,
							OrganizationID: "o-abc",
							Results: []models.ElevateTargetResult{
								{
									WorkspaceID:       "111222333444",
									RoleID:            "ReadOnly",
									SessionID:         "session-par",
									AccessCredentials: &credsJSON,
								},
							},
						},
					},
				}

				selector := &mockUnifiedSelector{
					item: &selectionItem{kind: selectionCloud, cloud: &awsTarget},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, elevateService, selector, cfg
			},
			args: []string{}, // no --provider triggers multi-CSP
			wantContain: []string{
				"Elevated to ReadOnly on AWS Sandbox",
				"Session ID: session-par",
			},
			wantErr: false,
		},
		{
			name: "no eligible targets found across all providers",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockUnifiedSelector, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{},
						Total:    0,
					},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, nil, nil, cfg
			},
			args: []string{},
			wantContain: []string{
				"no eligible targets or groups found",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, selector, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, selector, &mockGroupsEligibilityLister{response: &models.GroupsEligibilityResponse{}}, nil, cfg)

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

func TestRootElevate_DirectMode(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "direct mode success with target and role",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{
							{
								OrganizationID: "org-123",
								WorkspaceID:    "sub-456",
								WorkspaceName:  "Prod-EastUS",
								WorkspaceType:  models.WorkspaceTypeSubscription,
								RoleInfo: models.RoleInfo{
									ID:   "role-789",
									Name: "Contributor",
								},
							},
						},
						Total: 1,
					},
				}

				elevateService := &mockElevateService{
					response: &models.ElevateResponse{
						Response: models.ElevateAccessResult{
							CSP:            models.CSPAzure,
							OrganizationID: "org-123",
							Results: []models.ElevateTargetResult{
								{
									WorkspaceID: "sub-456",
									RoleID:      "role-789",
									SessionID:   "session-xyz",
								},
							},
						},
					},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, elevateService, cfg
			},
			args: []string{"--target", "Prod-EastUS", "--role", "Contributor"},
			wantContain: []string{
				"Elevated to Contributor on Prod-EastUS",
				"Session ID: session-xyz",
			},
			wantErr: false,
		},
		{
			name: "direct mode success with case-insensitive match",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{
							{
								OrganizationID: "org-123",
								WorkspaceID:    "sub-456",
								WorkspaceName:  "Prod-EastUS",
								WorkspaceType:  models.WorkspaceTypeSubscription,
								RoleInfo: models.RoleInfo{
									ID:   "role-789",
									Name: "Contributor",
								},
							},
						},
						Total: 1,
					},
				}

				elevateService := &mockElevateService{
					response: &models.ElevateResponse{
						Response: models.ElevateAccessResult{
							CSP:            models.CSPAzure,
							OrganizationID: "org-123",
							Results: []models.ElevateTargetResult{
								{
									WorkspaceID: "sub-456",
									RoleID:      "role-789",
									SessionID:   "session-ci",
								},
							},
						},
					},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, elevateService, cfg
			},
			args: []string{"--target", "prod-eastus", "--role", "contributor"},
			wantContain: []string{
				"Elevated to Contributor on Prod-EastUS",
				"Session ID: session-ci",
			},
			wantErr: false,
		},
		{
			name: "direct mode - target not found",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{
							{
								WorkspaceName: "Dev-WestEU",
								RoleInfo:      models.RoleInfo{Name: "Reader"},
							},
						},
						Total: 1,
					},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, nil, cfg
			},
			args: []string{"--target", "NonExistent", "--role", "Contributor"},
			wantContain: []string{
				`target "NonExistent" or role "Contributor" not found`,
			},
			wantErr: true,
		},
		{
			name: "direct mode - role not found",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{
							{
								WorkspaceName: "Prod-EastUS",
								RoleInfo:      models.RoleInfo{Name: "Reader"},
							},
						},
						Total: 1,
					},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, nil, cfg
			},
			args: []string{"--target", "Prod-EastUS", "--role", "NonExistentRole"},
			wantContain: []string{
				`target "Prod-EastUS" or role "NonExistentRole" not found`,
			},
			wantErr: true,
		},
		{
			name: "direct mode - missing role flag",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}
				cfg := config.DefaultConfig()
				return authLoader, nil, nil, cfg
			},
			args: []string{"--target", "Prod-EastUS"},
			wantContain: []string{
				"both --target and --role must be provided",
			},
			wantErr: true,
		},
		{
			name: "direct mode - missing target flag",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}
				cfg := config.DefaultConfig()
				return authLoader, nil, nil, cfg
			},
			args: []string{"--role", "Contributor"},
			wantContain: []string{
				"both --target and --role must be provided",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, nil, nil, nil, cfg)

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

func TestRootElevate_FavoriteMode(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockGroupsEligibilityLister, *mockGroupsElevator, *config.Config)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "favorite mode success",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockGroupsEligibilityLister, *mockGroupsElevator, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{
							{
								OrganizationID: "org-123",
								WorkspaceID:    "sub-456",
								WorkspaceName:  "Prod-EastUS",
								WorkspaceType:  models.WorkspaceTypeSubscription,
								RoleInfo: models.RoleInfo{
									ID:   "role-789",
									Name: "Contributor",
								},
							},
						},
						Total: 1,
					},
				}

				elevateService := &mockElevateService{
					response: &models.ElevateResponse{
						Response: models.ElevateAccessResult{
							CSP:            models.CSPAzure,
							OrganizationID: "org-123",
							Results: []models.ElevateTargetResult{
								{
									WorkspaceID: "sub-456",
									RoleID:      "role-789",
									SessionID:   "session-fav",
								},
							},
						},
					},
				}

				cfg := config.DefaultConfig()
				cfg.Favorites = map[string]config.Favorite{
					"prod-contrib": {
						Provider: "azure",
						Target:   "Prod-EastUS",
						Role:     "Contributor",
					},
				}

				return authLoader, eligibilityLister, elevateService, nil, nil, cfg
			},
			args: []string{"--favorite", "prod-contrib"},
			wantContain: []string{
				"Elevated to Contributor on Prod-EastUS",
				"Session ID: session-fav",
			},
			wantErr: false,
		},
		{
			name: "favorite not found",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockGroupsEligibilityLister, *mockGroupsElevator, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				cfg := config.DefaultConfig()

				return authLoader, nil, nil, nil, nil, cfg
			},
			args: []string{"--favorite", "nonexistent"},
			wantContain: []string{
				`favorite "nonexistent" not found`,
			},
			wantErr: true,
		},
		{
			name: "provider mismatch with favorite",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockGroupsEligibilityLister, *mockGroupsElevator, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				cfg := config.DefaultConfig()
				cfg.Favorites = map[string]config.Favorite{
					"prod-contrib": {
						Provider: "azure",
						Target:   "Prod-EastUS",
						Role:     "Contributor",
					},
				}

				return authLoader, nil, nil, nil, nil, cfg
			},
			args: []string{"--favorite", "prod-contrib", "--provider", "aws"},
			wantContain: []string{
				`provider "aws" does not match favorite provider "azure"`,
			},
			wantErr: true,
		},
		{
			name: "group favorite elevates group directly",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockGroupsEligibilityLister, *mockGroupsElevator, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				groupsEligLister := &mockGroupsEligibilityLister{
					response: &models.GroupsEligibilityResponse{
						Response: []models.GroupsEligibleTarget{
							{
								DirectoryID: "dir-uuid",
								GroupID:     "grp-123",
								GroupName:   "Engineering",
							},
						},
						Total: 1,
					},
				}

				groupsElevator := &mockGroupsElevator{
					response: &models.GroupsElevateResponse{
						DirectoryID: "dir-uuid",
						CSP:         models.CSPAzure,
						Results: []models.GroupsElevateTargetResult{
							{
								GroupID:   "grp-123",
								SessionID: "session-grp-fav",
							},
						},
					},
				}

				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "my-grp", config.Favorite{
					Type:        config.FavoriteTypeGroups,
					Provider:    "azure",
					Group:       "Engineering",
					DirectoryID: "dir-uuid",
				})

				return authLoader, &mockEligibilityLister{response: &models.EligibilityResponse{}}, nil, groupsEligLister, groupsElevator, cfg
			},
			args: []string{"--favorite", "my-grp"},
			wantContain: []string{
				"Elevated to group Engineering",
				"Session ID: session-grp-fav",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, groupsEligLister, groupsElevator, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, nil, groupsEligLister, groupsElevator, cfg)

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

func TestRootElevate_ProviderValidation(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func() (*mockAuthLoader, *mockEligibilityLister, *config.Config)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "invalid provider - gcp",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}
				cfg := config.DefaultConfig()
				return authLoader, nil, cfg
			},
			args: []string{"--provider", "gcp"},
			wantContain: []string{
				`provider "gcp" is not supported`,
				"supported providers: azure, aws",
			},
			wantErr: true,
		},
		{
			name: "valid provider - aws explicit",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}
				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{},
						Total:    0,
					},
				}
				cfg := config.DefaultConfig()
				return authLoader, eligibilityLister, cfg
			},
			args: []string{"--provider", "aws"},
			wantContain: []string{
				"no eligible aws targets found",
			},
			wantErr: true,
		},
		{
			name: "valid provider - azure explicit",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}
				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{},
						Total:    0,
					},
				}
				cfg := config.DefaultConfig()
				return authLoader, eligibilityLister, cfg
			},
			args: []string{"--provider", "azure"},
			wantContain: []string{
				"no eligible azure targets found",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, nil, nil, nil, nil, cfg)

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

func TestRootElevate_AuthenticationErrors(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func() (*mockAuthLoader, *config.Config)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "not authenticated",
			setupMocks: func() (*mockAuthLoader, *config.Config) {
				authLoader := &mockAuthLoader{
					loadErr: errors.New("no cached token"),
				}
				cfg := config.DefaultConfig()
				return authLoader, cfg
			},
			args: []string{},
			wantContain: []string{
				"not authenticated",
				"run 'grant login' first",
				"no cached token",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(nil, authLoader, nil, nil, nil, nil, nil, cfg)

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

func TestRootElevate_ElevationErrors(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "elevation API error - all targets fail",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.EligibleTarget{
							{
								OrganizationID: "org-123",
								WorkspaceID:    "sub-456",
								WorkspaceName:  "Prod-EastUS",
								WorkspaceType:  models.WorkspaceTypeSubscription,
								RoleInfo: models.RoleInfo{
									ID:   "role-789",
									Name: "Contributor",
								},
							},
						},
						Total: 1,
					},
				}

				errorInfo := &models.ErrorInfo{
					Code:        "POLICY_DENIED",
					Message:     "Elevation requires approval",
					Description: "This role requires manager approval",
				}

				elevateService := &mockElevateService{
					response: &models.ElevateResponse{
						Response: models.ElevateAccessResult{
							CSP:            models.CSPAzure,
							OrganizationID: "org-123",
							Results: []models.ElevateTargetResult{
								{
									WorkspaceID: "sub-456",
									RoleID:      "role-789",
									ErrorInfo:   errorInfo,
								},
							},
						},
					},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, elevateService, cfg
			},
			args: []string{"--target", "Prod-EastUS", "--role", "Contributor"},
			wantContain: []string{
				"elevation failed",
				"POLICY_DENIED",
				"Elevation requires approval",
			},
			wantErr: true,
		},
		{
			name: "eligibility list error",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					listErr: errors.New("API error: unauthorized"),
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, nil, cfg
			},
			args: []string{"--provider", "azure", "--target", "Prod-EastUS", "--role", "Contributor"},
			wantContain: []string{
				"failed to fetch eligible targets",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, nil, nil, nil, cfg)

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

func TestRootElevate_UsageAndFlags(t *testing.T) {
	cfg := config.DefaultConfig()
	cmd := NewRootCommandWithDeps(nil, &mockAuthLoader{}, nil, nil, nil, nil, nil, cfg)

	// Verify command metadata
	if cmd.Use != "grant" {
		t.Errorf("expected Use='grant', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	if cmd.Long == "" {
		t.Error("expected non-empty Long description")
	}

	// Verify flags are registered
	if cmd.Flags().Lookup("provider") == nil {
		t.Error("expected --provider flag to be registered")
	}

	if cmd.Flags().Lookup("target") == nil {
		t.Error("expected --target flag to be registered")
	}

	if cmd.Flags().Lookup("role") == nil {
		t.Error("expected --role flag to be registered")
	}

	if cmd.Flags().Lookup("favorite") == nil {
		t.Error("expected --favorite flag to be registered")
	}
}

func TestFetchEligibility_SingleProviderOmitsCSPTag(t *testing.T) {
	lister := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{
				{
					WorkspaceName: "Prod-EastUS",
					WorkspaceType: models.WorkspaceTypeSubscription,
					RoleInfo:      models.RoleInfo{ID: "role-1", Name: "Contributor"},
				},
			},
			Total: 1,
		},
	}

	targets, err := fetchEligibility(t.Context(), lister, "azure")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, tgt := range targets {
		if tgt.CSP != "" {
			t.Errorf("expected empty CSP on single-provider fetch, got %q", tgt.CSP)
		}
	}
}

func TestFetchEligibility_ConcurrentExecution(t *testing.T) {
	awsTarget := models.EligibleTarget{
		WorkspaceName: "AWS Sandbox",
		WorkspaceType: models.WorkspaceTypeAccount,
		RoleInfo:      models.RoleInfo{ID: "role-aws", Name: "ReadOnly"},
	}
	azureTarget := models.EligibleTarget{
		WorkspaceName: "Prod-EastUS",
		WorkspaceType: models.WorkspaceTypeSubscription,
		RoleInfo:      models.RoleInfo{ID: "role-az", Name: "Contributor"},
	}

	lister := &mockEligibilityLister{
		listFunc: func(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
			time.Sleep(200 * time.Millisecond)
			switch csp {
			case models.CSPAzure:
				return &models.EligibilityResponse{Response: []models.EligibleTarget{azureTarget}, Total: 1}, nil
			case models.CSPAWS:
				return &models.EligibilityResponse{Response: []models.EligibleTarget{awsTarget}, Total: 1}, nil
			}
			return &models.EligibilityResponse{}, nil
		},
	}

	start := time.Now()
	targets, err := fetchEligibility(t.Context(), lister, "")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	// With 2 CSPs sleeping 200ms each, parallel should finish well under 400ms
	if elapsed >= 350*time.Millisecond {
		t.Errorf("expected concurrent execution (<350ms), took %v", elapsed)
	}

	// Verify CSP tags were set
	cspSeen := map[models.CSP]bool{}
	for _, tgt := range targets {
		cspSeen[tgt.CSP] = true
	}
	if !cspSeen[models.CSPAzure] || !cspSeen[models.CSPAWS] {
		t.Errorf("expected both CSPs in results, got %v", cspSeen)
	}
}

func TestRootElevate_GroupsInteractiveMode(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	authLoader := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
	}
	cloudElig := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{
				{
					OrganizationID: "dir1",
					WorkspaceID:    "dir1",
					WorkspaceName:  "Contoso",
					WorkspaceType:  models.WorkspaceTypeDirectory,
				},
			},
		},
	}
	groupsElig := &mockGroupsEligibilityLister{
		response: &models.GroupsEligibilityResponse{
			Response: []models.GroupsEligibleTarget{
				{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
				{DirectoryID: "dir1", GroupID: "grp2", GroupName: "DevOps"},
			},
			Total: 2,
		},
	}
	groupsElev := &mockGroupsElevator{
		response: &models.GroupsElevateResponse{
			DirectoryID: "dir1",
			CSP:         models.CSPAzure,
			Results: []models.GroupsElevateTargetResult{
				{GroupID: "grp1", SessionID: "sess-grp-1"},
			},
		},
	}

	// User selects a group from the unified list
	selector := &mockUnifiedSelector{
		selectFunc: func(items []selectionItem) (*selectionItem, error) {
			// Verify both cloud and group items are present
			hasCloud := false
			hasGroup := false
			for _, item := range items {
				if item.kind == selectionCloud {
					hasCloud = true
				}
				if item.kind == selectionGroup {
					hasGroup = true
				}
			}
			if !hasCloud {
				t.Error("expected cloud items in unified selector")
			}
			if !hasGroup {
				t.Error("expected group items in unified selector")
			}
			// Select the Engineering group
			for i := range items {
				if items[i].kind == selectionGroup && items[i].group.GroupName == "Engineering" {
					return &items[i], nil
				}
			}
			t.Fatal("Engineering group not found in items")
			return nil, nil
		},
	}

	cmd := NewRootCommandWithDeps(nil, authLoader, cloudElig, nil, selector, groupsElig, groupsElev, config.DefaultConfig())
	output, err := executeCommand(cmd)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Elevated to group Engineering in Contoso") {
		t.Errorf("output missing expected text, got:\n%s", output)
	}
	if !strings.Contains(output, "Session ID: sess-grp-1") {
		t.Errorf("output missing session ID, got:\n%s", output)
	}
}

func TestRootElevate_GroupsDirectMode(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	tests := []struct {
		name        string
		args        []string
		groupsElig  *mockGroupsEligibilityLister
		groupsElev  *mockGroupsElevator
		cloudElig   *mockEligibilityLister
		wantContain []string
		wantErr     bool
	}{
		{
			name: "direct group elevation success",
			args: []string{"--group", "Engineering"},
			cloudElig: &mockEligibilityLister{
				response: &models.EligibilityResponse{Response: []models.EligibleTarget{}},
			},
			groupsElig: &mockGroupsEligibilityLister{
				response: &models.GroupsEligibilityResponse{
					Response: []models.GroupsEligibleTarget{
						{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
					},
					Total: 1,
				},
			},
			groupsElev: &mockGroupsElevator{
				response: &models.GroupsElevateResponse{
					DirectoryID: "dir1",
					CSP:         models.CSPAzure,
					Results: []models.GroupsElevateTargetResult{
						{GroupID: "grp1", SessionID: "sess1"},
					},
				},
			},
			wantContain: []string{"Elevated to group Engineering", "Session ID: sess1"},
			wantErr:     false,
		},
		{
			name: "direct group not found",
			args: []string{"--group", "NonExistent"},
			cloudElig: &mockEligibilityLister{
				response: &models.EligibilityResponse{Response: []models.EligibleTarget{}},
			},
			groupsElig: &mockGroupsEligibilityLister{
				response: &models.GroupsEligibilityResponse{
					Response: []models.GroupsEligibleTarget{
						{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
					},
					Total: 1,
				},
			},
			groupsElev:  &mockGroupsElevator{},
			wantContain: []string{`group "NonExistent" not found`},
			wantErr:     true,
		},
		{
			name: "group elevation API error",
			args: []string{"--group", "Engineering"},
			cloudElig: &mockEligibilityLister{
				response: &models.EligibilityResponse{Response: []models.EligibleTarget{}},
			},
			groupsElig: &mockGroupsEligibilityLister{
				response: &models.GroupsEligibilityResponse{
					Response: []models.GroupsEligibleTarget{
						{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
					},
					Total: 1,
				},
			},
			groupsElev:  &mockGroupsElevator{elevateErr: errors.New("API error: forbidden")},
			wantContain: []string{"elevation request failed"},
			wantErr:     true,
		},
		{
			name: "groups eligibility API error",
			args: []string{"--group", "Engineering"},
			cloudElig: &mockEligibilityLister{
				response: &models.EligibilityResponse{Response: []models.EligibleTarget{}},
			},
			groupsElig:  &mockGroupsEligibilityLister{listErr: errors.New("service unavailable")},
			groupsElev:  &mockGroupsElevator{},
			wantContain: []string{"failed to fetch eligible groups"},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader := &mockAuthLoader{
				token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
			}

			cmd := NewRootCommandWithDeps(nil, authLoader, tt.cloudElig, nil, nil, tt.groupsElig, tt.groupsElev, config.DefaultConfig())
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

func TestRootElevate_GroupsFlag(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	authLoader := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
	}
	cloudElig := &mockEligibilityLister{
		response: &models.EligibilityResponse{Response: []models.EligibleTarget{}},
	}
	groupsElig := &mockGroupsEligibilityLister{
		response: &models.GroupsEligibilityResponse{
			Response: []models.GroupsEligibleTarget{
				{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
				{DirectoryID: "dir1", GroupID: "grp2", GroupName: "DevOps"},
			},
			Total: 2,
		},
	}
	groupsElev := &mockGroupsElevator{
		response: &models.GroupsElevateResponse{
			DirectoryID: "dir1",
			CSP:         models.CSPAzure,
			Results: []models.GroupsElevateTargetResult{
				{GroupID: "grp2", SessionID: "sess-devops"},
			},
		},
	}

	selector := &mockUnifiedSelector{
		selectFunc: func(items []selectionItem) (*selectionItem, error) {
			// Verify only group items are present (no cloud)
			for _, item := range items {
				if item.kind == selectionCloud {
					t.Error("expected no cloud items when --groups flag is set")
				}
			}
			if len(items) != 2 {
				t.Errorf("expected 2 group items, got %d", len(items))
			}
			// Select DevOps
			for i := range items {
				if items[i].kind == selectionGroup && items[i].group.GroupName == "DevOps" {
					return &items[i], nil
				}
			}
			t.Fatal("DevOps group not found")
			return nil, nil
		},
	}

	cmd := NewRootCommandWithDeps(nil, authLoader, cloudElig, nil, selector, groupsElig, groupsElev, config.DefaultConfig())
	output, err := executeCommand(cmd, "--groups")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Elevated to group DevOps") {
		t.Errorf("output missing expected text, got:\n%s", output)
	}
	if !strings.Contains(output, "Session ID: sess-devops") {
		t.Errorf("output missing session ID, got:\n%s", output)
	}
}

func TestRootElevate_GroupFavoriteDirectoryID(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	authLoader := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
	}
	cloudElig := &mockEligibilityLister{
		response: &models.EligibilityResponse{Response: []models.EligibleTarget{}},
	}
	groupsElig := &mockGroupsEligibilityLister{
		response: &models.GroupsEligibilityResponse{
			Response: []models.GroupsEligibleTarget{
				{DirectoryID: "dir2", GroupID: "grp-wrong", GroupName: "Engineering"},
				{DirectoryID: "dir1", GroupID: "grp-right", GroupName: "Engineering"},
			},
			Total: 2,
		},
	}

	cfg := config.DefaultConfig()
	_ = config.AddFavorite(cfg, "my-grp", config.Favorite{
		Type:        config.FavoriteTypeGroups,
		Provider:    "azure",
		Group:       "Engineering",
		DirectoryID: "dir1",
	})

	groupsElev := &mockGroupsElevator{
		elevateFunc: func(ctx context.Context, req *models.GroupsElevateRequest) (*models.GroupsElevateResponse, error) {
			if req.Targets[0].GroupID != "grp-right" {
				t.Errorf("expected group ID grp-right, got %s", req.Targets[0].GroupID)
			}
			if req.DirectoryID != "dir1" {
				t.Errorf("expected directory ID dir1, got %s", req.DirectoryID)
			}
			return &models.GroupsElevateResponse{
				DirectoryID: "dir1",
				CSP:         models.CSPAzure,
				Results: []models.GroupsElevateTargetResult{
					{GroupID: "grp-right", SessionID: "sess1"},
				},
			}, nil
		},
	}

	cmd := NewRootCommandWithDeps(nil, authLoader, cloudElig, nil, nil, groupsElig, groupsElev, cfg)
	output, err := executeCommand(cmd, "--favorite", "my-grp")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Elevated to group Engineering") {
		t.Errorf("output missing expected text, got:\n%s", output)
	}
	if !strings.Contains(output, "Session ID: sess1") {
		t.Errorf("output missing session ID, got:\n%s", output)
	}
}

func TestRootElevate_MutualExclusivity(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "groups and provider are mutually exclusive",
			args:    []string{"--groups", "--provider", "azure"},
			wantErr: true,
		},
		{
			name:    "group and target are mutually exclusive",
			args:    []string{"--group", "Eng", "--target", "Sub1"},
			wantErr: true,
		},
		{
			name:    "group and role are mutually exclusive",
			args:    []string{"--group", "Eng", "--role", "Reader"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCommand(func(cmd *cobra.Command, args []string) error {
				return nil
			})
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
		})
	}
}

func TestRootElevate_UnifiedInteractiveShowsBoth(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	authLoader := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
	}

	// Cloud eligibility with a subscription target
	cloudElig := &mockEligibilityLister{
		listFunc: func(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
			if csp == models.CSPAzure {
				return &models.EligibilityResponse{
					Response: []models.EligibleTarget{
						{
							OrganizationID: "org-1",
							WorkspaceID:    "sub-1",
							WorkspaceName:  "Prod-EastUS",
							WorkspaceType:  models.WorkspaceTypeSubscription,
							RoleInfo:       models.RoleInfo{ID: "role-1", Name: "Contributor"},
						},
					},
					Total: 1,
				}, nil
			}
			return &models.EligibilityResponse{}, nil
		},
	}

	groupsElig := &mockGroupsEligibilityLister{
		response: &models.GroupsEligibilityResponse{
			Response: []models.GroupsEligibleTarget{
				{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
			},
			Total: 1,
		},
	}

	elevateService := &mockElevateService{
		response: &models.ElevateResponse{
			Response: models.ElevateAccessResult{
				CSP:            models.CSPAzure,
				OrganizationID: "org-1",
				Results: []models.ElevateTargetResult{
					{WorkspaceID: "sub-1", RoleID: "role-1", SessionID: "sess-cloud"},
				},
			},
		},
	}

	var receivedItems []selectionItem
	selector := &mockUnifiedSelector{
		selectFunc: func(items []selectionItem) (*selectionItem, error) {
			receivedItems = items
			// Select the cloud target
			for i := range items {
				if items[i].kind == selectionCloud {
					return &items[i], nil
				}
			}
			return nil, errors.New("no cloud item found")
		},
	}

	cmd := NewRootCommandWithDeps(nil, authLoader, cloudElig, elevateService, selector, groupsElig, nil, config.DefaultConfig())
	output, err := executeCommand(cmd)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify both cloud and group items were passed to selector
	hasCloud := false
	hasGroup := false
	for _, item := range receivedItems {
		if item.kind == selectionCloud {
			hasCloud = true
		}
		if item.kind == selectionGroup {
			hasGroup = true
		}
	}
	if !hasCloud {
		t.Error("expected cloud items in unified selector")
	}
	if !hasGroup {
		t.Error("expected group items in unified selector")
	}

	if !strings.Contains(output, "Elevated to Contributor on Prod-EastUS") {
		t.Errorf("output missing expected text, got:\n%s", output)
	}
}

// TestRootElevate_SlowPromptTimeout verifies that elevation succeeds even when
// the interactive prompt takes longer than apiTimeout. The context for the
// elevation API call must be independent of the prompt duration.
func TestRootElevate_SlowPromptTimeout(t *testing.T) {
	origTimeout := apiTimeout
	apiTimeout = 50 * time.Millisecond
	defer func() { apiTimeout = origTimeout }()

	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	authLoader := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
	}

	cloudElig := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{
				{
					OrganizationID: "org-1",
					WorkspaceID:    "sub-1",
					WorkspaceName:  "Prod-EastUS",
					WorkspaceType:  models.WorkspaceTypeSubscription,
					RoleInfo:       models.RoleInfo{ID: "role-1", Name: "Contributor"},
				},
			},
			Total: 1,
		},
	}

	groupsElig := &mockGroupsEligibilityLister{
		response: &models.GroupsEligibilityResponse{
			Response: []models.GroupsEligibleTarget{
				{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
			},
			Total: 1,
		},
	}

	// Slow selector simulates a user taking longer than apiTimeout to choose
	slowSelector := &mockUnifiedSelector{
		selectFunc: func(items []selectionItem) (*selectionItem, error) {
			time.Sleep(100 * time.Millisecond) // 2x apiTimeout
			return &items[0], nil
		},
	}

	// contextAwareElevator returns context deadline exceeded if ctx is expired,
	// matching real HTTP client behavior.
	contextAwareGroupsElev := &mockGroupsElevator{
		elevateFunc: func(ctx context.Context, req *models.GroupsElevateRequest) (*models.GroupsElevateResponse, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return &models.GroupsElevateResponse{
				DirectoryID: "dir1",
				CSP:         models.CSPAzure,
				Results: []models.GroupsElevateTargetResult{
					{GroupID: "grp1", SessionID: "sess-grp"},
				},
			}, nil
		},
	}

	contextAwareCloudElev := &mockElevateService{
		elevateFunc: func(ctx context.Context, req *models.ElevateRequest) (*models.ElevateResponse, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return &models.ElevateResponse{
				Response: models.ElevateAccessResult{
					CSP:            models.CSPAzure,
					OrganizationID: "org-1",
					Results: []models.ElevateTargetResult{
						{WorkspaceID: "sub-1", RoleID: "role-1", SessionID: "sess-cloud"},
					},
				},
			}, nil
		},
	}

	t.Run("unified path - group elevation after slow prompt", func(t *testing.T) {
		// Selector returns the group item
		sel := &mockUnifiedSelector{
			selectFunc: func(items []selectionItem) (*selectionItem, error) {
				time.Sleep(100 * time.Millisecond)
				for i := range items {
					if items[i].kind == selectionGroup {
						return &items[i], nil
					}
				}
				return &items[0], nil
			},
		}

		cmd := NewRootCommandWithDeps(nil, authLoader, cloudElig, nil, sel, groupsElig, contextAwareGroupsElev, config.DefaultConfig())
		output, err := executeCommand(cmd)

		if err != nil {
			t.Fatalf("elevation should succeed after slow prompt, got: %v", err)
		}
		if !strings.Contains(output, "Elevated to group Engineering") {
			t.Errorf("unexpected output:\n%s", output)
		}
	})

	t.Run("cloud-only path - elevation after slow prompt", func(t *testing.T) {
		cmd := NewRootCommandWithDeps(nil, authLoader, cloudElig, contextAwareCloudElev, slowSelector, groupsElig, nil, config.DefaultConfig())
		output, err := executeCommand(cmd, "--provider", "azure")

		if err != nil {
			t.Fatalf("elevation should succeed after slow prompt, got: %v", err)
		}
		if !strings.Contains(output, "Elevated to Contributor on Prod-EastUS") {
			t.Errorf("unexpected output:\n%s", output)
		}
	})

	t.Run("groups filter path - elevation after slow prompt", func(t *testing.T) {
		cmd := NewRootCommandWithDeps(nil, authLoader, cloudElig, nil, slowSelector, groupsElig, contextAwareGroupsElev, config.DefaultConfig())
		output, err := executeCommand(cmd, "--groups")

		if err != nil {
			t.Fatalf("elevation should succeed after slow prompt, got: %v", err)
		}
		if !strings.Contains(output, "Elevated to group Engineering") {
			t.Errorf("unexpected output:\n%s", output)
		}
	})
}
