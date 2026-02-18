package cmd

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func TestRootElevate_InteractiveMode(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockTargetSelector, *config.Config)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "interactive mode success",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockTargetSelector, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "test@example.com",
						ExpiresIn: commonmodels.IdsecRFC3339Time(time.Now().Add(1 * time.Hour)),
					},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.AzureEligibleTarget{
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

				selector := &mockTargetSelector{
					target: &models.AzureEligibleTarget{
						OrganizationID: "org-123",
						WorkspaceID:    "sub-456",
						WorkspaceName:  "Prod-EastUS",
						WorkspaceType:  models.WorkspaceTypeSubscription,
						RoleInfo: models.RoleInfo{
							ID:   "role-789",
							Name: "Contributor",
						},
					},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, elevateService, selector, cfg
			},
			args: []string{},
			wantContain: []string{
				"Elevated to Contributor on Prod-EastUS",
				"Session ID: session-abc",
			},
			wantErr: false,
		},
		{
			name: "no eligible targets found",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *mockTargetSelector, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.AzureEligibleTarget{},
						Total:    0,
					},
				}

				cfg := config.DefaultConfig()

				return authLoader, eligibilityLister, nil, nil, cfg
			},
			args: []string{},
			wantContain: []string{
				"no eligible azure targets found",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, selector, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, selector, cfg)

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
						Response: []models.AzureEligibleTarget{
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
						Response: []models.AzureEligibleTarget{
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
						Response: []models.AzureEligibleTarget{
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
						Response: []models.AzureEligibleTarget{
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

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, nil, cfg)

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
		setupMocks  func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "favorite mode success",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				eligibilityLister := &mockEligibilityLister{
					response: &models.EligibilityResponse{
						Response: []models.AzureEligibleTarget{
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

				return authLoader, eligibilityLister, elevateService, cfg
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
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}

				cfg := config.DefaultConfig()

				return authLoader, nil, nil, cfg
			},
			args: []string{"--favorite", "nonexistent"},
			wantContain: []string{
				`favorite "nonexistent" not found`,
			},
			wantErr: true,
		},
		{
			name: "provider mismatch with favorite",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
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

				return authLoader, nil, nil, cfg
			},
			args: []string{"--favorite", "prod-contrib", "--provider", "aws"},
			wantContain: []string{
				`provider "aws" does not match favorite provider "azure"`,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, nil, cfg)

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
			name: "invalid provider - v1 only accepts azure",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "test-jwt"},
				}
				cfg := config.DefaultConfig()
				return authLoader, nil, cfg
			},
			args: []string{"--provider", "aws"},
			wantContain: []string{
				`provider "aws" is not supported in this version`,
				"supported providers: azure",
			},
			wantErr: true,
		},
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
				`provider "gcp" is not supported in this version`,
				"supported providers: azure",
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
						Response: []models.AzureEligibleTarget{},
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

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, nil, nil, cfg)

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

			cmd := NewRootCommandWithDeps(nil, authLoader, nil, nil, nil, cfg)

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
						Response: []models.AzureEligibleTarget{
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
			args: []string{"--target", "Prod-EastUS", "--role", "Contributor"},
			wantContain: []string{
				"failed to fetch eligible targets",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, nil, cfg)

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
	cmd := NewRootCommandWithDeps(nil, &mockAuthLoader{}, nil, nil, nil, cfg)

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
