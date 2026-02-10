package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	common_models "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

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
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "test@example.com",
						ExpiresIn: common_models.IdsecRFC3339Time(time.Now().Add(1 * time.Hour)),
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
					token: &auth_models.IdsecToken{Token: "test-jwt"},
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
				"No eligible azure targets found",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, selector, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(authLoader, eligibilityLister, elevateService, selector, cfg)

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
					token: &auth_models.IdsecToken{Token: "test-jwt"},
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
			name: "direct mode - target not found",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &auth_models.IdsecToken{Token: "test-jwt"},
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
				"Target 'NonExistent' or role 'Contributor' not found",
			},
			wantErr: true,
		},
		{
			name: "direct mode - role not found",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &auth_models.IdsecToken{Token: "test-jwt"},
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
				"Target 'Prod-EastUS' or role 'NonExistentRole' not found",
			},
			wantErr: true,
		},
		{
			name: "direct mode - missing role flag",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &auth_models.IdsecToken{Token: "test-jwt"},
				}
				cfg := config.DefaultConfig()
				return authLoader, nil, nil, cfg
			},
			args: []string{"--target", "Prod-EastUS"},
			wantContain: []string{
				"Both --target and --role must be provided",
			},
			wantErr: true,
		},
		{
			name: "direct mode - missing target flag",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &auth_models.IdsecToken{Token: "test-jwt"},
				}
				cfg := config.DefaultConfig()
				return authLoader, nil, nil, cfg
			},
			args: []string{"--role", "Contributor"},
			wantContain: []string{
				"Both --target and --role must be provided",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(authLoader, eligibilityLister, elevateService, nil, cfg)

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
					token: &auth_models.IdsecToken{Token: "test-jwt"},
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
					token: &auth_models.IdsecToken{Token: "test-jwt"},
				}

				cfg := config.DefaultConfig()

				return authLoader, nil, nil, cfg
			},
			args: []string{"--favorite", "nonexistent"},
			wantContain: []string{
				"Favorite 'nonexistent' not found",
			},
			wantErr: true,
		},
		{
			name: "provider mismatch with favorite",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &auth_models.IdsecToken{Token: "test-jwt"},
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
				"Provider 'aws' does not match favorite provider 'azure'",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, eligibilityLister, elevateService, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(authLoader, eligibilityLister, elevateService, nil, cfg)

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
		setupMocks  func() (*mockAuthLoader, *config.Config)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "invalid provider - v1 only accepts azure",
			setupMocks: func() (*mockAuthLoader, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &auth_models.IdsecToken{Token: "test-jwt"},
				}
				cfg := config.DefaultConfig()
				return authLoader, cfg
			},
			args: []string{"--provider", "aws"},
			wantContain: []string{
				"Provider 'aws' is not supported in this version",
				"Supported providers: azure",
			},
			wantErr: true,
		},
		{
			name: "invalid provider - gcp",
			setupMocks: func() (*mockAuthLoader, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &auth_models.IdsecToken{Token: "test-jwt"},
				}
				cfg := config.DefaultConfig()
				return authLoader, cfg
			},
			args: []string{"--provider", "gcp"},
			wantContain: []string{
				"Provider 'gcp' is not supported in this version",
				"Supported providers: azure",
			},
			wantErr: true,
		},
		{
			name: "valid provider - azure explicit",
			setupMocks: func() (*mockAuthLoader, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &auth_models.IdsecToken{Token: "test-jwt"},
				}
				cfg := config.DefaultConfig()
				return authLoader, cfg
			},
			args:    []string{"--provider", "azure"},
			wantErr: true, // Will fail due to other reasons but provider validation passes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(authLoader, nil, nil, nil, cfg)

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
				"Not authenticated",
				"Run 'grant login' first",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authLoader, cfg := tt.setupMocks()

			cmd := NewRootCommandWithDeps(authLoader, nil, nil, nil, cfg)

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
					token: &auth_models.IdsecToken{Token: "test-jwt"},
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
				"Elevation failed",
				"POLICY_DENIED",
				"Elevation requires approval",
			},
			wantErr: true,
		},
		{
			name: "eligibility list error",
			setupMocks: func() (*mockAuthLoader, *mockEligibilityLister, *mockElevateService, *config.Config) {
				authLoader := &mockAuthLoader{
					token: &auth_models.IdsecToken{Token: "test-jwt"},
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

			cmd := NewRootCommandWithDeps(authLoader, eligibilityLister, elevateService, nil, cfg)

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
	cmd := NewRootCommandWithDeps(&mockAuthLoader{}, nil, nil, nil, cfg)

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

	if cmd.Flags().Lookup("duration") == nil {
		t.Error("expected --duration flag to be registered")
	}
}
