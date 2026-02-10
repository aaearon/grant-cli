package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sca_models "github.com/aaearon/sca-cli/internal/sca/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	common_models "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func TestStatusCommand(t *testing.T) {
	now := time.Now()
	expiresIn := common_models.IdsecRFC3339Time(now.Add(1 * time.Hour))

	tests := []struct {
		name        string
		setupAuth   func() *mockAuthLoader
		setupSvc    func() *mockSessionLister
		provider    string
		wantContain []string
		wantNotContain []string
		wantErr     bool
	}{
		{
			name: "not authenticated",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token:   nil,
					loadErr: errors.New("no cached authentication"),
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{}
			},
			wantContain: []string{
				"Not authenticated",
				"Run 'sca-cli login' first",
			},
			wantErr: false,
		},
		{
			name: "authenticated with no sessions",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &sca_models.SessionsResponse{
						Response: []sca_models.SessionInfo{},
						Total:    0,
					},
					listErr: nil,
				}
			},
			wantContain: []string{
				"Authenticated as: tim@iosharp.com",
				"No active sessions",
			},
			wantErr: false,
		},
		{
			name: "authenticated with Azure sessions",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				expiryTime1 := now.Add(1*time.Hour + 12*time.Minute)
				expiryTime2 := now.Add(25 * time.Minute)

				return &mockSessionLister{
					sessions: &sca_models.SessionsResponse{
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								WorkspaceName:   "Prod-EastUS",
								RoleID:          "/providers/Microsoft.Authorization/roleDefinitions/role-1",
								RoleName:        "Contributor",
								SessionDuration: 4320, // 72 minutes in seconds
								ExpiresAt:       &expiryTime1,
							},
							{
								SessionID:       "session-2",
								UserID:          "tim@iosharp.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-2",
								WorkspaceName:   "Dev-WestEU",
								RoleID:          "/providers/Microsoft.Authorization/roleDefinitions/role-2",
								RoleName:        "Owner",
								SessionDuration: 1500, // 25 minutes in seconds
								ExpiresAt:       &expiryTime2,
							},
						},
						Total: 2,
					},
					listErr: nil,
				}
			},
			wantContain: []string{
				"Authenticated as: tim@iosharp.com",
				"Azure sessions:",
				"Contributor on Prod-EastUS",
				"expires at",
				"1h 12m remaining",
				"Owner on Dev-WestEU",
				"25m remaining",
			},
			wantErr: false,
		},
		{
			name: "filter by provider - Azure",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					listFunc: func(ctx context.Context, csp *sca_models.CSP) (*sca_models.SessionsResponse, error) {
						// Verify the filter is applied
						if csp != nil && *csp == sca_models.CSPAzure {
							expiryTime := now.Add(30 * time.Minute)
							return &sca_models.SessionsResponse{
								Response: []sca_models.SessionInfo{
									{
										SessionID:       "session-azure",
										UserID:          "tim@iosharp.com",
										CSP:             sca_models.CSPAzure,
										WorkspaceID:     "/subscriptions/sub-1",
										WorkspaceName:   "Test-Workspace",
										RoleID:          "role-1",
										RoleName:        "Reader",
										SessionDuration: 1800,
										ExpiresAt:       &expiryTime,
									},
								},
								Total: 1,
							}, nil
						}
						return &sca_models.SessionsResponse{Response: []sca_models.SessionInfo{}, Total: 0}, nil
					},
				}
			},
			provider: "azure",
			wantContain: []string{
				"Authenticated as: tim@iosharp.com",
				"Azure sessions:",
				"Reader on Test-Workspace",
			},
			wantErr: false,
		},
		{
			name: "multiple providers (future-proof)",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "user@example.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				expiryTime := now.Add(1 * time.Hour)

				return &mockSessionLister{
					sessions: &sca_models.SessionsResponse{
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "session-azure",
								UserID:          "user@example.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								WorkspaceName:   "Azure-Prod",
								RoleID:          "role-1",
								RoleName:        "Contributor",
								SessionDuration: 3600,
								ExpiresAt:       &expiryTime,
							},
							{
								SessionID:       "session-aws",
								UserID:          "user@example.com",
								CSP:             sca_models.CSPAWS,
								WorkspaceID:     "arn:aws:iam::123456789012:role/Admin",
								WorkspaceName:   "AWS-Account-1",
								RoleID:          "role-arn",
								RoleName:        "Administrator",
								SessionDuration: 3600,
								ExpiresAt:       &expiryTime,
							},
						},
						Total: 2,
					},
					listErr: nil,
				}
			},
			wantContain: []string{
				"Authenticated as: user@example.com",
				"Azure sessions:",
				"Contributor on Azure-Prod",
				"AWS sessions:",
				"Administrator on AWS-Account-1",
			},
			wantErr: false,
		},
		{
			name: "session expiry time formatting - less than 1 hour",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				expiryTime := now.Add(45 * time.Minute)

				return &mockSessionLister{
					sessions: &sca_models.SessionsResponse{
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								WorkspaceName:   "Test-Workspace",
								RoleID:          "role-1",
								RoleName:        "Reader",
								SessionDuration: 2700,
								ExpiresAt:       &expiryTime,
							},
						},
						Total: 1,
					},
					listErr: nil,
				}
			},
			wantContain: []string{
				"45m remaining",
			},
			wantErr: false,
		},
		{
			name: "session expiry time formatting - multiple hours",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				expiryTime := now.Add(2*time.Hour + 30*time.Minute)

				return &mockSessionLister{
					sessions: &sca_models.SessionsResponse{
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								WorkspaceName:   "Test-Workspace",
								RoleID:          "role-1",
								RoleName:        "Reader",
								SessionDuration: 9000,
								ExpiresAt:       &expiryTime,
							},
						},
						Total: 1,
					},
					listErr: nil,
				}
			},
			wantContain: []string{
				"2h 30m remaining",
			},
			wantErr: false,
		},
		{
			name: "session list error",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions:  nil,
					listErr: errors.New("API error: service unavailable"),
				}
			},
			wantContain: []string{
				"failed to list sessions",
				"API error: service unavailable",
			},
			wantErr: true,
		},
		{
			name: "fallback to IDs when names not available",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				expiryTime := now.Add(1 * time.Hour)

				return &mockSessionLister{
					sessions: &sca_models.SessionsResponse{
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/11111111-2222-3333-4444-555555555555",
								WorkspaceName:   "", // No name available
								RoleID:          "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
								RoleName:        "", // No name available
								SessionDuration: 3600,
								ExpiresAt:       &expiryTime,
							},
						},
						Total: 1,
					},
					listErr: nil,
				}
			},
			wantContain: []string{
				"Authenticated as: tim@iosharp.com",
				"Azure sessions:",
				"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
				"/subscriptions/11111111-2222-3333-4444-555555555555",
			},
			wantErr: false,
		},
		{
			name: "invalid provider flag",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &auth_models.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{}
			},
			provider: "invalid",
			wantContain: []string{
				"invalid provider",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create command with mock dependencies
			authLoader := tt.setupAuth()
			sessionLister := tt.setupSvc()
			cmd := NewStatusCommandWithDeps(authLoader, sessionLister)

			// Set provider flag if specified
			if tt.provider != "" {
				cmd.Flags().Set("provider", tt.provider)
			}

			// Execute command
			output, err := executeCommand(cmd)

			// Check error expectation
			if tt.wantErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Verify output contains expected strings
			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}

			// Verify output does not contain unwanted strings
			for _, notWant := range tt.wantNotContain {
				if strings.Contains(output, notWant) {
					t.Errorf("output should not contain %q\ngot:\n%s", notWant, output)
				}
			}
		})
	}
}

func TestStatusCommandIntegration(t *testing.T) {
	// Test that status command is properly registered
	rootCmd := NewRootCommand()
	statusCmd := NewStatusCommand()
	rootCmd.AddCommand(statusCmd)

	// Verify command is accessible
	cmd, _, err := rootCmd.Find([]string{"status"})
	if err != nil {
		t.Fatalf("status command not found: %v", err)
	}

	if cmd.Use != "status" {
		t.Errorf("expected command Use='status', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected command to have Short description")
	}

	// Verify provider flag exists
	providerFlag := cmd.Flags().Lookup("provider")
	if providerFlag == nil {
		t.Error("expected --provider flag to be defined")
	}

	// Verify shorthand
	pFlag := cmd.Flags().ShorthandLookup("p")
	if pFlag == nil {
		t.Error("expected -p shorthand for provider flag")
	}
}

func TestStatusCommandUsage(t *testing.T) {
	cmd := NewStatusCommand()

	// Verify command metadata
	if cmd.Use != "status" {
		t.Errorf("expected Use='status', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	if cmd.Long == "" {
		t.Error("expected non-empty Long description")
	}

	// Verify flags
	providerFlag := cmd.Flags().Lookup("provider")
	if providerFlag == nil {
		t.Fatal("expected --provider flag to be defined")
	}

	if providerFlag.Shorthand != "p" {
		t.Errorf("expected provider flag shorthand 'p', got %q", providerFlag.Shorthand)
	}
}
