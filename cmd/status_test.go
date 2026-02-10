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
		name           string
		setupAuth      func() *mockAuthLoader
		setupSvc       func() *mockSessionLister
		provider       string
		wantContain    []string
		wantNotContain []string
		wantErr        bool
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
				return &mockSessionLister{
					sessions: &sca_models.SessionsResponse{
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
								RoleID:          "Contributor",
								SessionDuration: 4320, // 72 minutes
							},
							{
								SessionID:       "session-2",
								UserID:          "tim@iosharp.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-2",
								RoleID:          "Owner",
								SessionDuration: 1500, // 25 minutes
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
				"Contributor on providers/Microsoft.Management/managementGroups/29cb7961",
				"duration: 1h 12m",
				"Owner on /subscriptions/sub-2",
				"duration: 25m",
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
							return &sca_models.SessionsResponse{
								Response: []sca_models.SessionInfo{
									{
										SessionID:       "session-azure",
										UserID:          "tim@iosharp.com",
										CSP:             sca_models.CSPAzure,
										WorkspaceID:     "/subscriptions/sub-1",
										RoleID:          "Reader",
										SessionDuration: 1800,
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
				"Reader on /subscriptions/sub-1",
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
				return &mockSessionLister{
					sessions: &sca_models.SessionsResponse{
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "session-azure",
								UserID:          "user@example.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								RoleID:          "Contributor",
								SessionDuration: 3600,
							},
							{
								SessionID:       "session-aws",
								UserID:          "user@example.com",
								CSP:             sca_models.CSPAWS,
								WorkspaceID:     "arn:aws:iam::123456789012:role/Admin",
								RoleID:          "Administrator",
								SessionDuration: 3600,
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
				"Contributor on /subscriptions/sub-1",
				"AWS sessions:",
				"Administrator on arn:aws:iam::123456789012:role/Admin",
			},
			wantErr: false,
		},
		{
			name: "session duration formatting - less than 1 hour",
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
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								RoleID:          "Reader",
								SessionDuration: 2700, // 45 minutes
							},
						},
						Total: 1,
					},
					listErr: nil,
				}
			},
			wantContain: []string{
				"duration: 45m",
			},
			wantErr: false,
		},
		{
			name: "session duration formatting - multiple hours",
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
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								RoleID:          "Reader",
								SessionDuration: 9000, // 2h 30m
							},
						},
						Total: 1,
					},
					listErr: nil,
				}
			},
			wantContain: []string{
				"duration: 2h 30m",
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
					sessions: nil,
					listErr:  errors.New("API error: service unavailable"),
				}
			},
			wantContain: []string{
				"failed to list sessions",
				"API error: service unavailable",
			},
			wantErr: true,
		},
		{
			name: "real API format - role name in role_id field",
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
						Response: []sca_models.SessionInfo{
							{
								SessionID:       "0e796e75-6027-48bd-bf1e-80e3b1024de4",
								UserID:          "tim.schindler@cyberark.cloud.40562",
								CSP:             sca_models.CSPAzure,
								WorkspaceID:     "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
								RoleID:          "User Access Administrator",
								SessionDuration: 3600,
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
				"User Access Administrator on providers/Microsoft.Management/managementGroups/29cb7961",
				"duration: 1h 0m",
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
