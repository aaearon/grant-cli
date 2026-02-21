package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/cache"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func TestStatusCommand(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	tests := []struct {
		name              string
		setupAuth         func() *mockAuthLoader
		setupSvc          func() *mockSessionLister
		setupEligibility  func() *mockEligibilityLister
		provider          string
		wantContain       []string
		wantNotContain    []string
		wantErr           bool
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
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{}
			},
			wantContain: []string{
				"Not authenticated",
				"Run 'grant login' first",
			},
			wantErr: false,
		},
		{
			name: "authenticated with no sessions",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{},
						Total:    0,
					},
					listErr: nil,
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{}
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
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
								RoleID:          "Contributor",
								SessionDuration: 4320, // 72 minutes
							},
							{
								SessionID:       "session-2",
								UserID:          "tim@iosharp.com",
								CSP:             scamodels.CSPAzure,
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
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					response: &scamodels.EligibilityResponse{
						Response: []scamodels.EligibleTarget{
							{
								WorkspaceID:   "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
								WorkspaceName: "Tenant Root Group",
							},
							{
								WorkspaceID:   "/subscriptions/sub-2",
								WorkspaceName: "My Subscription",
							},
						},
					},
				}
			},
			wantContain: []string{
				"Authenticated as: tim@iosharp.com",
				"Azure sessions:",
				"Contributor on Tenant Root Group (providers/Microsoft.Management/managementGroups/29cb7961",
				"duration: 1h 12m",
				"session: session-1",
				"Owner on My Subscription (/subscriptions/sub-2)",
				"duration: 25m",
				"session: session-2",
			},
			wantErr: false,
		},
		{
			name: "filter by provider - Azure",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					listFunc: func(ctx context.Context, csp *scamodels.CSP) (*scamodels.SessionsResponse, error) {
						// Verify the filter is applied
						if csp != nil && *csp == scamodels.CSPAzure {
							return &scamodels.SessionsResponse{
								Response: []scamodels.SessionInfo{
									{
										SessionID:       "session-azure",
										UserID:          "tim@iosharp.com",
										CSP:             scamodels.CSPAzure,
										WorkspaceID:     "/subscriptions/sub-1",
										RoleID:          "Reader",
										SessionDuration: 1800,
									},
								},
								Total: 1,
							}, nil
						}
						return &scamodels.SessionsResponse{Response: []scamodels.SessionInfo{}, Total: 0}, nil
					},
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					response: &scamodels.EligibilityResponse{
						Response: []scamodels.EligibleTarget{
							{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Test Subscription"},
						},
					},
				}
			},
			provider: "azure",
			wantContain: []string{
				"Authenticated as: tim@iosharp.com",
				"Azure sessions:",
				"Reader on Test Subscription (/subscriptions/sub-1)",
				"session: session-azure",
			},
			wantErr: false,
		},
		{
			name: "multiple providers (future-proof)",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "user@example.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "session-azure",
								UserID:          "user@example.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								RoleID:          "Contributor",
								SessionDuration: 3600,
							},
							{
								SessionID:       "session-aws",
								UserID:          "user@example.com",
								CSP:             scamodels.CSPAWS,
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
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					response: &scamodels.EligibilityResponse{
						Response: []scamodels.EligibleTarget{
							{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Dev Subscription"},
						},
					},
				}
			},
			wantContain: []string{
				"Authenticated as: user@example.com",
				"Azure sessions:",
				"Contributor on Dev Subscription (/subscriptions/sub-1)",
				"session: session-azure",
				"AWS sessions:",
				"Administrator on arn:aws:iam::123456789012:role/Admin",
				"session: session-aws",
			},
			wantErr: false,
		},
		{
			name: "session duration formatting - less than 1 hour",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             scamodels.CSPAzure,
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
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{}
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
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             scamodels.CSPAzure,
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
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{}
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
					token: &authmodels.IdsecToken{
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
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{}
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
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "0e796e75-6027-48bd-bf1e-80e3b1024de4",
								UserID:          "tim.schindler@cyberark.cloud.40562",
								CSP:             scamodels.CSPAzure,
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
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					response: &scamodels.EligibilityResponse{
						Response: []scamodels.EligibleTarget{
							{
								WorkspaceID:   "providers/Microsoft.Management/managementGroups/29cb7961-e16d-42c7-8ade-1794bbb76782",
								WorkspaceName: "Tenant Root Group",
							},
						},
					},
				}
			},
			wantContain: []string{
				"Authenticated as: tim@iosharp.com",
				"Azure sessions:",
				"User Access Administrator on Tenant Root Group (providers/Microsoft.Management/managementGroups/29cb7961",
				"duration: 1h 0m",
				"session: 0e796e75-6027-48bd-bf1e-80e3b1024de4",
			},
			wantErr: false,
		},
		{
			name: "eligibility fetch fails - graceful degradation",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "session-1",
								UserID:          "tim@iosharp.com",
								CSP:             scamodels.CSPAzure,
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
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listErr: errors.New("eligibility API unavailable"),
				}
			},
			wantContain: []string{
				"User Access Administrator on providers/Microsoft.Management/managementGroups/29cb7961",
				"duration: 1h 0m",
				"session: session-1",
			},
			wantErr: false,
		},
		{
			name: "mixed cloud and group sessions",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "cloud-session-1",
								UserID:          "tim@iosharp.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								RoleID:          "Contributor",
								SessionDuration: 3600,
							},
							{
								SessionID:       "group-session-1",
								UserID:          "tim@iosharp.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "29cb7961-dir-uuid",
								SessionDuration: 3600,
								Target:          &scamodels.SessionTarget{ID: "group-uuid-1", Type: scamodels.TargetTypeGroups},
							},
						},
						Total: 2,
					},
					listErr: nil,
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					response: &scamodels.EligibilityResponse{
						Response: []scamodels.EligibleTarget{
							{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "My Subscription"},
							{
								OrganizationID: "29cb7961-dir-uuid",
								WorkspaceID:    "29cb7961-dir-uuid",
								WorkspaceName:  "Contoso Directory",
								WorkspaceType:  scamodels.WorkspaceTypeDirectory,
							},
						},
					},
				}
			},
			wantContain: []string{
				"Azure sessions:",
				"Contributor on My Subscription (/subscriptions/sub-1)",
				"session: cloud-session-1",
				"Groups sessions:",
				"Group: group-uuid-1 in Contoso Directory",
				"session: group-session-1",
			},
			wantErr: false,
		},
		{
			name: "only group sessions",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{
						Token:     "test-jwt",
						Username:  "tim@iosharp.com",
						ExpiresIn: expiresIn,
					},
					loadErr: nil,
				}
			},
			setupSvc: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "group-session-1",
								UserID:          "tim@iosharp.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "dir-uuid-123",
								SessionDuration: 1800,
								Target:          &scamodels.SessionTarget{ID: "grp-uuid", Type: scamodels.TargetTypeGroups},
							},
						},
						Total: 1,
					},
					listErr: nil,
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{}
			},
			wantContain: []string{
				"Groups sessions:",
				"Group: grp-uuid in dir-uuid-123",
				"duration: 30m",
			},
			wantNotContain: []string{
				"Azure sessions:",
				"AWS sessions:",
			},
			wantErr: false,
		},
		{
			name: "invalid provider flag",
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{
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
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{}
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
			eligibilityLister := tt.setupEligibility()
			cmd := NewStatusCommandWithDeps(authLoader, sessionLister, eligibilityLister, nil, nil)

			// Set provider flag if specified
			if tt.provider != "" {
				_ = cmd.Flags().Set("provider", tt.provider)
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
	rootCmd := newTestRootCommand()
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


func TestStatusCommand_CachedEligibility(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	// Inner mock returns Azure targets including DIRECTORY type for directory name resolution
	innerElig := newCountingEligibilityLister(&mockEligibilityLister{
		listFunc: func(ctx context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
			if csp == scamodels.CSPAzure {
				return &scamodels.EligibilityResponse{
					Response: []scamodels.EligibleTarget{
						{
							OrganizationID: "org-1",
							WorkspaceID:    "/subscriptions/sub-1",
							WorkspaceName:  "Dev Sub",
						},
						{
							OrganizationID: "dir-1",
							WorkspaceID:    "dir-1",
							WorkspaceName:  "Contoso",
							WorkspaceType:  scamodels.WorkspaceTypeDirectory,
						},
					},
				}, nil
			}
			return &scamodels.EligibilityResponse{Response: []scamodels.EligibleTarget{}}, nil
		},
	})

	// Wrap in CachedEligibilityLister with a real temp dir store
	store := cache.NewStore(t.TempDir(), 4*time.Hour)
	cachedLister := cache.NewCachedEligibilityLister(innerElig, nil, store, false, nil)

	auth := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
	}
	sessions := &mockSessionLister{
		sessions: &scamodels.SessionsResponse{
			Response: []scamodels.SessionInfo{
				{
					SessionID:       "session-1",
					CSP:             scamodels.CSPAzure,
					WorkspaceID:     "/subscriptions/sub-1",
					RoleID:          "Contributor",
					SessionDuration: 3600,
				},
			},
			Total: 1,
		},
	}

	cmd := NewStatusCommandWithDeps(auth, sessions, cachedLister, nil, nil)
	output, err := executeCommand(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "Dev Sub") {
		t.Errorf("output missing workspace name, got:\n%s", output)
	}

	// Key assertion: Azure inner was called only once.
	// fetchStatusData calls Azure once, then buildDirectoryNameMap calls Azure again,
	// but the second call is a cache hit.
	if got := innerElig.CallCount(scamodels.CSPAzure); got != 1 {
		t.Errorf("Azure inner called %d times, want 1 (cache should deduplicate)", got)
	}

	// AWS was called once by fetchStatusData
	if got := innerElig.CallCount(scamodels.CSPAWS); got != 1 {
		t.Errorf("AWS inner called %d times, want 1", got)
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

func TestStatusCommand_JSONOutput(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	tests := []struct {
		name     string
		auth     *mockAuthLoader
		sessions *mockSessionLister
		elig     *mockEligibilityLister
		validate func(t *testing.T, output string)
	}{
		{
			name:     "not authenticated",
			auth:     &mockAuthLoader{loadErr: errors.New("no token")},
			sessions: &mockSessionLister{},
			elig:     &mockEligibilityLister{},
			validate: func(t *testing.T, output string) {
				var out statusOutput
				if err := json.Unmarshal([]byte(output), &out); err != nil {
					t.Fatalf("invalid JSON: %v\n%s", err, output)
				}
				if out.Authenticated {
					t.Error("expected authenticated=false")
				}
				if len(out.Sessions) != 0 {
					t.Errorf("expected empty sessions, got %d", len(out.Sessions))
				}
			},
		},
		{
			name: "with sessions",
			auth: &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt", Username: "user@test.com", ExpiresIn: expiresIn}},
			sessions: &mockSessionLister{
				sessions: &scamodels.SessionsResponse{Response: []scamodels.SessionInfo{
					{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "sub-1", RoleID: "Contributor", SessionDuration: 3600},
				}},
			},
			elig: &mockEligibilityLister{response: &scamodels.EligibilityResponse{
				Response: []scamodels.EligibleTarget{{WorkspaceID: "sub-1", WorkspaceName: "Prod"}},
			}},
			validate: func(t *testing.T, output string) {
				var out statusOutput
				if err := json.Unmarshal([]byte(output), &out); err != nil {
					t.Fatalf("invalid JSON: %v\n%s", err, output)
				}
				if !out.Authenticated {
					t.Error("expected authenticated=true")
				}
				if out.Username != "user@test.com" {
					t.Errorf("username = %q, want user@test.com", out.Username)
				}
				if len(out.Sessions) != 1 {
					t.Fatalf("expected 1 session, got %d", len(out.Sessions))
				}
				if out.Sessions[0].SessionID != "s1" {
					t.Errorf("sessionId = %q, want s1", out.Sessions[0].SessionID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewStatusCommandWithDeps(tt.auth, tt.sessions, tt.elig, nil, nil)
			root := newTestRootCommand()
			root.AddCommand(cmd)

			output, err := executeCommand(root, "status", "--output", "json")
			if err != nil {
				t.Fatalf("unexpected error: %v\noutput: %s", err, output)
			}
			tt.validate(t, output)
		})
	}
}

func TestStatusCommand_GroupNameResolution(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	auth := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "jwt", Username: "user@test.com", ExpiresIn: expiresIn},
	}
	sessions := &mockSessionLister{
		sessions: &scamodels.SessionsResponse{
			Response: []scamodels.SessionInfo{
				{
					SessionID:       "group-session-1",
					CSP:             scamodels.CSPAzure,
					WorkspaceID:     "dir-uuid-1",
					SessionDuration: 3600,
					Target:          &scamodels.SessionTarget{ID: "grp-uuid-1", Type: scamodels.TargetTypeGroups},
				},
			},
			Total: 1,
		},
	}
	elig := &mockEligibilityLister{
		response: &scamodels.EligibilityResponse{
			Response: []scamodels.EligibleTarget{
				{
					WorkspaceID:   "dir-uuid-1",
					WorkspaceName: "Contoso Directory",
					WorkspaceType: scamodels.WorkspaceTypeDirectory,
				},
			},
		},
	}
	groupsElig := &mockGroupsEligibilityLister{
		response: &scamodels.GroupsEligibilityResponse{
			Response: []scamodels.GroupsEligibleTarget{
				{GroupID: "grp-uuid-1", GroupName: "CloudAdmins", DirectoryID: "dir-uuid-1"},
			},
			Total: 1,
		},
	}

	t.Run("text output shows group name", func(t *testing.T) {
		old := outputFormat
		defer func() { outputFormat = old }()
		outputFormat = "text"

		cmd := NewStatusCommandWithDeps(auth, sessions, elig, groupsElig, nil)
		output, err := executeCommand(cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(output, "Group: CloudAdmins in Contoso Directory") {
			t.Errorf("output missing group name, got:\n%s", output)
		}
	})

	t.Run("JSON output includes groupName", func(t *testing.T) {
		cmd := NewStatusCommandWithDeps(auth, sessions, elig, groupsElig, nil)
		root := newTestRootCommand()
		root.AddCommand(cmd)

		output, err := executeCommand(root, "status", "--output", "json")
		if err != nil {
			t.Fatalf("unexpected error: %v\noutput: %s", err, output)
		}

		var out statusOutput
		if err := json.Unmarshal([]byte(output), &out); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, output)
		}
		if len(out.Sessions) != 1 {
			t.Fatalf("expected 1 session, got %d", len(out.Sessions))
		}
		if out.Sessions[0].GroupName != "CloudAdmins" {
			t.Errorf("groupName = %q, want CloudAdmins", out.Sessions[0].GroupName)
		}
		if out.Sessions[0].GroupID != "grp-uuid-1" {
			t.Errorf("groupId = %q, want grp-uuid-1", out.Sessions[0].GroupID)
		}
	})

	t.Run("group session without group name falls back to UUID", func(t *testing.T) {
		old := outputFormat
		defer func() { outputFormat = old }()
		outputFormat = "text"

		emptyGroupsElig := &mockGroupsEligibilityLister{
			response: &scamodels.GroupsEligibilityResponse{
				Response: []scamodels.GroupsEligibleTarget{},
				Total:    0,
			},
		}
		cmd := NewStatusCommandWithDeps(auth, sessions, elig, emptyGroupsElig, nil)
		output, err := executeCommand(cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(output, "Group: grp-uuid-1 in Contoso Directory") {
			t.Errorf("output should fall back to UUID, got:\n%s", output)
		}
	})
}

func TestStatusCommand_RemainingTime(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	auth := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "jwt", Username: "user@test.com", ExpiresIn: expiresIn},
	}
	sessions := &mockSessionLister{
		sessions: &scamodels.SessionsResponse{
			Response: []scamodels.SessionInfo{
				{
					SessionID:       "tracked-session",
					CSP:             scamodels.CSPAzure,
					WorkspaceID:     "/subscriptions/sub-1",
					RoleID:          "Contributor",
					SessionDuration: 3600, // 1 hour
				},
				{
					SessionID:       "untracked-session",
					CSP:             scamodels.CSPAzure,
					WorkspaceID:     "/subscriptions/sub-2",
					RoleID:          "Reader",
					SessionDuration: 1800,
				},
			},
			Total: 2,
		},
	}
	elig := &mockEligibilityLister{
		response: &scamodels.EligibilityResponse{
			Response: []scamodels.EligibleTarget{},
		},
	}

	// Create a tracker with a recorded session timestamp
	tracker := cache.NewStore(t.TempDir(), 25*time.Hour)
	elevatedAt := now.Add(-15 * time.Minute) // elevated 15 minutes ago
	if err := cache.RecordSession(tracker, "tracked-session", elevatedAt); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	t.Run("text output shows remaining time", func(t *testing.T) {
		old := outputFormat
		defer func() { outputFormat = old }()
		outputFormat = "text"

		cmd := NewStatusCommandWithDeps(auth, sessions, elig, nil, tracker)
		output, err := executeCommand(cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(output, "remaining: 4") {
			t.Errorf("output should show remaining time, got:\n%s", output)
		}
		// Untracked session should show duration
		if !strings.Contains(output, "duration: 30m") {
			t.Errorf("untracked session should show duration, got:\n%s", output)
		}
	})

	t.Run("JSON output includes remainingSeconds for tracked session", func(t *testing.T) {
		cmd := NewStatusCommandWithDeps(auth, sessions, elig, nil, tracker)
		root := newTestRootCommand()
		root.AddCommand(cmd)

		output, err := executeCommand(root, "status", "--output", "json")
		if err != nil {
			t.Fatalf("unexpected error: %v\noutput: %s", err, output)
		}

		var out statusOutput
		if err := json.Unmarshal([]byte(output), &out); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, output)
		}
		if len(out.Sessions) != 2 {
			t.Fatalf("expected 2 sessions, got %d", len(out.Sessions))
		}

		// Find tracked and untracked sessions
		var tracked, untracked *sessionOutput
		for i := range out.Sessions {
			if out.Sessions[i].SessionID == "tracked-session" {
				tracked = &out.Sessions[i]
			}
			if out.Sessions[i].SessionID == "untracked-session" {
				untracked = &out.Sessions[i]
			}
		}

		if tracked == nil {
			t.Fatal("tracked session not found in output")
		}
		if tracked.RemainingSeconds == nil {
			t.Error("tracked session should have remainingSeconds")
		} else if *tracked.RemainingSeconds < 2500 || *tracked.RemainingSeconds > 2800 {
			t.Errorf("remainingSeconds = %d, expected ~2700 (45 min)", *tracked.RemainingSeconds)
		}

		if untracked == nil {
			t.Fatal("untracked session not found in output")
		}
		if untracked.RemainingSeconds != nil {
			t.Errorf("untracked session should not have remainingSeconds, got %d", *untracked.RemainingSeconds)
		}
	})

	t.Run("nil tracker shows duration for all sessions", func(t *testing.T) {
		old := outputFormat
		defer func() { outputFormat = old }()
		outputFormat = "text"

		cmd := NewStatusCommandWithDeps(auth, sessions, elig, nil, nil)
		output, err := executeCommand(cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(output, "remaining:") {
			t.Errorf("output should not contain remaining without tracker, got:\n%s", output)
		}
		if !strings.Contains(output, "duration: 1h 0m") {
			t.Errorf("output should show duration for tracked session, got:\n%s", output)
		}
	})
}

func TestComputeRemainingTime(t *testing.T) {
	tests := []struct {
		name       string
		sessions   []scamodels.SessionInfo
		timestamps map[string]time.Time
		wantNil    bool
		wantKeys   []string
	}{
		{
			name:       "empty timestamps returns nil",
			sessions:   []scamodels.SessionInfo{{SessionID: "s1"}},
			timestamps: map[string]time.Time{},
			wantNil:    true,
		},
		{
			name:       "no matching sessions returns nil",
			sessions:   []scamodels.SessionInfo{{SessionID: "s1"}},
			timestamps: map[string]time.Time{"other": time.Now()},
			wantNil:    true,
		},
		{
			name: "matching session computes remaining",
			sessions: []scamodels.SessionInfo{
				{SessionID: "s1", SessionDuration: 3600},
			},
			timestamps: map[string]time.Time{"s1": time.Now().Add(-15 * time.Minute)},
			wantKeys:   []string{"s1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeRemainingTime(tt.sessions, tt.timestamps)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			for _, key := range tt.wantKeys {
				if _, ok := result[key]; !ok {
					t.Errorf("expected key %q in result", key)
				}
			}
		})
	}
}
