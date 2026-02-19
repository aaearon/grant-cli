// NOTE: Do not use t.Parallel() in cmd/ tests due to package-level state
// (verbose, passedArgValidation) that is mutated during test execution.
package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/cache"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func TestRevokeCommand(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	activeSessions := &scamodels.SessionsResponse{
		Response: []scamodels.SessionInfo{
			{
				SessionID:       "session-1",
				UserID:          "user@example.com",
				CSP:             scamodels.CSPAzure,
				WorkspaceID:     "/subscriptions/sub-1",
				RoleID:          "Contributor",
				SessionDuration: 3600,
			},
			{
				SessionID:       "session-2",
				UserID:          "user@example.com",
				CSP:             scamodels.CSPAzure,
				WorkspaceID:     "/subscriptions/sub-2",
				RoleID:          "Reader",
				SessionDuration: 1800,
			},
		},
		Total: 2,
	}

	tests := []struct {
		name           string
		args           []string
		setupAuth      func() *mockAuthLoader
		setupLister    func() *mockSessionLister
		setupElig      func() *mockEligibilityLister
		setupRevoker   func() *mockSessionRevoker
		setupSelector  func() *mockSessionSelector
		setupConfirm   func() *mockConfirmPrompter
		wantContain    []string
		wantNotContain []string
		wantErr        bool
	}{
		{
			name: "not authenticated",
			args: []string{"--all", "--yes"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{loadErr: errNotAuthenticated}
			},
			setupLister:   func() *mockSessionLister { return &mockSessionLister{} },
			setupElig:     func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker:  func() *mockSessionRevoker { return &mockSessionRevoker{} },
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"not authenticated"},
			wantErr:       true,
		},
		{
			name: "no active sessions",
			args: []string{"--all", "--yes"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{sessions: &scamodels.SessionsResponse{Response: []scamodels.SessionInfo{}, Total: 0}}
			},
			setupElig:     func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker:  func() *mockSessionRevoker { return &mockSessionRevoker{} },
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"No active sessions to revoke"},
			wantErr:       false,
		},
		{
			name: "direct mode - single session ID",
			args: []string{"session-1"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister { return &mockSessionLister{} },
			setupElig:   func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					response: &scamodels.RevokeResponse{
						Response: []scamodels.RevocationResult{
							{SessionID: "session-1", RevocationStatus: scamodels.RevocationSuccessful},
						},
					},
				}
			},
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"session-1", "SUCCESSFULLY_REVOKED"},
			wantErr:       false,
		},
		{
			name: "direct mode - multiple session IDs",
			args: []string{"session-1", "session-2"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister { return &mockSessionLister{} },
			setupElig:   func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					response: &scamodels.RevokeResponse{
						Response: []scamodels.RevocationResult{
							{SessionID: "session-1", RevocationStatus: scamodels.RevocationSuccessful},
							{SessionID: "session-2", RevocationStatus: scamodels.RevocationInProgress},
						},
					},
				}
			},
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"session-1", "SUCCESSFULLY_REVOKED", "session-2", "REVOCATION_IN_PROGRESS"},
			wantErr:       false,
		},
		{
			name: "all mode - revokes all sessions",
			args: []string{"--all", "--yes"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{sessions: activeSessions}
			},
			setupElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					revokeFunc: func(ctx context.Context, req *scamodels.RevokeRequest) (*scamodels.RevokeResponse, error) {
						if len(req.SessionIDs) != 2 {
							t.Errorf("expected 2 session IDs, got %d", len(req.SessionIDs))
						}
						return &scamodels.RevokeResponse{
							Response: []scamodels.RevocationResult{
								{SessionID: "session-1", RevocationStatus: scamodels.RevocationSuccessful},
								{SessionID: "session-2", RevocationStatus: scamodels.RevocationSuccessful},
							},
						}, nil
					},
				}
			},
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"session-1", "session-2", "SUCCESSFULLY_REVOKED"},
			wantErr:       false,
		},
		{
			name: "all mode with provider filter",
			args: []string{"--all", "--yes", "--provider", "azure"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{
					listFunc: func(ctx context.Context, csp *scamodels.CSP) (*scamodels.SessionsResponse, error) {
						if csp == nil || *csp != scamodels.CSPAzure {
							t.Errorf("expected Azure filter, got %v", csp)
						}
						return activeSessions, nil
					},
				}
			},
			setupElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					response: &scamodels.RevokeResponse{
						Response: []scamodels.RevocationResult{
							{SessionID: "session-1", RevocationStatus: scamodels.RevocationSuccessful},
							{SessionID: "session-2", RevocationStatus: scamodels.RevocationSuccessful},
						},
					},
				}
			},
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"SUCCESSFULLY_REVOKED"},
			wantErr:       false,
		},
		{
			name: "all mode - confirmation required and confirmed",
			args: []string{"--all"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{sessions: activeSessions}
			},
			setupElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					response: &scamodels.RevokeResponse{
						Response: []scamodels.RevocationResult{
							{SessionID: "session-1", RevocationStatus: scamodels.RevocationSuccessful},
							{SessionID: "session-2", RevocationStatus: scamodels.RevocationSuccessful},
						},
					},
				}
			},
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{confirmed: true} },
			wantContain:   []string{"SUCCESSFULLY_REVOKED"},
			wantErr:       false,
		},
		{
			name: "all mode - confirmation cancelled",
			args: []string{"--all"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{sessions: activeSessions}
			},
			setupElig:     func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker:  func() *mockSessionRevoker { return &mockSessionRevoker{} },
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{confirmed: false} },
			wantContain:   []string{"Revocation cancelled"},
			wantErr:       false,
		},
		{
			name: "all mode with args - mutual exclusivity error",
			args: []string{"--all", "session-1"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister:   func() *mockSessionLister { return &mockSessionLister{} },
			setupElig:     func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker:  func() *mockSessionRevoker { return &mockSessionRevoker{} },
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"--all", "cannot be used with session ID arguments"},
			wantErr:       true,
		},
		{
			name: "interactive mode - sessions selected",
			args: []string{},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{sessions: activeSessions}
			},
			setupElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					response: &scamodels.RevokeResponse{
						Response: []scamodels.RevocationResult{
							{SessionID: "session-1", RevocationStatus: scamodels.RevocationSuccessful},
						},
					},
				}
			},
			setupSelector: func() *mockSessionSelector {
				return &mockSessionSelector{
					sessions: []scamodels.SessionInfo{
						{SessionID: "session-1", CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1", RoleID: "Contributor", SessionDuration: 3600},
					},
				}
			},
			setupConfirm: func() *mockConfirmPrompter { return &mockConfirmPrompter{confirmed: true} },
			wantContain:  []string{"session-1", "SUCCESSFULLY_REVOKED"},
			wantErr:      false,
		},
		{
			name: "API error propagated",
			args: []string{"session-1"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister { return &mockSessionLister{} },
			setupElig:   func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{revokeErr: errors.New("API error: forbidden")}
			},
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"API error: forbidden"},
			wantErr:       true,
		},
		{
			name: "direct mode with --provider - mutual exclusivity error",
			args: []string{"--provider", "azure", "session-1"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister:   func() *mockSessionLister { return &mockSessionLister{} },
			setupElig:     func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker:  func() *mockSessionRevoker { return &mockSessionRevoker{} },
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"--provider cannot be used with session ID arguments"},
			wantErr:       true,
		},
		{
			name: "all mode - list sessions error",
			args: []string{"--all", "--yes"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{listErr: errors.New("service unavailable")}
			},
			setupElig:     func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker:  func() *mockSessionRevoker { return &mockSessionRevoker{} },
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"failed to list sessions"},
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
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{sessions: activeSessions}
			},
			setupElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker { return &mockSessionRevoker{} },
			setupSelector: func() *mockSessionSelector {
				return &mockSessionSelector{selectErr: errors.New("prompt interrupted")}
			},
			setupConfirm: func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:  []string{"session selection failed"},
			wantErr:      true,
		},
		{
			name: "interactive mode with --yes skips confirmation",
			args: []string{"--yes"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{sessions: activeSessions}
			},
			setupElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					response: &scamodels.RevokeResponse{
						Response: []scamodels.RevocationResult{
							{SessionID: "session-1", RevocationStatus: scamodels.RevocationSuccessful},
						},
					},
				}
			},
			setupSelector: func() *mockSessionSelector {
				return &mockSessionSelector{
					sessions: []scamodels.SessionInfo{
						{SessionID: "session-1", CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1", RoleID: "Contributor", SessionDuration: 3600},
					},
				}
			},
			setupConfirm: func() *mockConfirmPrompter {
				return &mockConfirmPrompter{
					confirmFunc: func(count int) (bool, error) {
						t.Error("ConfirmRevocation should not be called with --yes flag")
						return false, nil
					},
				}
			},
			wantContain: []string{"session-1", "SUCCESSFULLY_REVOKED"},
			wantErr:     false,
		},
		{
			name: "direct mode - group session ID",
			args: []string{"group-session-1"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister { return &mockSessionLister{} },
			setupElig:   func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					revokeFunc: func(ctx context.Context, req *scamodels.RevokeRequest) (*scamodels.RevokeResponse, error) {
						if len(req.SessionIDs) != 1 || req.SessionIDs[0] != "group-session-1" {
							t.Errorf("expected [group-session-1], got %v", req.SessionIDs)
						}
						return &scamodels.RevokeResponse{
							Response: []scamodels.RevocationResult{
								{SessionID: "group-session-1", RevocationStatus: scamodels.RevocationSuccessful},
							},
						}, nil
					},
				}
			},
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"group-session-1", "SUCCESSFULLY_REVOKED"},
			wantErr:       false,
		},
		{
			name: "all mode - mixed cloud and group sessions",
			args: []string{"--all", "--yes"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "cloud-session-1",
								UserID:          "user@example.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								RoleID:          "Contributor",
								SessionDuration: 3600,
							},
							{
								SessionID:       "group-session-1",
								UserID:          "user@example.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "29cb7961-dir-uuid",
								SessionDuration: 3600,
								Target:          &scamodels.SessionTarget{ID: "group-uuid-1", Type: scamodels.TargetTypeGroups},
							},
							{
								SessionID:       "group-session-2",
								UserID:          "user@example.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "29cb7961-dir-uuid",
								SessionDuration: 1800,
								Target:          &scamodels.SessionTarget{ID: "group-uuid-2", Type: scamodels.TargetTypeGroups},
							},
						},
						Total: 3,
					},
				}
			},
			setupElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					revokeFunc: func(ctx context.Context, req *scamodels.RevokeRequest) (*scamodels.RevokeResponse, error) {
						if len(req.SessionIDs) != 3 {
							t.Errorf("expected 3 session IDs, got %d", len(req.SessionIDs))
						}
						// Verify all session IDs are collected regardless of type
						ids := make(map[string]bool)
						for _, id := range req.SessionIDs {
							ids[id] = true
						}
						for _, want := range []string{"cloud-session-1", "group-session-1", "group-session-2"} {
							if !ids[want] {
								t.Errorf("missing session ID %q in revoke request", want)
							}
						}
						return &scamodels.RevokeResponse{
							Response: []scamodels.RevocationResult{
								{SessionID: "cloud-session-1", RevocationStatus: scamodels.RevocationSuccessful},
								{SessionID: "group-session-1", RevocationStatus: scamodels.RevocationSuccessful},
								{SessionID: "group-session-2", RevocationStatus: scamodels.RevocationSuccessful},
							},
						}, nil
					},
				}
			},
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"cloud-session-1", "group-session-1", "group-session-2", "SUCCESSFULLY_REVOKED"},
			wantErr:       false,
		},
		{
			name: "interactive mode - mixed sessions with group session selected",
			args: []string{"--yes"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{
								SessionID:       "cloud-session-1",
								UserID:          "user@example.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "/subscriptions/sub-1",
								RoleID:          "Contributor",
								SessionDuration: 3600,
							},
							{
								SessionID:       "group-session-1",
								UserID:          "user@example.com",
								CSP:             scamodels.CSPAzure,
								WorkspaceID:     "29cb7961-dir-uuid",
								SessionDuration: 3600,
								Target:          &scamodels.SessionTarget{ID: "group-uuid", Type: scamodels.TargetTypeGroups},
							},
						},
						Total: 2,
					},
				}
			},
			setupElig: func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker: func() *mockSessionRevoker {
				return &mockSessionRevoker{
					revokeFunc: func(ctx context.Context, req *scamodels.RevokeRequest) (*scamodels.RevokeResponse, error) {
						if len(req.SessionIDs) != 1 || req.SessionIDs[0] != "group-session-1" {
							t.Errorf("expected [group-session-1], got %v", req.SessionIDs)
						}
						return &scamodels.RevokeResponse{
							Response: []scamodels.RevocationResult{
								{SessionID: "group-session-1", RevocationStatus: scamodels.RevocationSuccessful},
							},
						}, nil
					},
				}
			},
			setupSelector: func() *mockSessionSelector {
				return &mockSessionSelector{
					sessions: []scamodels.SessionInfo{
						{
							SessionID:       "group-session-1",
							UserID:          "user@example.com",
							CSP:             scamodels.CSPAzure,
							WorkspaceID:     "29cb7961-dir-uuid",
							SessionDuration: 3600,
							Target:          &scamodels.SessionTarget{ID: "group-uuid", Type: scamodels.TargetTypeGroups},
						},
					},
				}
			},
			setupConfirm: func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:  []string{"group-session-1", "SUCCESSFULLY_REVOKED"},
			wantErr:      false,
		},
		{
			name: "invalid provider",
			args: []string{"--all", "--provider", "invalid"},
			setupAuth: func() *mockAuthLoader {
				return &mockAuthLoader{
					token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
				}
			},
			setupLister:   func() *mockSessionLister { return &mockSessionLister{} },
			setupElig:     func() *mockEligibilityLister { return &mockEligibilityLister{} },
			setupRevoker:  func() *mockSessionRevoker { return &mockSessionRevoker{} },
			setupSelector: func() *mockSessionSelector { return &mockSessionSelector{} },
			setupConfirm:  func() *mockConfirmPrompter { return &mockConfirmPrompter{} },
			wantContain:   []string{"invalid provider"},
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := tt.setupAuth()
			lister := tt.setupLister()
			elig := tt.setupElig()
			revoker := tt.setupRevoker()
			selector := tt.setupSelector()
			confirmer := tt.setupConfirm()

			cmd := NewRevokeCommandWithDeps(auth, lister, elig, revoker, selector, confirmer)
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
			for _, notWant := range tt.wantNotContain {
				if strings.Contains(output, notWant) {
					t.Errorf("output should not contain %q\ngot:\n%s", notWant, output)
				}
			}
		})
	}
}

func TestRevokeCommand_CachedEligibility(t *testing.T) {
	now := time.Now()
	expiresIn := commonmodels.IdsecRFC3339Time(now.Add(1 * time.Hour))

	innerElig := newCountingEligibilityLister(&mockEligibilityLister{
		response: &scamodels.EligibilityResponse{
			Response: []scamodels.EligibleTarget{
				{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Dev Sub"},
			},
		},
	})

	store := cache.NewStore(t.TempDir(), 4*time.Hour)
	cachedLister := cache.NewCachedEligibilityLister(innerElig, nil, store, false, nil)

	auth := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn},
	}
	sessions := &mockSessionLister{
		sessions: &scamodels.SessionsResponse{
			Response: []scamodels.SessionInfo{
				{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1", RoleID: "Contributor", SessionDuration: 3600},
			},
			Total: 1,
		},
	}
	revoker := &mockSessionRevoker{
		response: &scamodels.RevokeResponse{
			Response: []scamodels.RevocationResult{
				{SessionID: "s1", RevocationStatus: scamodels.RevocationSuccessful},
			},
		},
	}
	selector := &mockSessionSelector{
		sessions: []scamodels.SessionInfo{
			{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1", RoleID: "Contributor", SessionDuration: 3600},
		},
	}
	confirmer := &mockConfirmPrompter{confirmed: true}

	cmd := NewRevokeCommandWithDeps(auth, sessions, cachedLister, revoker, selector, confirmer)
	output, err := executeCommand(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "SUCCESSFULLY_REVOKED") {
		t.Errorf("expected successful revocation, got:\n%s", output)
	}

	// buildWorkspaceNameMap calls ListEligibility once per unique CSP in sessions
	if got := innerElig.CallCount(scamodels.CSPAzure); got != 1 {
		t.Errorf("Azure inner called %d times, want 1", got)
	}
}

func TestRevokeCommandUsage(t *testing.T) {
	cmd := NewRevokeCommand()

	if cmd.Use != "revoke [session-id...]" {
		t.Errorf("expected Use='revoke [session-id...]', got %q", cmd.Use)
	}
	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	// Verify flags
	allFlag := cmd.Flags().Lookup("all")
	if allFlag == nil {
		t.Fatal("expected --all flag")
	}
	if allFlag.Shorthand != "a" {
		t.Errorf("expected -a shorthand, got %q", allFlag.Shorthand)
	}

	yesFlag := cmd.Flags().Lookup("yes")
	if yesFlag == nil {
		t.Fatal("expected --yes flag")
	}
	if yesFlag.Shorthand != "y" {
		t.Errorf("expected -y shorthand, got %q", yesFlag.Shorthand)
	}

	providerFlag := cmd.Flags().Lookup("provider")
	if providerFlag == nil {
		t.Fatal("expected --provider flag")
	}
}
