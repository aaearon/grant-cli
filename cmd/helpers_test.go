package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

func TestFetchStatusData(t *testing.T) {
	tests := []struct {
		name             string
		setupSessions    func() *mockSessionLister
		setupEligibility func() *mockEligibilityLister
		cspFilter        *scamodels.CSP
		wantErr          bool
		wantErrContain   string
		wantSessions     int
		wantNameMapKeys  []string
	}{
		{
			name: "both sessions and eligibility succeed",
			setupSessions: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
							{SessionID: "s2", CSP: scamodels.CSPAWS, WorkspaceID: "arn:aws:iam::123:role/Admin"},
						},
						Total: 2,
					},
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
						switch csp {
						case scamodels.CSPAzure:
							return &scamodels.EligibilityResponse{
								Response: []scamodels.EligibleTarget{
									{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Dev Sub"},
								},
							}, nil
						case scamodels.CSPAWS:
							return &scamodels.EligibilityResponse{
								Response: []scamodels.EligibleTarget{
									{WorkspaceID: "arn:aws:iam::123:role/Admin", WorkspaceName: "Admin Account"},
								},
							}, nil
						}
						return &scamodels.EligibilityResponse{}, nil
					},
				}
			},
			wantSessions:    2,
			wantNameMapKeys: []string{"/subscriptions/sub-1", "arn:aws:iam::123:role/Admin"},
		},
		{
			name: "sessions error propagated",
			setupSessions: func() *mockSessionLister {
				return &mockSessionLister{
					listErr: errors.New("API error: service unavailable"),
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{}
			},
			wantErr:        true,
			wantErrContain: "failed to list sessions",
		},
		{
			name: "single eligibility error - graceful degradation",
			setupSessions: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
						},
						Total: 1,
					},
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
						if csp == scamodels.CSPAWS {
							return nil, errors.New("AWS unavailable")
						}
						return &scamodels.EligibilityResponse{
							Response: []scamodels.EligibleTarget{
								{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Dev Sub"},
							},
						}, nil
					},
				}
			},
			wantSessions:    1,
			wantNameMapKeys: []string{"/subscriptions/sub-1"},
		},
		{
			name: "all eligibility errors - empty name map, sessions still returned",
			setupSessions: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{
							{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
						},
						Total: 1,
					},
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listErr: errors.New("eligibility unavailable"),
				}
			},
			wantSessions:    1,
			wantNameMapKeys: nil,
		},
		{
			name: "no sessions - empty name map",
			setupSessions: func() *mockSessionLister {
				return &mockSessionLister{
					sessions: &scamodels.SessionsResponse{
						Response: []scamodels.SessionInfo{},
						Total:    0,
					},
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					response: &scamodels.EligibilityResponse{
						Response: []scamodels.EligibleTarget{
							{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Dev Sub"},
						},
					},
				}
			},
			wantSessions: 0,
		},
		{
			name: "with provider filter - only filtered CSP eligibility called",
			setupSessions: func() *mockSessionLister {
				cspAzure := scamodels.CSPAzure
				return &mockSessionLister{
					listFunc: func(ctx context.Context, csp *scamodels.CSP) (*scamodels.SessionsResponse, error) {
						if csp == nil || *csp != cspAzure {
							return nil, errors.New("expected azure filter")
						}
						return &scamodels.SessionsResponse{
							Response: []scamodels.SessionInfo{
								{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
							},
							Total: 1,
						}, nil
					},
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
						if csp != scamodels.CSPAzure {
							return nil, errors.New("should not call non-Azure eligibility")
						}
						return &scamodels.EligibilityResponse{
							Response: []scamodels.EligibleTarget{
								{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Dev Sub"},
							},
						}, nil
					},
				}
			},
			cspFilter:       func() *scamodels.CSP { c := scamodels.CSPAzure; return &c }(),
			wantSessions:    1,
			wantNameMapKeys: []string{"/subscriptions/sub-1"},
		},
		{
			name: "context cancellation - no hang",
			setupSessions: func() *mockSessionLister {
				return &mockSessionLister{
					listFunc: func(ctx context.Context, csp *scamodels.CSP) (*scamodels.SessionsResponse, error) {
						return nil, ctx.Err()
					},
				}
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.name == "context cancellation - no hang" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			sessionLister := tt.setupSessions()
			eligLister := tt.setupEligibility()
			var errBuf bytes.Buffer

			data, err := fetchStatusData(ctx, sessionLister, eligLister, tt.cspFilter, &errBuf)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.wantErrContain != "" && !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErrContain)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(data.sessions.Response) != tt.wantSessions {
				t.Errorf("got %d sessions, want %d", len(data.sessions.Response), tt.wantSessions)
			}

			for _, key := range tt.wantNameMapKeys {
				if _, ok := data.nameMap[key]; !ok {
					t.Errorf("nameMap missing key %q, got: %v", key, data.nameMap)
				}
			}
		})
	}
}

func TestFetchStatusData_VerboseWarning(t *testing.T) {
	oldVerbose := verbose
	verbose = true
	defer func() { verbose = oldVerbose }()

	ctx := context.Background()
	sessionLister := &mockSessionLister{
		sessions: &scamodels.SessionsResponse{
			Response: []scamodels.SessionInfo{
				{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
			},
			Total: 1,
		},
	}
	eligLister := &mockEligibilityLister{
		listErr: errors.New("eligibility API unavailable"),
	}

	var errBuf bytes.Buffer
	data, err := fetchStatusData(ctx, sessionLister, eligLister, nil, &errBuf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.sessions.Response) != 1 {
		t.Errorf("expected 1 session, got %d", len(data.sessions.Response))
	}
	if len(data.nameMap) != 0 {
		t.Errorf("expected empty nameMap, got %v", data.nameMap)
	}

	// Verify verbose warnings were written for both CSPs
	errOutput := errBuf.String()
	if !strings.Contains(errOutput, "Warning:") {
		t.Errorf("expected verbose warning, got: %q", errOutput)
	}
}

func TestBuildWorkspaceNameMap(t *testing.T) {
	tests := []struct {
		name             string
		sessions         []scamodels.SessionInfo
		setupEligibility func() *mockEligibilityLister
		wantNameMapKeys  []string
		wantNameMapVals  map[string]string
	}{
		{
			name: "multiple CSPs fetched concurrently",
			sessions: []scamodels.SessionInfo{
				{CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
				{CSP: scamodels.CSPAWS, WorkspaceID: "arn:aws:iam::123:role/Admin"},
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
						switch csp {
						case scamodels.CSPAzure:
							return &scamodels.EligibilityResponse{
								Response: []scamodels.EligibleTarget{
									{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Dev Sub"},
								},
							}, nil
						case scamodels.CSPAWS:
							return &scamodels.EligibilityResponse{
								Response: []scamodels.EligibleTarget{
									{WorkspaceID: "arn:aws:iam::123:role/Admin", WorkspaceName: "Admin Account"},
								},
							}, nil
						}
						return &scamodels.EligibilityResponse{}, nil
					},
				}
			},
			wantNameMapKeys: []string{"/subscriptions/sub-1", "arn:aws:iam::123:role/Admin"},
			wantNameMapVals: map[string]string{
				"/subscriptions/sub-1":        "Dev Sub",
				"arn:aws:iam::123:role/Admin": "Admin Account",
			},
		},
		{
			name:     "no sessions returns empty map",
			sessions: []scamodels.SessionInfo{},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
						t.Error("ListEligibility should not be called with no sessions")
						return nil, nil
					},
				}
			},
		},
		{
			name: "duplicate CSPs deduplicated",
			sessions: []scamodels.SessionInfo{
				{CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
				{CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-2"},
			},
			setupEligibility: func() *mockEligibilityLister {
				var callCount int
				return &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
						callCount++
						if callCount > 1 {
							t.Error("ListEligibility called more than once for same CSP")
						}
						return &scamodels.EligibilityResponse{
							Response: []scamodels.EligibleTarget{
								{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Sub 1"},
								{WorkspaceID: "/subscriptions/sub-2", WorkspaceName: "Sub 2"},
							},
						}, nil
					},
				}
			},
			wantNameMapKeys: []string{"/subscriptions/sub-1", "/subscriptions/sub-2"},
		},
		{
			name: "partial failure - graceful degradation",
			sessions: []scamodels.SessionInfo{
				{CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
				{CSP: scamodels.CSPAWS, WorkspaceID: "arn:aws:iam::123:role/Admin"},
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
						if csp == scamodels.CSPAWS {
							return nil, errors.New("AWS unavailable")
						}
						return &scamodels.EligibilityResponse{
							Response: []scamodels.EligibleTarget{
								{WorkspaceID: "/subscriptions/sub-1", WorkspaceName: "Dev Sub"},
							},
						}, nil
					},
				}
			},
			wantNameMapKeys: []string{"/subscriptions/sub-1"},
		},
		{
			name: "all failures - empty map",
			sessions: []scamodels.SessionInfo{
				{CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listErr: errors.New("eligibility unavailable"),
				}
			},
			wantNameMapKeys: nil,
		},
		{
			name: "context cancellation - no hang",
			sessions: []scamodels.SessionInfo{
				{CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
				{CSP: scamodels.CSPAWS, WorkspaceID: "arn:aws:iam::123:role/Admin"},
			},
			setupEligibility: func() *mockEligibilityLister {
				return &mockEligibilityLister{
					listFunc: func(ctx context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
						return nil, ctx.Err()
					},
				}
			},
			wantNameMapKeys: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.name == "context cancellation - no hang" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			eligLister := tt.setupEligibility()
			var errBuf bytes.Buffer
			nameMap := buildWorkspaceNameMap(ctx, eligLister, tt.sessions, &errBuf)

			for _, key := range tt.wantNameMapKeys {
				if _, ok := nameMap[key]; !ok {
					t.Errorf("nameMap missing key %q, got: %v", key, nameMap)
				}
			}

			for k, wantV := range tt.wantNameMapVals {
				if gotV := nameMap[k]; gotV != wantV {
					t.Errorf("nameMap[%q] = %q, want %q", k, gotV, wantV)
				}
			}

			if tt.wantNameMapKeys == nil && len(nameMap) > 0 {
				t.Errorf("expected empty nameMap, got: %v", nameMap)
			}
		})
	}
}

func TestBuildWorkspaceNameMap_VerboseWarning(t *testing.T) {
	oldVerbose := verbose
	verbose = true
	defer func() { verbose = oldVerbose }()

	ctx := context.Background()
	eligLister := &mockEligibilityLister{
		listErr: errors.New("eligibility API unavailable"),
	}

	sessions := []scamodels.SessionInfo{
		{CSP: scamodels.CSPAzure, WorkspaceID: "/subscriptions/sub-1"},
	}

	var buf bytes.Buffer
	_ = buildWorkspaceNameMap(ctx, eligLister, sessions, &buf)

	if !strings.Contains(buf.String(), "Warning: failed to fetch names for AZURE") {
		t.Errorf("expected verbose warning, got: %q", buf.String())
	}
}
