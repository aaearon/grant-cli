package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

func TestEnvCommand_AWSSuccess(t *testing.T) {
	credsJSON := `{"aws_access_key":"ASIAXXXXXXXXXEXAMPLE","aws_secret_access_key":"wJalrXUtnFEMI/SECRET","aws_session_token":"FwoGZXIvYXdzEBYaDHqa0AP+TOKEN"}`

	authLoader := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "test-jwt"},
	}
	eligibilityLister := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{
				{
					OrganizationID: "o-abc123",
					WorkspaceID:    "123456789012",
					WorkspaceName:  "AWS Management",
					WorkspaceType:  models.WorkspaceTypeAccount,
					RoleInfo:       models.RoleInfo{ID: "role-1", Name: "AdminAccess"},
				},
			},
			Total: 1,
		},
	}
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
	selector := &mockTargetSelector{
		target: &models.EligibleTarget{
			OrganizationID: "o-abc123",
			WorkspaceID:    "123456789012",
			WorkspaceName:  "AWS Management",
			WorkspaceType:  models.WorkspaceTypeAccount,
			RoleInfo:       models.RoleInfo{ID: "role-1", Name: "AdminAccess"},
		},
	}

	cfg := config.DefaultConfig()
	cmd := NewEnvCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, selector, cfg)

	output, err := executeCommand(cmd, "--provider", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantLines := []string{
		"export AWS_ACCESS_KEY_ID='ASIAXXXXXXXXXEXAMPLE'",
		"export AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/SECRET'",
		"export AWS_SESSION_TOKEN='FwoGZXIvYXdzEBYaDHqa0AP+TOKEN'",
	}

	for _, want := range wantLines {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, output)
		}
	}

	// Should NOT contain human-readable messages
	if strings.Contains(output, "Elevated to") {
		t.Errorf("output should not contain human-readable text\ngot:\n%s", output)
	}
}

func TestEnvCommand_AzureError(t *testing.T) {
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
					RoleInfo:       models.RoleInfo{ID: "role-789", Name: "Contributor"},
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
						SessionID:   "session-az",
					},
				},
			},
		},
	}
	selector := &mockTargetSelector{
		target: &models.EligibleTarget{
			OrganizationID: "org-123",
			WorkspaceID:    "sub-456",
			WorkspaceName:  "Prod-EastUS",
			WorkspaceType:  models.WorkspaceTypeSubscription,
			RoleInfo:       models.RoleInfo{ID: "role-789", Name: "Contributor"},
		},
	}

	cfg := config.DefaultConfig()
	cmd := NewEnvCommandWithDeps(nil, authLoader, eligibilityLister, elevateService, selector, cfg)

	_, err := executeCommand(cmd)
	if err == nil {
		t.Fatal("expected error for Azure elevation (no credentials)")
	}

	if !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("expected 'no credentials' error, got: %v", err)
	}
}

func TestEnvCommand_NotAuthenticated(t *testing.T) {
	authLoader := &mockAuthLoader{
		loadErr: errNotAuthenticated,
	}
	cfg := config.DefaultConfig()
	cmd := NewEnvCommandWithDeps(nil, authLoader, nil, nil, nil, cfg)

	_, err := executeCommand(cmd)
	if err == nil {
		t.Fatal("expected error for unauthenticated user")
	}

	if !strings.Contains(err.Error(), "not authenticated") {
		t.Errorf("expected 'not authenticated' error, got: %v", err)
	}
}

func TestEnvCommand_RecordsSessionTimestamp(t *testing.T) {
	originalRecorder := recordSessionTimestamp
	defer func() { recordSessionTimestamp = originalRecorder }()

	var recorded string
	recordSessionTimestamp = func(sessionID string) { recorded = sessionID }

	credsJSON := `{"aws_access_key":"ASIAXXX","aws_secret_access_key":"secret","aws_session_token":"tok"}`

	authLoader := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "test-jwt"},
	}
	eligLister := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{{
				OrganizationID: "o-1", WorkspaceID: "acct-1", WorkspaceName: "AWS Mgmt",
				WorkspaceType: models.WorkspaceTypeAccount,
				RoleInfo:      models.RoleInfo{ID: "role-1", Name: "Admin"},
			}}, Total: 1,
		},
	}
	elevSvc := &mockElevateService{
		response: &models.ElevateResponse{Response: models.ElevateAccessResult{
			CSP: models.CSPAWS, OrganizationID: "o-1",
			Results: []models.ElevateTargetResult{{
				WorkspaceID: "acct-1", RoleID: "Admin", SessionID: "env-sess-1",
				AccessCredentials: &credsJSON,
			}},
		}},
	}
	selector := &mockTargetSelector{
		target: &models.EligibleTarget{
			OrganizationID: "o-1", WorkspaceID: "acct-1", WorkspaceName: "AWS Mgmt",
			WorkspaceType: models.WorkspaceTypeAccount,
			RoleInfo:      models.RoleInfo{ID: "role-1", Name: "Admin"},
		},
	}

	cmd := NewEnvCommandWithDeps(nil, authLoader, eligLister, elevSvc, selector, config.DefaultConfig())
	_, err := executeCommand(cmd, "--provider", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if recorded != "env-sess-1" {
		t.Errorf("recorded session = %q, want env-sess-1", recorded)
	}
}

func TestNewEnvCommand_RefreshFlagRegistered(t *testing.T) {
	cmd := newEnvCommand(nil)
	if cmd.Flags().Lookup("refresh") == nil {
		t.Error("expected --refresh flag to be registered")
	}
}

func TestEnvCommand_JSONOutput(t *testing.T) {
	credsJSON := `{"aws_access_key":"ASIAXXX","aws_secret_access_key":"secret","aws_session_token":"tok"}`

	authLoader := &mockAuthLoader{
		token: &authmodels.IdsecToken{Token: "test-jwt"},
	}
	eligLister := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{{
				OrganizationID: "o-1", WorkspaceID: "acct-1", WorkspaceName: "AWS Mgmt",
				WorkspaceType: models.WorkspaceTypeAccount,
				RoleInfo:      models.RoleInfo{ID: "role-1", Name: "Admin"},
			}},
			Total: 1,
		},
	}
	elevSvc := &mockElevateService{
		response: &models.ElevateResponse{Response: models.ElevateAccessResult{
			CSP: models.CSPAWS, OrganizationID: "o-1",
			Results: []models.ElevateTargetResult{{
				WorkspaceID: "acct-1", RoleID: "Admin", SessionID: "sess-1",
				AccessCredentials: &credsJSON,
			}},
		}},
	}
	selector := &mockTargetSelector{
		target: &models.EligibleTarget{
			OrganizationID: "o-1", WorkspaceID: "acct-1", WorkspaceName: "AWS Mgmt",
			WorkspaceType: models.WorkspaceTypeAccount,
			RoleInfo:      models.RoleInfo{ID: "role-1", Name: "Admin"},
		},
	}

	cmd := NewEnvCommandWithDeps(nil, authLoader, eligLister, elevSvc, selector, config.DefaultConfig())
	// Attach to root so --output flag is available
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "env", "--provider", "aws", "--target", "AWS Mgmt", "--role", "Admin", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	var parsed awsCredentialOutput
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, output)
	}
	if parsed.AccessKeyID != "ASIAXXX" {
		t.Errorf("accessKeyId = %q, want ASIAXXX", parsed.AccessKeyID)
	}
}
