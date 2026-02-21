package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

func TestListCommand(t *testing.T) {
	tests := []struct {
		name        string
		auth        *mockAuthLoader
		eligLister  *mockEligibilityLister
		groupsElig  *mockGroupsEligibilityLister
		args        []string
		wantContain []string
		wantErr     bool
		wantErrStr  string
	}{
		{
			name:       "not authenticated",
			auth:       &mockAuthLoader{loadErr: errors.New("no token")},
			eligLister: &mockEligibilityLister{},
			groupsElig: &mockGroupsEligibilityLister{},
			args:       []string{},
			wantErr:    true,
			wantErrStr: "not authenticated",
		},
		{
			name: "list cloud targets text",
			auth: &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}},
			eligLister: &mockEligibilityLister{response: &models.EligibilityResponse{
				Response: []models.EligibleTarget{
					{
						WorkspaceID: "sub-1", WorkspaceName: "Prod-EastUS",
						WorkspaceType: models.WorkspaceTypeSubscription,
						RoleInfo:      models.RoleInfo{ID: "r1", Name: "Contributor"},
					},
				},
				Total: 1,
			}},
			groupsElig: &mockGroupsEligibilityLister{listErr: errors.New("skip")},
			args:       []string{"--provider", "azure"},
			wantContain: []string{
				"Subscription: Prod-EastUS / Role: Contributor",
			},
			wantErr: false,
		},
		{
			name: "list cloud targets JSON",
			auth: &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}},
			eligLister: &mockEligibilityLister{response: &models.EligibilityResponse{
				Response: []models.EligibleTarget{
					{
						WorkspaceID: "sub-1", WorkspaceName: "Prod-EastUS",
						WorkspaceType: models.WorkspaceTypeSubscription,
						RoleInfo:      models.RoleInfo{ID: "r1", Name: "Contributor"},
					},
				},
				Total: 1,
			}},
			groupsElig: &mockGroupsEligibilityLister{listErr: errors.New("skip")},
			args:       []string{"--provider", "azure", "--output", "json"},
			wantErr:    false,
		},
		{
			name:       "groups only",
			auth:       &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}},
			eligLister: &mockEligibilityLister{response: &models.EligibilityResponse{Response: []models.EligibleTarget{{WorkspaceID: "sub-1", WorkspaceName: "Prod", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r1", Name: "Reader"}}}, Total: 1}},
			groupsElig: &mockGroupsEligibilityLister{response: &models.GroupsEligibilityResponse{
				Response: []models.GroupsEligibleTarget{
					{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
				},
				Total: 1,
			}},
			args: []string{"--groups"},
			wantContain: []string{
				"Engineering",
			},
			wantErr: false,
		},
		{
			name: "provider filter",
			auth: &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}},
			eligLister: &mockEligibilityLister{response: &models.EligibilityResponse{
				Response: []models.EligibleTarget{
					{
						WorkspaceID: "acct-1", WorkspaceName: "AWS Sandbox",
						WorkspaceType: models.WorkspaceTypeAccount,
						RoleInfo:      models.RoleInfo{ID: "r1", Name: "Admin"},
					},
				},
				Total: 1,
			}},
			groupsElig: &mockGroupsEligibilityLister{listErr: errors.New("skip")},
			args:       []string{"--provider", "aws"},
			wantContain: []string{
				"Account: AWS Sandbox / Role: Admin",
			},
			wantErr: false,
		},
		{
			name:       "no eligible targets",
			auth:       &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}},
			eligLister: &mockEligibilityLister{listErr: errors.New("no eligible targets found")},
			groupsElig: &mockGroupsEligibilityLister{listErr: errors.New("no groups")},
			args:       []string{},
			wantErr:    true,
			wantErrStr: "no eligible",
		},
		{
			name: "cloud and groups merged",
			auth: &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}},
			eligLister: &mockEligibilityLister{response: &models.EligibilityResponse{
				Response: []models.EligibleTarget{
					{WorkspaceID: "sub-1", WorkspaceName: "Prod", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r1", Name: "Reader"}},
				},
				Total: 1,
			}},
			groupsElig: &mockGroupsEligibilityLister{response: &models.GroupsEligibilityResponse{
				Response: []models.GroupsEligibleTarget{
					{DirectoryID: "dir1", GroupID: "grp1", GroupName: "CloudAdmins"},
				},
				Total: 1,
			}},
			args: []string{},
			wantContain: []string{
				"Subscription: Prod / Role: Reader",
				"CloudAdmins",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewListCommandWithDeps(tt.auth, tt.eligLister, tt.groupsElig)
			root := newTestRootCommand()
			root.AddCommand(cmd)

			args := append([]string{"list"}, tt.args...)
			output, err := executeCommand(root, args...)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v\noutput: %s", err, tt.wantErr, output)
			}
			if tt.wantErr && tt.wantErrStr != "" && !strings.Contains(output, tt.wantErrStr) {
				t.Errorf("expected error containing %q, got:\n%s", tt.wantErrStr, output)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestListCommand_JSONOutput(t *testing.T) {
	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}}
	eligLister := &mockEligibilityLister{
		listFunc: func(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
			if csp == models.CSPAzure {
				return &models.EligibilityResponse{
					Response: []models.EligibleTarget{{
						WorkspaceID: "sub-1", WorkspaceName: "Prod-EastUS",
						WorkspaceType: models.WorkspaceTypeSubscription,
						RoleInfo:      models.RoleInfo{ID: "r1", Name: "Contributor"},
					}},
					Total: 1,
				}, nil
			}
			return &models.EligibilityResponse{}, nil
		},
	}
	groupsElig := &mockGroupsEligibilityLister{response: &models.GroupsEligibilityResponse{
		Response: []models.GroupsEligibleTarget{
			{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering", DirectoryName: "Contoso"},
		},
		Total: 1,
	}}

	cmd := NewListCommandWithDeps(auth, eligLister, groupsElig)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "list", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	var parsed listOutput
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, output)
	}

	if len(parsed.Cloud) != 1 {
		t.Fatalf("expected 1 cloud target, got %d", len(parsed.Cloud))
	}
	if parsed.Cloud[0].Target != "Prod-EastUS" {
		t.Errorf("cloud target = %q, want Prod-EastUS", parsed.Cloud[0].Target)
	}
	if parsed.Cloud[0].Role != "Contributor" {
		t.Errorf("cloud role = %q, want Contributor", parsed.Cloud[0].Role)
	}

	if len(parsed.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(parsed.Groups))
	}
	if parsed.Groups[0].GroupName != "Engineering" {
		t.Errorf("group name = %q, want Engineering", parsed.Groups[0].GroupName)
	}
	if parsed.Groups[0].Directory != "Contoso" {
		t.Errorf("directory = %q, want Contoso", parsed.Groups[0].Directory)
	}
}

func TestListCommand_GroupsOnlyJSON(t *testing.T) {
	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}}
	eligLister := &mockEligibilityLister{response: &models.EligibilityResponse{
		Response: []models.EligibleTarget{{WorkspaceID: "sub-1", WorkspaceName: "Prod", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r1", Name: "Reader"}}},
		Total:    1,
	}}
	groupsElig := &mockGroupsEligibilityLister{response: &models.GroupsEligibilityResponse{
		Response: []models.GroupsEligibleTarget{
			{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Admins"},
		},
		Total: 1,
	}}

	cmd := NewListCommandWithDeps(auth, eligLister, groupsElig)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	output, err := executeCommand(root, "list", "--groups", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, output)
	}

	var parsed listOutput
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, output)
	}

	if len(parsed.Cloud) != 0 {
		t.Errorf("expected no cloud targets with --groups, got %d", len(parsed.Cloud))
	}
	if len(parsed.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(parsed.Groups))
	}
}

func TestListCommand_MutualExclusivity(t *testing.T) {
	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}}
	eligLister := &mockEligibilityLister{}
	groupsElig := &mockGroupsEligibilityLister{}

	cmd := NewListCommandWithDeps(auth, eligLister, groupsElig)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	_, err := executeCommand(root, "list", "--groups", "--provider", "aws")
	if err == nil {
		t.Fatal("expected error for --groups + --provider")
	}
}
