package ui

import (
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

func TestFormatTargetOption(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target models.EligibleTarget
		want   string
	}{
		{
			name: "subscription",
			target: models.EligibleTarget{
				WorkspaceName: "Production Sub",
				WorkspaceType: models.WorkspaceTypeSubscription,
				RoleInfo:      models.RoleInfo{ID: "1", Name: "Owner"},
			},
			want: "Subscription: Production Sub / Role: Owner",
		},
		{
			name: "resource group",
			target: models.EligibleTarget{
				WorkspaceName: "rg-web-prod",
				WorkspaceType: models.WorkspaceTypeResourceGroup,
				RoleInfo:      models.RoleInfo{ID: "2", Name: "Contributor"},
			},
			want: "Resource Group: rg-web-prod / Role: Contributor",
		},
		{
			name: "management group",
			target: models.EligibleTarget{
				WorkspaceName: "Corp MG",
				WorkspaceType: models.WorkspaceTypeManagementGroup,
				RoleInfo:      models.RoleInfo{ID: "3", Name: "Reader"},
			},
			want: "Management Group: Corp MG / Role: Reader",
		},
		{
			name: "directory",
			target: models.EligibleTarget{
				WorkspaceName: "Contoso",
				WorkspaceType: models.WorkspaceTypeDirectory,
				RoleInfo:      models.RoleInfo{ID: "4", Name: "Global Administrator"},
			},
			want: "Directory: Contoso / Role: Global Administrator",
		},
		{
			name: "resource (fallback to resource type)",
			target: models.EligibleTarget{
				WorkspaceName: "vm-prod-001",
				WorkspaceType: models.WorkspaceTypeResource,
				RoleInfo:      models.RoleInfo{ID: "5", Name: "Contributor"},
			},
			want: "Resource: vm-prod-001 / Role: Contributor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatTargetOption(tt.target)
			if got != tt.want {
				t.Errorf("FormatTargetOption() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		targets []models.EligibleTarget
		want    []string
	}{
		{
			name:    "empty list",
			targets: []models.EligibleTarget{},
			want:    []string{},
		},
		{
			name: "single target",
			targets: []models.EligibleTarget{
				{
					WorkspaceName: "Sub A",
					WorkspaceType: models.WorkspaceTypeSubscription,
					RoleInfo:      models.RoleInfo{Name: "Owner"},
				},
			},
			want: []string{"Subscription: Sub A / Role: Owner"},
		},
		{
			name: "multiple targets sorted by workspace name",
			targets: []models.EligibleTarget{
				{
					WorkspaceName: "Sub C",
					WorkspaceType: models.WorkspaceTypeSubscription,
					RoleInfo:      models.RoleInfo{Name: "Owner"},
				},
				{
					WorkspaceName: "Sub A",
					WorkspaceType: models.WorkspaceTypeSubscription,
					RoleInfo:      models.RoleInfo{Name: "Contributor"},
				},
				{
					WorkspaceName: "Sub B",
					WorkspaceType: models.WorkspaceTypeSubscription,
					RoleInfo:      models.RoleInfo{Name: "Reader"},
				},
			},
			want: []string{
				"Subscription: Sub A / Role: Contributor",
				"Subscription: Sub B / Role: Reader",
				"Subscription: Sub C / Role: Owner",
			},
		},
		{
			name: "mixed workspace types sorted",
			targets: []models.EligibleTarget{
				{
					WorkspaceName: "RG Zebra",
					WorkspaceType: models.WorkspaceTypeResourceGroup,
					RoleInfo:      models.RoleInfo{Name: "Owner"},
				},
				{
					WorkspaceName: "Sub Alpha",
					WorkspaceType: models.WorkspaceTypeSubscription,
					RoleInfo:      models.RoleInfo{Name: "Contributor"},
				},
			},
			want: []string{
				"Resource Group: RG Zebra / Role: Owner",
				"Subscription: Sub Alpha / Role: Contributor",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := BuildOptions(tt.targets)
			if len(got) != len(tt.want) {
				t.Fatalf("BuildOptions() length = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("BuildOptions()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFindTargetByDisplay(t *testing.T) {
	t.Parallel()
	targets := []models.EligibleTarget{
		{
			OrganizationID: "org1",
			WorkspaceID:    "sub1",
			WorkspaceName:  "Production",
			WorkspaceType:  models.WorkspaceTypeSubscription,
			RoleInfo:       models.RoleInfo{ID: "role1", Name: "Owner"},
		},
		{
			OrganizationID: "org1",
			WorkspaceID:    "rg1",
			WorkspaceName:  "rg-web",
			WorkspaceType:  models.WorkspaceTypeResourceGroup,
			RoleInfo:       models.RoleInfo{ID: "role2", Name: "Contributor"},
		},
	}

	tests := []struct {
		name    string
		targets []models.EligibleTarget
		display string
		want    *models.EligibleTarget
		wantErr bool
	}{
		{
			name:    "found subscription",
			targets: targets,
			display: "Subscription: Production / Role: Owner",
			want:    &targets[0],
			wantErr: false,
		},
		{
			name:    "found resource group",
			targets: targets,
			display: "Resource Group: rg-web / Role: Contributor",
			want:    &targets[1],
			wantErr: false,
		},
		{
			name:    "not found",
			targets: targets,
			display: "Subscription: NonExistent / Role: Reader",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty targets",
			targets: []models.EligibleTarget{},
			display: "Subscription: Test / Role: Owner",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := FindTargetByDisplay(tt.targets, tt.display)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindTargetByDisplay() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want == nil && got != nil {
				t.Errorf("FindTargetByDisplay() = %v, want nil", got)
				return
			}
			if tt.want != nil {
				if got == nil {
					t.Errorf("FindTargetByDisplay() = nil, want %v", tt.want)
					return
				}
				if got.WorkspaceID != tt.want.WorkspaceID || got.RoleInfo.ID != tt.want.RoleInfo.ID {
					t.Errorf("FindTargetByDisplay() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
