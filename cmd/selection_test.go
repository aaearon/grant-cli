package cmd

import (
	"testing"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

func TestFormatSelectionItem(t *testing.T) {
	tests := []struct {
		name string
		item selectionItem
		want string
	}{
		{
			name: "cloud item delegates to FormatTargetOption",
			item: selectionItem{
				kind: selectionCloud,
				cloud: &scamodels.EligibleTarget{
					WorkspaceName: "Prod-EastUS",
					WorkspaceType: scamodels.WorkspaceTypeSubscription,
					RoleInfo:      scamodels.RoleInfo{Name: "Contributor"},
				},
			},
			want: "Subscription: Prod-EastUS / Role: Contributor",
		},
		{
			name: "cloud item with CSP tag",
			item: selectionItem{
				kind: selectionCloud,
				cloud: &scamodels.EligibleTarget{
					WorkspaceName: "AWS Sandbox",
					WorkspaceType: scamodels.WorkspaceTypeAccount,
					RoleInfo:      scamodels.RoleInfo{Name: "ReadOnly"},
					CSP:           scamodels.CSPAWS,
				},
			},
			want: "Account: AWS Sandbox / Role: ReadOnly (aws)",
		},
		{
			name: "group item with directory name shows azure suffix",
			item: selectionItem{
				kind: selectionGroup,
				group: &scamodels.GroupsEligibleTarget{
					DirectoryName: "Contoso",
					GroupName:     "Engineering",
				},
			},
			want: "Directory: Contoso / Group: Engineering (azure)",
		},
		{
			name: "group item without directory name shows azure suffix",
			item: selectionItem{
				kind: selectionGroup,
				group: &scamodels.GroupsEligibleTarget{
					GroupName: "DevOps",
				},
			},
			want: "Group: DevOps (azure)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatSelectionItem(tt.item)
			if got != tt.want {
				t.Errorf("formatSelectionItem() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildUnifiedOptions(t *testing.T) {
	tests := []struct {
		name      string
		items     []selectionItem
		wantLen   int
		wantFirst string
	}{
		{
			name:    "empty list returns empty",
			items:   []selectionItem{},
			wantLen: 0,
		},
		{
			name: "mixed items sorted alphabetically",
			items: []selectionItem{
				{
					kind: selectionCloud,
					cloud: &scamodels.EligibleTarget{
						WorkspaceName: "Prod-EastUS",
						WorkspaceType: scamodels.WorkspaceTypeSubscription,
						RoleInfo:      scamodels.RoleInfo{Name: "Contributor"},
					},
				},
				{
					kind: selectionGroup,
					group: &scamodels.GroupsEligibleTarget{
						DirectoryName: "Contoso",
						GroupName:     "Engineering",
					},
				},
			},
			wantLen:   2,
			wantFirst: "Directory: Contoso / Group: Engineering (azure)", // D < S
		},
		{
			name: "cloud items only",
			items: []selectionItem{
				{
					kind: selectionCloud,
					cloud: &scamodels.EligibleTarget{
						WorkspaceName: "Z-Sub",
						WorkspaceType: scamodels.WorkspaceTypeSubscription,
						RoleInfo:      scamodels.RoleInfo{Name: "Reader"},
					},
				},
				{
					kind: selectionCloud,
					cloud: &scamodels.EligibleTarget{
						WorkspaceName: "A-Sub",
						WorkspaceType: scamodels.WorkspaceTypeSubscription,
						RoleInfo:      scamodels.RoleInfo{Name: "Contributor"},
					},
				},
			},
			wantLen:   2,
			wantFirst: "Subscription: A-Sub / Role: Contributor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options, sorted := buildUnifiedOptions(tt.items)
			if len(options) != tt.wantLen {
				t.Errorf("buildUnifiedOptions() returned %d options, want %d", len(options), tt.wantLen)
			}
			if len(sorted) != tt.wantLen {
				t.Errorf("buildUnifiedOptions() returned %d sorted items, want %d", len(sorted), tt.wantLen)
			}
			if tt.wantFirst != "" && len(options) > 0 && options[0] != tt.wantFirst {
				t.Errorf("first option = %q, want %q", options[0], tt.wantFirst)
			}
		})
	}
}

func TestFindItemByDisplay(t *testing.T) {
	cloudTarget := &scamodels.EligibleTarget{
		WorkspaceName: "Prod-EastUS",
		WorkspaceType: scamodels.WorkspaceTypeSubscription,
		RoleInfo:      scamodels.RoleInfo{Name: "Contributor"},
	}
	groupTarget := &scamodels.GroupsEligibleTarget{
		DirectoryName: "Contoso",
		GroupName:     "Engineering",
	}

	items := []selectionItem{
		{kind: selectionCloud, cloud: cloudTarget},
		{kind: selectionGroup, group: groupTarget},
	}

	tests := []struct {
		name    string
		display string
		wantErr bool
	}{
		{
			name:    "finds cloud by display",
			display: "Subscription: Prod-EastUS / Role: Contributor",
			wantErr: false,
		},
		{
			name:    "finds group by display",
			display: "Directory: Contoso / Group: Engineering (azure)",
			wantErr: false,
		},
		{
			name:    "returns error on mismatch",
			display: "NonExistent Display String",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item, err := findItemByDisplay(items, tt.display)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if item == nil {
				t.Fatal("expected non-nil item")
			}
		})
	}
}
