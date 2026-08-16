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

func TestResolveSelectionItem(t *testing.T) {
	first := &scamodels.GroupsEligibleTarget{
		DirectoryID: "dir-first",
		GroupID:     "group-first",
		GroupName:   "Cloud Admins",
	}
	second := &scamodels.GroupsEligibleTarget{
		DirectoryID: "dir-second",
		GroupID:     "group-second",
		GroupName:   "Cloud Admins",
	}
	cloud := &scamodels.EligibleTarget{
		WorkspaceID:   "sub-1",
		WorkspaceName: "Prod-EastUS",
		WorkspaceType: scamodels.WorkspaceTypeSubscription,
		RoleInfo:      scamodels.RoleInfo{Name: "Contributor"},
	}

	// The two groups render identically, which is exactly the case a display-string
	// lookup gets wrong.
	items := []selectionItem{
		{kind: selectionGroup, group: first},
		{kind: selectionGroup, group: second},
		{kind: selectionCloud, cloud: cloud},
	}

	tests := []struct {
		name    string
		idx     int
		wantErr bool
		wantID  string
	}{
		{name: "first of two identical displays", idx: 0, wantID: "group-first"},
		{name: "second of two identical displays", idx: 1, wantID: "group-second"},
		{name: "cloud item", idx: 2, wantID: "sub-1"},
		{name: "negative index errors", idx: -1, wantErr: true},
		{name: "index past end errors", idx: 3, wantErr: true},
		{name: "far out of range errors", idx: 99, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item, err := resolveSelectionItem(items, tt.idx)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveSelectionItem(%d) = %v, want error", tt.idx, item)
				}
				if item != nil {
					t.Errorf("resolveSelectionItem(%d) item = %v, want nil", tt.idx, item)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var gotID string
			switch item.kind {
			case selectionGroup:
				gotID = item.group.GroupID
			case selectionCloud:
				gotID = item.cloud.WorkspaceID
			}
			if gotID != tt.wantID {
				t.Errorf("resolveSelectionItem(%d) id = %q, want %q", tt.idx, gotID, tt.wantID)
			}
		})
	}
}

// TestResolveSelectionItem_EmptySlice guards the degenerate case: with nothing to
// select from, every index must be rejected rather than panicking.
func TestResolveSelectionItem_EmptySlice(t *testing.T) {
	if item, err := resolveSelectionItem(nil, 0); err == nil {
		t.Errorf("resolveSelectionItem(nil, 0) = %v, want error", item)
	}
}
