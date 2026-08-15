package ui

import (
	"errors"
	"reflect"
	"sort"
	"strings"
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
		{
			name: "account (AWS)",
			target: models.EligibleTarget{
				WorkspaceName: "Acme AWS Management",
				WorkspaceType: models.WorkspaceTypeAccount,
				RoleInfo:      models.RoleInfo{ID: "6", Name: "AdministratorAccess"},
			},
			want: "Account: Acme AWS Management / Role: AdministratorAccess",
		},
		{
			name: "subscription with CSP tag",
			target: models.EligibleTarget{
				CSP:           models.CSPAzure,
				WorkspaceName: "Prod Sub",
				WorkspaceType: models.WorkspaceTypeSubscription,
				RoleInfo:      models.RoleInfo{ID: "7", Name: "Reader"},
			},
			want: "Subscription: Prod Sub / Role: Reader (azure)",
		},
		{
			name: "account with CSP tag",
			target: models.EligibleTarget{
				CSP:           models.CSPAWS,
				WorkspaceName: "Dev Account",
				WorkspaceType: models.WorkspaceTypeAccount,
				RoleInfo:      models.RoleInfo{ID: "8", Name: "ReadOnly"},
			},
			want: "Account: Dev Account / Role: ReadOnly (aws)",
		},
		{
			name: "GCP project with CSP tag",
			target: models.EligibleTarget{
				CSP:           models.CSPGCP,
				WorkspaceName: "My GCP Project",
				WorkspaceType: models.WorkspaceTypeProject,
				RoleInfo:      models.RoleInfo{ID: "9", Name: "Viewer"},
			},
			want: "Project: My GCP Project / Role: Viewer (gcp)",
		},
		{
			name: "GCP folder",
			target: models.EligibleTarget{
				WorkspaceName: "Engineering",
				WorkspaceType: models.WorkspaceTypeFolder,
				RoleInfo:      models.RoleInfo{ID: "10", Name: "Editor"},
			},
			want: "Folder: Engineering / Role: Editor",
		},
		{
			name: "GCP organization",
			target: models.EligibleTarget{
				WorkspaceName: "acme.example",
				WorkspaceType: models.WorkspaceTypeGCPOrganization,
				RoleInfo:      models.RoleInfo{ID: "11", Name: "Organization Administrator"},
			},
			want: "GCP Organization: acme.example / Role: Organization Administrator",
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

// Not parallel: mutates the package-global IsTerminalFunc.
func TestSelectTarget_NonTTY(t *testing.T) {
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()
	IsTerminalFunc = func(fd uintptr) bool { return false }

	targets := []models.EligibleTarget{
		{WorkspaceName: "Sub A", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{Name: "Owner"}},
	}

	_, err := SelectTarget(targets)
	if err == nil {
		t.Fatal("expected error for non-TTY")
	}
	if !errors.Is(err, ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--target") {
		t.Errorf("error should mention --target, got: %v", err)
	}
}

// TestSelectTarget_NonTTYEmptyList pins the order of the two guards. _NonTTY passes a
// non-empty list and _EmptyList forces a TTY, so their inputs never intersect and
// swapping the guards survives both. This case satisfies both conditions at once.
// Not parallel: mutates the package-global IsTerminalFunc.
func TestSelectTarget_NonTTYEmptyList(t *testing.T) {
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()
	IsTerminalFunc = func(fd uintptr) bool { return false }

	_, err := SelectTarget(nil)
	if err == nil {
		t.Fatal("expected error for non-TTY with an empty list")
	}
	if !errors.Is(err, ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive to win over the empty-list guard, got: %v", err)
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

// TestSortTargetsForDisplay_Ordering pins the order options are rendered in, and
// nothing else. Which target a selection denotes is resolveTargetSelection's job.
func TestSortTargetsForDisplay_Ordering(t *testing.T) {
	t.Parallel()
	// Deliberately unsorted input containing a display collision: the two "Shared"
	// subscriptions carry the same workspace name and role, so both render identically.
	targets := []models.EligibleTarget{
		{OrganizationID: "org-z", WorkspaceID: "sub-zebra", WorkspaceName: "Zebra Sub", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r0", Name: "Reader"}},
		{OrganizationID: "org-1", WorkspaceID: "sub-shared-1", WorkspaceName: "Shared", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r1", Name: "Owner"}},
		{OrganizationID: "org-2", WorkspaceID: "sub-shared-2", WorkspaceName: "Shared", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r1", Name: "Owner"}},
		{OrganizationID: "org-a", WorkspaceID: "sub-alpha", WorkspaceName: "Alpha Sub", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "r2", Name: "Contributor"}},
	}
	before := append([]models.EligibleTarget(nil), targets...)

	sorted := sortTargetsForDisplay(targets)

	if len(sorted) != len(targets) {
		t.Fatalf("sortTargetsForDisplay() length = %d, want %d", len(sorted), len(targets))
	}

	options := make([]string, len(sorted))
	for i := range sorted {
		options[i] = FormatTargetOption(sorted[i])
	}
	if !sort.StringsAreSorted(options) {
		t.Errorf("rendered options are not in display order: %q", options)
	}

	// The sort is stable, so the two colliding rows keep their input order.
	if sorted[1].WorkspaceID != "sub-shared-1" || sorted[2].WorkspaceID != "sub-shared-2" {
		t.Errorf("colliding rows lost input order: got %q, %q", sorted[1].WorkspaceID, sorted[2].WorkspaceID)
	}

	if !reflect.DeepEqual(targets, before) {
		t.Errorf("sortTargetsForDisplay() mutated the caller's slice: got %+v, want %+v", targets, before)
	}
}

// TestResolveTargetSelection_DuplicateDisplayStrings pins the wrong-target fix.
// FormatTargetOption carries no ID, so two eligible targets with the same workspace
// name and role in different subscriptions/accounts render to the same string.
// Recovering the answer by text returns the first match regardless of which row the
// user highlighted — and SelectTarget searched the caller's *unsorted* slice while
// rendering a sorted one, so the two could disagree even without a collision.
// survey.Select cannot be driven from a test, so the index path is asserted on the
// extracted resolver, mirroring SelectGroup/SelectRole/SelectRequest.
func TestResolveTargetSelection_DuplicateDisplayStrings(t *testing.T) {
	t.Parallel()
	targets := []models.EligibleTarget{
		{OrganizationID: "org-1", WorkspaceID: "sub-1", WorkspaceName: "Shared", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "role-1", Name: "Owner"}},
		{OrganizationID: "org-2", WorkspaceID: "sub-2", WorkspaceName: "Shared", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{ID: "role-1", Name: "Owner"}},
	}
	sorted := sortTargetsForDisplay(targets)
	if len(sorted) != 2 {
		t.Fatalf("sortTargetsForDisplay() length = %d, want 2", len(sorted))
	}
	if FormatTargetOption(sorted[0]) != FormatTargetOption(sorted[1]) {
		t.Fatalf("fixture no longer collides: %q vs %q", FormatTargetOption(sorted[0]), FormatTargetOption(sorted[1]))
	}
	if sorted[0].WorkspaceID == sorted[1].WorkspaceID {
		t.Fatalf("fixture targets are indistinguishable: %+v", sorted)
	}

	// The sort is stable and the two entries compare equal, so the rendered order is
	// the input order: row 0 is sub-1, row 1 is sub-2.
	tests := []struct {
		idx             int
		wantWorkspaceID string
		wantOrgID       string
	}{
		{idx: 0, wantWorkspaceID: "sub-1", wantOrgID: "org-1"},
		{idx: 1, wantWorkspaceID: "sub-2", wantOrgID: "org-2"},
	}
	for _, tt := range tests {
		got, err := resolveTargetSelection(sorted, tt.idx)
		if err != nil {
			t.Fatalf("resolveTargetSelection(_, %d) error = %v", tt.idx, err)
		}
		if got.WorkspaceID != tt.wantWorkspaceID || got.OrganizationID != tt.wantOrgID {
			t.Errorf("selecting row %d returned WorkspaceID=%q OrganizationID=%q, want %q/%q",
				tt.idx, got.WorkspaceID, got.OrganizationID, tt.wantWorkspaceID, tt.wantOrgID)
		}
	}
}

func TestResolveTargetSelection_OutOfRange(t *testing.T) {
	t.Parallel()
	targets := []models.EligibleTarget{
		{WorkspaceID: "sub-1", WorkspaceName: "Shared", WorkspaceType: models.WorkspaceTypeSubscription, RoleInfo: models.RoleInfo{Name: "Owner"}},
	}
	for _, idx := range []int{-1, 1} {
		if _, err := resolveTargetSelection(targets, idx); err == nil {
			t.Errorf("resolveTargetSelection(_, %d) = nil error, want out-of-range error", idx)
		}
	}
}

// Not parallel: mutates the package-global IsTerminalFunc.
func TestSelectTarget_EmptyList(t *testing.T) {
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()
	IsTerminalFunc = func(fd uintptr) bool { return true }

	_, err := SelectTarget(nil)
	if err == nil {
		t.Fatal("expected error for empty list")
	}
	if !strings.Contains(err.Error(), "no eligible targets available") {
		t.Errorf("unexpected error: %v", err)
	}
}
