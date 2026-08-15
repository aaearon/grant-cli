package ui

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

func TestFormatGroupOption(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		group models.GroupsEligibleTarget
		want  string
	}{
		{
			name:  "simple group without directory name",
			group: models.GroupsEligibleTarget{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
			want:  "Group: Engineering",
		},
		{
			name:  "group with directory name",
			group: models.GroupsEligibleTarget{DirectoryID: "dir1", DirectoryName: "Contoso", GroupID: "grp1", GroupName: "Cloud Admins"},
			want:  "Directory: Contoso / Group: Cloud Admins",
		},
		{
			name:  "group with empty directory name",
			group: models.GroupsEligibleTarget{DirectoryID: "dir1", DirectoryName: "", GroupID: "grp2", GroupName: "DevOps"},
			want:  "Group: DevOps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatGroupOption(tt.group)
			if got != tt.want {
				t.Errorf("FormatGroupOption() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildGroupOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		groups []models.GroupsEligibleTarget
		want   []string
	}{
		{
			name:   "empty list",
			groups: []models.GroupsEligibleTarget{},
			want:   []string{},
		},
		{
			name: "single group",
			groups: []models.GroupsEligibleTarget{
				{GroupID: "g1", GroupName: "Admins"},
			},
			want: []string{"Group: Admins"},
		},
		{
			name: "multiple groups sorted",
			groups: []models.GroupsEligibleTarget{
				{GroupID: "g1", GroupName: "Zebra Team"},
				{GroupID: "g2", GroupName: "Alpha Team"},
				{GroupID: "g3", GroupName: "Beta Team"},
			},
			want: []string{
				"Group: Alpha Team",
				"Group: Beta Team",
				"Group: Zebra Team",
			},
		},
		{
			name: "groups with directory names sorted",
			groups: []models.GroupsEligibleTarget{
				{DirectoryName: "Contoso", GroupID: "g1", GroupName: "Zebra Team"},
				{DirectoryName: "Contoso", GroupID: "g2", GroupName: "Alpha Team"},
			},
			want: []string{
				"Directory: Contoso / Group: Alpha Team",
				"Directory: Contoso / Group: Zebra Team",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := BuildGroupOptions(tt.groups)
			if len(got) != len(tt.want) {
				t.Fatalf("BuildGroupOptions() length = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("BuildGroupOptions()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestBuildGroupOptions_DuplicateDisplayStrings(t *testing.T) {
	t.Parallel()
	// Two groups with same name and no DirectoryName produce identical display strings
	groups := []models.GroupsEligibleTarget{
		{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
		{DirectoryID: "dir2", GroupID: "grp2", GroupName: "Engineering"},
	}
	options := BuildGroupOptions(groups)
	if len(options) != 2 {
		t.Fatalf("expected 2 options, got %d", len(options))
	}
	// Both should be "Group: Engineering" (duplicate is expected)
	for _, opt := range options {
		if opt != "Group: Engineering" {
			t.Errorf("unexpected option %q", opt)
		}
	}
}

func TestFindGroupByDisplay_DuplicateDisplayStrings(t *testing.T) {
	t.Parallel()
	// When display strings collide, FindGroupByDisplay returns the first match
	// in the slice it's given. SelectGroup sorts a copy, so the caller controls order.
	groups := []models.GroupsEligibleTarget{
		{DirectoryID: "dir2", GroupID: "grp2", GroupName: "Engineering"},
		{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
	}
	got, err := FindGroupByDisplay(groups, "Group: Engineering")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return first in slice (grp2 since dir2 is first)
	if got.GroupID != "grp2" {
		t.Errorf("expected grp2 (first in slice), got %q", got.GroupID)
	}
}

func TestFindGroupByDisplay(t *testing.T) {
	t.Parallel()
	groups := []models.GroupsEligibleTarget{
		{DirectoryID: "dir1", DirectoryName: "Contoso", GroupID: "grp1", GroupName: "Engineering"},
		{DirectoryID: "dir1", DirectoryName: "Contoso", GroupID: "grp2", GroupName: "DevOps"},
	}

	tests := []struct {
		name    string
		groups  []models.GroupsEligibleTarget
		display string
		wantID  string
		wantErr bool
	}{
		{
			name:    "found engineering",
			groups:  groups,
			display: "Directory: Contoso / Group: Engineering",
			wantID:  "grp1",
		},
		{
			name:    "found devops",
			groups:  groups,
			display: "Directory: Contoso / Group: DevOps",
			wantID:  "grp2",
		},
		{
			name:    "not found",
			groups:  groups,
			display: "Directory: Contoso / Group: NonExistent",
			wantErr: true,
		},
		{
			name:    "empty groups",
			groups:  []models.GroupsEligibleTarget{},
			display: "Group: Test",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := FindGroupByDisplay(tt.groups, tt.display)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindGroupByDisplay() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.GroupID != tt.wantID {
				t.Errorf("FindGroupByDisplay().GroupID = %q, want %q", got.GroupID, tt.wantID)
			}
		})
	}
}

// TestSortGroupsForDisplay_CollisionOrdering pins a previously fixed bug: SelectGroup
// used to render options built from a sorted copy while resolving the user's answer
// against the caller's unsorted slice. Two groups can render to the same display
// string, so the two slices disagree about which group that string denotes and the
// user could be elevated into a group they did not pick. survey.Select cannot be
// driven from a test, so the ordering is asserted on the extracted helper: the slice
// FindGroupByDisplay searches must be the same ordered slice whose options were shown.
func TestSortGroupsForDisplay_CollisionOrdering(t *testing.T) {
	t.Parallel()
	// Deliberately unsorted input containing a display collision: the two
	// "Engineering" groups have no DirectoryName, so both render identically.
	groups := []models.GroupsEligibleTarget{
		{DirectoryID: "dir-z", GroupID: "grp-zebra", GroupName: "Zebra Team"},
		{DirectoryID: "dir-1", GroupID: "grp-eng-1", GroupName: "Engineering"},
		{DirectoryID: "dir-2", GroupID: "grp-eng-2", GroupName: "Engineering"},
		{DirectoryID: "dir-a", GroupID: "grp-alpha", GroupName: "Alpha Team"},
	}

	sorted := sortGroupsForDisplay(groups)

	if len(sorted) != len(groups) {
		t.Fatalf("sortGroupsForDisplay() length = %d, want %d", len(sorted), len(groups))
	}

	options := make([]string, len(sorted))
	for i := range sorted {
		options[i] = FormatGroupOption(sorted[i])
	}
	if !sort.StringsAreSorted(options) {
		t.Errorf("rendered options are not in display order: %q", options)
	}

	// Every option the user could pick must resolve, inside this same slice, to a
	// group that renders back to exactly that option.
	for i, opt := range options {
		got, err := FindGroupByDisplay(sorted, opt)
		if err != nil {
			t.Fatalf("option %d (%q) not found in the slice it was rendered from: %v", i, opt, err)
		}
		if back := FormatGroupOption(*got); back != opt {
			t.Errorf("option %d (%q) resolved to a group rendering as %q", i, opt, back)
		}
	}

	// The caller's slice must not be reordered underneath it.
	if groups[0].GroupID != "grp-zebra" || groups[3].GroupID != "grp-alpha" {
		t.Errorf("sortGroupsForDisplay() mutated the caller's slice: %+v", groups)
	}
}

// Not parallel: mutates the package-global IsTerminalFunc.
func TestSelectGroup_EmptyList(t *testing.T) {
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()
	IsTerminalFunc = func(fd uintptr) bool { return true }

	_, err := SelectGroup(nil)
	if err == nil {
		t.Fatal("expected error for empty list")
	}
	if !strings.Contains(err.Error(), "no eligible groups available") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Not parallel: mutates the package-global IsTerminalFunc.
func TestSelectGroup_NonTTY(t *testing.T) {
	original := IsTerminalFunc
	defer func() { IsTerminalFunc = original }()
	IsTerminalFunc = func(fd uintptr) bool { return false }

	groups := []models.GroupsEligibleTarget{
		{DirectoryID: "dir1", GroupID: "grp1", GroupName: "Engineering"},
	}

	_, err := SelectGroup(groups)
	if err == nil {
		t.Fatal("expected error for non-TTY")
	}
	if !errors.Is(err, ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--group") {
		t.Errorf("error should mention --group, got: %v", err)
	}
}
