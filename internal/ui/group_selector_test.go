package ui

import (
	"errors"
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

func TestSelectGroup_NonTTY(t *testing.T) {
	t.Parallel()
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
