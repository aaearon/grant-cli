package ui

import (
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
