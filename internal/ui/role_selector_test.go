package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

func TestFormatRoleOption(t *testing.T) {
	tests := []struct {
		name string
		in   models.OnDemandResource
		want string
	}{
		{"plain", models.OnDemandResource{ResourceName: "Reader"}, "Reader"},
		{"custom", models.OnDemandResource{ResourceName: "CyberArk-SIA", Custom: true}, "CyberArk-SIA  [custom]"},
		{"description", models.OnDemandResource{ResourceName: "Admin", Description: "Full access"}, "Admin — Full access"},
		{
			name: "description truncated",
			in:   models.OnDemandResource{ResourceName: "X", Description: strings.Repeat("a", 100)},
			want: "X — " + strings.Repeat("a", 70),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatRoleOption(tt.in); got != tt.want {
				t.Errorf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestBuildRoleOptions_CustomFirstThenAlpha(t *testing.T) {
	roles := []models.OnDemandResource{
		{ResourceName: "Reader"},
		{ResourceName: "Custom-B", Custom: true},
		{ResourceName: "Contributor"},
		{ResourceName: "Custom-A", Custom: true},
	}
	opts, sorted := BuildRoleOptions(roles)

	if len(opts) != 4 {
		t.Fatalf("expected 4 options, got %d", len(opts))
	}
	if sorted[0].ResourceName != "Custom-A" {
		t.Errorf("expected first = Custom-A, got %s", sorted[0].ResourceName)
	}
	if sorted[1].ResourceName != "Custom-B" {
		t.Errorf("expected second = Custom-B, got %s", sorted[1].ResourceName)
	}
	if sorted[2].ResourceName != "Contributor" {
		t.Errorf("expected third = Contributor, got %s", sorted[2].ResourceName)
	}
	if sorted[3].ResourceName != "Reader" {
		t.Errorf("expected fourth = Reader, got %s", sorted[3].ResourceName)
	}
	if !strings.Contains(opts[0], "[custom]") {
		t.Errorf("custom role option should include [custom] marker: %s", opts[0])
	}
}

func TestSelectRole_NonInteractive(t *testing.T) {
	orig := IsTerminalFunc
	defer func() { IsTerminalFunc = orig }()
	IsTerminalFunc = func(fd uintptr) bool { return false }

	_, err := SelectRole([]models.OnDemandResource{{ResourceID: "r1", ResourceName: "Reader"}})
	if err == nil {
		t.Fatal("expected error in non-interactive mode")
	}
	if !errors.Is(err, ErrNotInteractive) {
		t.Errorf("expected ErrNotInteractive, got %v", err)
	}
	if !strings.Contains(err.Error(), "--role-id") {
		t.Errorf("error should suggest --role-id: %v", err)
	}
}

// TestBuildRoleOptions_MixedCaseSort pins the strings.ToLower normalisation in the
// role sort. A case-sensitive comparison puts every capitalised name ahead of every
// lower-case one ("Zone" < "admin" in ASCII), scattering the list the user scans.
// The custom-first fixture above is uniformly capitalised and cannot see that.
func TestBuildRoleOptions_MixedCaseSort(t *testing.T) {
	roles := []models.OnDemandResource{
		{ResourceName: "cost-reader"},
		{ResourceName: "Backup Operator"},
		{ResourceName: "admin-lite"},
		{ResourceName: "Zone Editor"},
	}
	_, sorted := BuildRoleOptions(roles)

	want := []string{"admin-lite", "Backup Operator", "cost-reader", "Zone Editor"}
	for i, name := range want {
		if sorted[i].ResourceName != name {
			t.Errorf("position %d: got %q, want %q", i, sorted[i].ResourceName, name)
		}
	}
}

func TestSelectRole_EmptyList(t *testing.T) {
	orig := IsTerminalFunc
	defer func() { IsTerminalFunc = orig }()
	IsTerminalFunc = func(fd uintptr) bool { return true }

	_, err := SelectRole(nil)
	if err == nil {
		t.Fatal("expected error for empty list")
	}
	if !strings.Contains(err.Error(), "no on-demand roles") {
		t.Errorf("got: %v", err)
	}
}
