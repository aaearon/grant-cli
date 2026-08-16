package cmd

// Favorites persistence and flag-validation coverage.
//
// Fixture values are deliberately distinct and self-describing; see the header
// of output_contract_test.go for why that is mandatory rather than cosmetic.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
)

// twoGroupsSameName is the fixture for the DirectoryID persistence tests: two
// groups with the SAME display name in DIFFERENT directories. The names must
// collide, otherwise findMatchingGroup resolves on the name alone and the
// directory ID is never load-bearing.
func twoGroupsSameName() []models.GroupsEligibleTarget {
	return []models.GroupsEligibleTarget{
		{GroupName: "grp-name", GroupID: "grp-id-a", DirectoryID: "dir-id-a"},
		{GroupName: "grp-name", GroupID: "grp-id-b", DirectoryID: "dir-id-b"},
	}
}

// assertFavoriteResolvesToGroup reloads the saved favorite and pushes it back
// through findMatchingGroup — the production lookup behind `grant --favorite`.
// The round trip is what makes dropping `fav.DirectoryID = ...` fail: without
// it the favorite still names the right group, but resolution silently picks
// the first same-named group, in the wrong directory.
func assertFavoriteResolvesToGroup(t *testing.T, configPath, favName string, groups []models.GroupsEligibleTarget, wantDirectoryID, wantGroupID string) {
	t.Helper()

	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("reload config failed: %v", err)
	}
	fav, err := config.GetFavorite(reloaded, favName)
	if err != nil {
		t.Fatalf("favorite not found: %v", err)
	}
	if fav.DirectoryID != wantDirectoryID {
		t.Errorf("persisted DirectoryID = %q, want %q", fav.DirectoryID, wantDirectoryID)
	}

	match := findMatchingGroup(groups, fav.Group, fav.DirectoryID)
	if match == nil {
		t.Fatalf("findMatchingGroup(%q, %q) = nil", fav.Group, fav.DirectoryID)
	}
	if match.GroupID != wantGroupID {
		t.Errorf("favorite resolved to group %q, want %q", match.GroupID, wantGroupID)
	}
}

// TestFavoritesAddInteractive_PersistsDirectoryID covers the unified-selector
// path (selectFavoriteInteractive).
func TestFavoritesAddInteractive_PersistsDirectoryID(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)
	if err := config.Save(config.DefaultConfig(), configPath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	groups := twoGroupsSameName()
	eligLister := &mockEligibilityLister{response: &models.EligibilityResponse{
		Response: []models.EligibleTarget{{
			WorkspaceID: "ws-id", WorkspaceName: "ws-name",
			WorkspaceType: models.WorkspaceTypeSubscription,
			RoleInfo:      models.RoleInfo{ID: "role-id", Name: "role-name"},
		}},
		Total: 1,
	}}
	groupsElig := &mockGroupsEligibilityLister{response: &models.GroupsEligibilityResponse{
		Response: groups, Total: len(groups),
	}}
	// Select the SECOND group, so a dropped DirectoryID resolves to the first.
	sel := &mockUnifiedSelector{item: &selectionItem{kind: selectionGroup, group: &groups[1]}}

	rootCmd := newTestRootCommand()
	rootCmd.AddCommand(NewFavoritesCommandWithAllDeps(eligLister, sel, &mockNamePrompter{}, groupsElig))

	if out, err := executeCommand(rootCmd, "favorites", "add", "fav-group"); err != nil {
		t.Fatalf("add favorite failed: %v\noutput: %s", err, out)
	}

	assertFavoriteResolvesToGroup(t, configPath, "fav-group", twoGroupsSameName(), "dir-id-b", "grp-id-b")
}

// TestAddGroupFavorite_PersistsDirectoryID covers the `--type groups` selector
// path (addGroupFavorite), which copies the directory ID independently.
func TestAddGroupFavorite_PersistsDirectoryID(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)
	if err := config.Save(config.DefaultConfig(), configPath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	groups := twoGroupsSameName()
	groupsElig := &mockGroupsEligibilityLister{response: &models.GroupsEligibilityResponse{
		Response: groups, Total: len(groups),
	}}
	sel := &mockUnifiedSelector{item: &selectionItem{kind: selectionGroup, group: &groups[1]}}

	rootCmd := newTestRootCommand()
	rootCmd.AddCommand(NewFavoritesCommandWithAllDeps(nil, sel, &mockNamePrompter{}, groupsElig))

	if out, err := executeCommand(rootCmd, "favorites", "add", "fav-group", "--type", "groups"); err != nil {
		t.Fatalf("add group favorite failed: %v\noutput: %s", err, out)
	}

	assertFavoriteResolvesToGroup(t, configPath, "fav-group", twoGroupsSameName(), "dir-id-b", "grp-id-b")
}

// TestFavoritesAdd_HonorsNonDefaultProvider pins that a providerless
// `favorites add --target/--role` takes its provider from
// config.default_provider. Every other test uses DefaultConfig(), whose default
// already IS "azure", so a hardcoded "azure" was indistinguishable from
// reading the field.
func TestFavoritesAdd_HonorsNonDefaultProvider(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	cfg := config.DefaultConfig()
	cfg.DefaultProvider = "aws"
	if err := config.Save(cfg, configPath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	rootCmd := newTestRootCommand()
	rootCmd.AddCommand(NewFavoritesCommand())

	out, err := executeCommand(rootCmd, "favorites", "add", "fav-cloud", "--target", "ws-name", "--role", "role-name")
	if err != nil {
		t.Fatalf("add favorite failed: %v\noutput: %s", err, out)
	}

	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("reload config failed: %v", err)
	}
	fav, err := config.GetFavorite(reloaded, "fav-cloud")
	if err != nil {
		t.Fatalf("favorite not found: %v", err)
	}
	if fav.Provider != "aws" {
		t.Errorf("Provider = %q, want aws (from config.default_provider)", fav.Provider)
	}
}

// TestFavoritesAddInteractive_ProviderFlagWinsOverTargetCSP pins the precedence
// in selectFavoriteInteractive: an explicit --provider is stored verbatim
// rather than derived from the selected target's CSP. The fixture is
// deliberately impossible: --provider azure with an AWS target is a
// combination production filtering would never produce, and it exists only so
// the two branches yield different values. Do not read it as a realistic
// scenario, and do not "fix" it to azure — with both azure the branches are
// indistinguishable and the mutation survives.
func TestFavoritesAddInteractive_ProviderFlagWinsOverTargetCSP(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)
	if err := config.Save(config.DefaultConfig(), configPath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	selected := models.EligibleTarget{
		CSP:         models.CSPAWS,
		WorkspaceID: "ws-id", WorkspaceName: "ws-name",
		WorkspaceType: models.WorkspaceTypeAccount,
		RoleInfo:      models.RoleInfo{ID: "role-id", Name: "role-name"},
	}
	eligLister := &mockEligibilityLister{response: &models.EligibilityResponse{
		Response: []models.EligibleTarget{selected}, Total: 1,
	}}
	sel := &mockUnifiedSelector{item: &selectionItem{kind: selectionCloud, cloud: &selected}}

	rootCmd := newTestRootCommand()
	rootCmd.AddCommand(NewFavoritesCommandWithAllDeps(eligLister, sel, &mockNamePrompter{}, nil))

	out, err := executeCommand(rootCmd, "favorites", "add", "fav-cloud", "--provider", "azure")
	if err != nil {
		t.Fatalf("add favorite failed: %v\noutput: %s", err, out)
	}

	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("reload config failed: %v", err)
	}
	fav, err := config.GetFavorite(reloaded, "fav-cloud")
	if err != nil {
		t.Fatalf("favorite not found: %v", err)
	}
	if fav.Provider != "azure" {
		t.Errorf("Provider = %q, want azure (the --provider flag, not the target CSP)", fav.Provider)
	}
}

// TestParseFavoritesAddFlags_Validation exercises parseFavoritesAddFlags
// directly. runFavoritesAddProduction repeats two of these checks, so the
// command-level tests keep passing when this copy is deleted — every DI caller
// of runFavoritesAddWithDeps would lose the validation silently.
func TestParseFavoritesAddFlags_Validation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		// wantErrContains empty means the parse must succeed.
		wantErrContains string
	}{
		{name: "cloud target and role", args: []string{"--target", "ws-name", "--role", "role-name"}},
		{name: "groups with group", args: []string{"--type", "groups", "--group", "grp-name"}},
		{name: "groups with target", args: []string{"--type", "groups", "--target", "ws-name"}, wantErrContains: "--target and --role cannot be used with --type groups"},
		{name: "groups with role", args: []string{"--type", "groups", "--role", "role-name"}, wantErrContains: "--target and --role cannot be used with --type groups"},
		{name: "group without type groups", args: []string{"--group", "grp-name"}, wantErrContains: "--group requires --type groups"},
		{name: "target without role", args: []string{"--target", "ws-name"}, wantErrContains: "both --target and --role must be provided"},
		{name: "role without target", args: []string{"--role", "role-name"}, wantErrContains: "both --target and --role must be provided"},
		{name: "invalid type", args: []string{"--type", "bogus"}, wantErrContains: `invalid --type "bogus"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newFavoritesAddCommandWithRunner(nil)
			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatalf("ParseFlags() error = %v", err)
			}

			f, err := parseFavoritesAddFlags(cmd)
			if tt.wantErrContains == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if f == nil {
					t.Fatal("expected parsed flags, got nil")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrContains)
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErrContains)
			}
		})
	}
}

// TestFavoritesRemove_RejectsExtraArgs pins the arity check: without it,
// `grant favorites remove first second` silently removes only "first".
func TestFavoritesRemove_RejectsExtraArgs(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	cfg := config.DefaultConfig()
	if err := config.AddFavorite(cfg, "fav-first", config.Favorite{Provider: "azure", Target: "ws-name", Role: "role-name"}); err != nil {
		t.Fatalf("AddFavorite() error = %v", err)
	}
	if err := config.AddFavorite(cfg, "fav-second", config.Favorite{Provider: "aws", Target: "ws-name-2", Role: "role-name-2"}); err != nil {
		t.Fatalf("AddFavorite() error = %v", err)
	}
	if err := config.Save(cfg, configPath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	rootCmd := newTestRootCommand()
	rootCmd.AddCommand(NewFavoritesCommand())

	_, err := executeCommand(rootCmd, "favorites", "remove", "fav-first", "fav-second")
	if err == nil {
		t.Fatal("expected an error for two favorite names")
	}
	if !strings.Contains(err.Error(), "expected 1 favorite name, got 2") {
		t.Errorf("error = %v, want the arity message", err)
	}

	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("reload config failed: %v", err)
	}
	for _, name := range []string{"fav-first", "fav-second"} {
		if _, err := config.GetFavorite(reloaded, name); err != nil {
			t.Errorf("favorite %q was removed despite the rejected command", name)
		}
	}
}
