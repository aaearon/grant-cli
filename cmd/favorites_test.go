package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/cache"
	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
)

func TestFavoritesListCommand(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func(string)
		wantContain []string
		wantErr     bool
	}{
		{
			name: "list with multiple favorites",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "dev", config.Favorite{
					Provider: "azure",
					Target:   "subscription-123",
					Role:     "Contributor",
				})
				_ = config.AddFavorite(cfg, "prod", config.Favorite{
					Provider: "azure",
					Target:   "subscription-456",
					Role:     "Reader",
				})
				_ = config.Save(cfg, path)
			},
			wantContain: []string{
				"dev: azure/subscription-123/Contributor",
				"prod: azure/subscription-456/Reader",
			},
			wantErr: false,
		},
		{
			name: "list with empty favorites",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			wantContain: []string{"No favorites saved", "grant favorites add"},
			wantErr:     false,
		},
		{
			name:        "list with no config file",
			setupConfig: func(path string) {},
			wantContain: []string{"No favorites saved", "grant favorites add"},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup temp config
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			t.Setenv("GRANT_CONFIG", configPath)

			tt.setupConfig(configPath)

			// Execute command
			rootCmd := newTestRootCommand()
			favCmd := NewFavoritesCommand()
			rootCmd.AddCommand(favCmd)

			output, err := executeCommand(rootCmd, "favorites", "list")

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestFavoritesList_VerboseLogs(t *testing.T) {
	spy := &spyLogger{}
	oldLog := log
	log = spy
	defer func() { log = oldLog }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	cfg := config.DefaultConfig()
	_ = config.AddFavorite(cfg, "dev", config.Favorite{
		Provider: "azure",
		Target:   "sub-123",
		Role:     "Contributor",
	})
	_ = config.AddFavorite(cfg, "prod", config.Favorite{
		Provider: "azure",
		Target:   "sub-456",
		Role:     "Reader",
	})
	_ = config.Save(cfg, configPath)

	rootCmd := newTestRootCommand()
	rootCmd.AddCommand(NewFavoritesCommand())
	_, err := executeCommand(rootCmd, "favorites", "list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantMessages := []string{"Loading config", "2 favorite"}
	for _, want := range wantMessages {
		found := false
		for _, msg := range spy.messages {
			if strings.Contains(msg, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected log containing %q, got: %v", want, spy.messages)
		}
	}
}

func TestFavoritesRemove_VerboseLogs(t *testing.T) {
	spy := &spyLogger{}
	oldLog := log
	log = spy
	defer func() { log = oldLog }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	cfg := config.DefaultConfig()
	_ = config.AddFavorite(cfg, "dev", config.Favorite{
		Provider: "azure",
		Target:   "sub-123",
		Role:     "Contributor",
	})
	_ = config.Save(cfg, configPath)

	rootCmd := newTestRootCommand()
	rootCmd.AddCommand(NewFavoritesCommand())
	_, err := executeCommand(rootCmd, "favorites", "remove", "dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantMessages := []string{"Loading config", "Removing favorite", "Saving config"}
	for _, want := range wantMessages {
		found := false
		for _, msg := range spy.messages {
			if strings.Contains(msg, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected log containing %q, got: %v", want, spy.messages)
		}
	}
}

func TestFavoritesAddNonInteractive_VerboseLogs(t *testing.T) {
	spy := &spyLogger{}
	oldLog := log
	log = spy
	defer func() { log = oldLog }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)
	cfg := config.DefaultConfig()
	_ = config.Save(cfg, configPath)

	rootCmd := newTestRootCommand()
	rootCmd.AddCommand(NewFavoritesCommand())
	_, err := executeCommand(rootCmd, "favorites", "add", "myfav", "--target", "sub-123", "--role", "Contributor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantMessages := []string{"Non-interactive mode", "Saving"}
	for _, want := range wantMessages {
		found := false
		for _, msg := range spy.messages {
			if strings.Contains(msg, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected log containing %q, got: %v", want, spy.messages)
		}
	}
}

func TestFavoritesRemoveCommand(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func(string)
		args        []string
		wantContain []string
		wantErr     bool
	}{
		{
			name: "remove existing favorite",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "dev", config.Favorite{
					Provider: "azure",
					Target:   "subscription-123",
					Role:     "Contributor",
				})
				_ = config.Save(cfg, path)
			},
			args:        []string{"dev"},
			wantContain: []string{"Removed favorite"},
			wantErr:     false,
		},
		{
			name: "remove non-existent favorite",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"nonexistent"},
			wantContain: []string{"not found"},
			wantErr:     true,
		},
		{
			name: "remove without name argument",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{},
			wantErr:     true,
			wantContain: []string{"requires a favorite name", "grant favorites list"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup temp config
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			t.Setenv("GRANT_CONFIG", configPath)

			tt.setupConfig(configPath)

			// Execute command
			rootCmd := newTestRootCommand()
			favCmd := NewFavoritesCommand()
			rootCmd.AddCommand(favCmd)

			cmdArgs := append([]string{"favorites", "remove"}, tt.args...)
			output, err := executeCommand(rootCmd, cmdArgs...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestFavoritesAddCommand(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func(string)
		args        []string
		wantErr     bool
		wantContain []string
	}{
		{
			name: "add without name in non-interactive mode requires name",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"--target", "sub-123", "--role", "Contributor"},
			wantErr:     true,
			wantContain: []string{"name is required"},
		},
		{
			name: "add duplicate favorite name",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "dev", config.Favorite{
					Provider: "azure",
					Target:   "subscription-123",
					Role:     "Contributor",
				})
				_ = config.Save(cfg, path)
			},
			args:    []string{"dev"},
			wantErr: true, // Should fail with duplicate error
		},
		{
			name: "success with target and role flags",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"myfav", "--target", "sub-123", "--role", "Contributor"},
			wantErr:     false,
			wantContain: []string{"Added favorite", "myfav", "azure/sub-123/Contributor"},
		},
		{
			name: "success with all three flags",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"myfav2", "--provider", "azure", "--target", "sub-456", "--role", "Reader"},
			wantErr:     false,
			wantContain: []string{"Added favorite", "myfav2", "azure/sub-456/Reader"},
		},
		{
			name: "success with custom provider",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"myfav3", "--provider", "aws", "--target", "account-789", "--role", "Admin"},
			wantErr:     false,
			wantContain: []string{"Added favorite", "myfav3", "aws/account-789/Admin"},
		},
		{
			name: "error target only without role",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"myfav", "--target", "sub-123"},
			wantErr:     true,
			wantContain: []string{"both --target and --role must be provided"},
		},
		{
			name: "error role only without target",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"myfav", "--role", "Contributor"},
			wantErr:     true,
			wantContain: []string{"both --target and --role must be provided"},
		},
		{
			name: "duplicate name with flags",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "dev", config.Favorite{
					Provider: "azure",
					Target:   "subscription-123",
					Role:     "Contributor",
				})
				_ = config.Save(cfg, path)
			},
			args:        []string{"dev", "--target", "sub-456", "--role", "Reader"},
			wantErr:     true,
			wantContain: []string{"already exists"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup temp config
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			t.Setenv("GRANT_CONFIG", configPath)

			tt.setupConfig(configPath)

			// Execute command
			rootCmd := newTestRootCommand()
			favCmd := NewFavoritesCommand()
			rootCmd.AddCommand(favCmd)

			cmdArgs := append([]string{"favorites", "add"}, tt.args...)
			output, err := executeCommand(rootCmd, cmdArgs...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestFavoritesAddWithFlagsPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	// Save initial config
	cfg := config.DefaultConfig()
	_ = config.Save(cfg, configPath)

	// Add favorite via flags
	rootCmd := newTestRootCommand()
	favCmd := NewFavoritesCommand()
	rootCmd.AddCommand(favCmd)

	_, err := executeCommand(rootCmd, "favorites", "add", "persist-test", "--target", "sub-999", "--role", "Owner")
	if err != nil {
		t.Fatalf("add favorite failed: %v", err)
	}

	// Reload config from disk and verify
	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("failed to reload config: %v", err)
	}

	fav, err := config.GetFavorite(reloaded, "persist-test")
	if err != nil {
		t.Fatalf("favorite not found after reload: %v", err)
	}

	if fav.Provider != "azure" {
		t.Errorf("provider = %q, want %q", fav.Provider, "azure")
	}
	if fav.Target != "sub-999" {
		t.Errorf("target = %q, want %q", fav.Target, "sub-999")
	}
	if fav.Role != "Owner" {
		t.Errorf("role = %q, want %q", fav.Role, "Owner")
	}
}

func TestFavoritesCommandIntegration(t *testing.T) {
	// Setup temp config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	// Initialize config
	cfg := config.DefaultConfig()
	_ = config.Save(cfg, configPath)

	// Test that favorites command is properly registered
	rootCmd := newTestRootCommand()
	favCmd := NewFavoritesCommand()
	rootCmd.AddCommand(favCmd)

	// Execute favorites list command
	output, err := executeCommand(rootCmd, "favorites", "list")
	if err != nil {
		t.Fatalf("favorites list command failed: %v", err)
	}

	// Should show no favorites message
	if !strings.Contains(output, "No favorites saved") {
		t.Errorf("expected empty favorites message, got: %s", output)
	}
}

func TestFavoritesParentCommand(t *testing.T) {
	cmd := NewFavoritesCommand()

	// Check parent command structure
	if cmd.Use != "favorites" {
		t.Errorf("expected Use='favorites', got %q", cmd.Use)
	}

	// Check subcommands exist
	expectedSubcommands := []string{"add", "list", "remove"}
	commands := cmd.Commands()

	if len(commands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(commands))
	}

	for _, expected := range expectedSubcommands {
		found := false
		for _, c := range commands {
			// cobra Use field includes args like "add <name>", so check with HasPrefix
			if strings.HasPrefix(c.Use, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %q not found", expected)
		}
	}
}

func TestFavoritesAddInteractiveMode(t *testing.T) {
	twoTargets := []models.EligibleTarget{
		{
			OrganizationID: "org-123",
			WorkspaceID:    "sub-456",
			WorkspaceName:  "Prod-EastUS",
			WorkspaceType:  models.WorkspaceTypeSubscription,
			RoleInfo:       models.RoleInfo{ID: "role-789", Name: "Contributor"},
		},
		{
			OrganizationID: "org-123",
			WorkspaceID:    "sub-abc",
			WorkspaceName:  "Dev-WestEU",
			WorkspaceType:  models.WorkspaceTypeSubscription,
			RoleInfo:       models.RoleInfo{ID: "role-def", Name: "Reader"},
		},
	}

	tests := []struct {
		name         string
		setupConfig  func(string)
		eligLister   eligibilityLister
		groupsElig   groupsEligibilityLister
		selector     unifiedSelector
		namePrompter namePrompter
		args         []string
		wantContain  []string
		wantErr      bool
	}{
		{
			name: "success - selects cloud target from eligibility",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
					if csp == models.CSPAzure {
						return &models.EligibilityResponse{Response: twoTargets, Total: 2}, nil
					}
					return &models.EligibilityResponse{}, nil
				},
			},
			selector: &mockUnifiedSelector{
				item: &selectionItem{kind: selectionCloud, cloud: &twoTargets[0]},
			},
			args:        []string{"myfav"},
			wantContain: []string{"Added favorite", "myfav", "azure/Prod-EastUS/Contributor"},
			wantErr:     false,
		},
		{
			name: "success - provider from flag",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				response: &models.EligibilityResponse{
					Response: twoTargets,
					Total:    2,
				},
			},
			selector: &mockUnifiedSelector{
				item: &selectionItem{kind: selectionCloud, cloud: &twoTargets[0]},
			},
			args:        []string{"myfav", "--provider", "azure"},
			wantContain: []string{"Added favorite", "myfav", "azure/Prod-EastUS/Contributor"},
			wantErr:     false,
		},
		{
			name: "success - no provider flag (multi-CSP)",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
					if csp == models.CSPAzure {
						return &models.EligibilityResponse{Response: twoTargets, Total: 2}, nil
					}
					return &models.EligibilityResponse{}, nil
				},
			},
			selector: &mockUnifiedSelector{
				item: &selectionItem{kind: selectionCloud, cloud: &twoTargets[1]},
			},
			args:        []string{"myfav"},
			wantContain: []string{"Added favorite", "myfav", "azure/Dev-WestEU/Reader"},
			wantErr:     false,
		},
		{
			name: "success - selects group from unified list",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
					if csp == models.CSPAzure {
						return &models.EligibilityResponse{Response: twoTargets, Total: 2}, nil
					}
					return &models.EligibilityResponse{}, nil
				},
			},
			groupsElig: &mockGroupsEligibilityLister{
				response: &models.GroupsEligibilityResponse{
					Response: []models.GroupsEligibleTarget{
						{DirectoryID: "dir-1", GroupID: "grp-1", GroupName: "Engineering"},
					},
					Total: 1,
				},
			},
			selector: &mockUnifiedSelector{
				selectFunc: func(items []selectionItem) (*selectionItem, error) {
					// Verify both cloud and group items are present
					hasCloud, hasGroup := false, false
					for _, item := range items {
						if item.kind == selectionCloud {
							hasCloud = true
						}
						if item.kind == selectionGroup {
							hasGroup = true
						}
					}
					if !hasCloud {
						return nil, errors.New("expected cloud items in unified selector")
					}
					if !hasGroup {
						return nil, errors.New("expected group items in unified selector")
					}
					// Select the group
					for i := range items {
						if items[i].kind == selectionGroup {
							return &items[i], nil
						}
					}
					return nil, errors.New("no group item found")
				},
			},
			args:        []string{"my-grp-fav"},
			wantContain: []string{"Added favorite", "my-grp-fav", "groups/Engineering"},
			wantErr:     false,
		},
		{
			name: "eligibility fetch fails",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				listErr: errors.New("API error: unauthorized"),
			},
			selector:    &mockUnifiedSelector{},
			args:        []string{"myfav", "--provider", "azure"},
			wantContain: []string{"failed to fetch eligible targets"},
			wantErr:     true,
		},
		{
			name: "no eligible targets or groups",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
					return &models.EligibilityResponse{Response: []models.EligibleTarget{}, Total: 0}, nil
				},
			},
			selector:    &mockUnifiedSelector{},
			args:        []string{"myfav"},
			wantContain: []string{"no eligible"},
			wantErr:     true,
		},
		{
			name: "selector cancelled",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
					if csp == models.CSPAzure {
						return &models.EligibilityResponse{Response: twoTargets, Total: 2}, nil
					}
					return &models.EligibilityResponse{}, nil
				},
			},
			selector: &mockUnifiedSelector{
				selectErr: errors.New("user cancelled"),
			},
			args:        []string{"myfav"},
			wantContain: []string{"selection failed"},
			wantErr:     true,
		},
		{
			name: "duplicate name",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "myfav", config.Favorite{
					Provider: "azure",
					Target:   "existing-sub",
					Role:     "Reader",
				})
				_ = config.Save(cfg, path)
			},
			eligLister:  nil, // should not be called
			selector:    nil, // should not be called
			args:        []string{"myfav"},
			wantContain: []string{"already exists"},
			wantErr:     true,
		},
		{
			name: "flags bypass eligibility",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister:  nil, // nil — should not be called
			selector:    nil, // nil — should not be called
			args:        []string{"myfav", "--target", "sub-123", "--role", "Contributor"},
			wantContain: []string{"Added favorite", "myfav", "azure/sub-123/Contributor"},
			wantErr:     false,
		},
		{
			name: "no name - interactive prompts for name after selection",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
					if csp == models.CSPAzure {
						return &models.EligibilityResponse{Response: twoTargets, Total: 2}, nil
					}
					return &models.EligibilityResponse{}, nil
				},
			},
			selector: &mockUnifiedSelector{
				item: &selectionItem{kind: selectionCloud, cloud: &twoTargets[0]},
			},
			namePrompter: &mockNamePrompter{name: "my-fav"},
			args:         []string{},
			wantContain:  []string{"Added favorite", "my-fav", "azure/Prod-EastUS/Contributor"},
			wantErr:      false,
		},
		{
			name: "no name - prompted name is duplicate",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "existing", config.Favorite{
					Provider: "azure",
					Target:   "sub-old",
					Role:     "Reader",
				})
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
					if csp == models.CSPAzure {
						return &models.EligibilityResponse{Response: twoTargets, Total: 2}, nil
					}
					return &models.EligibilityResponse{}, nil
				},
			},
			selector: &mockUnifiedSelector{
				item: &selectionItem{kind: selectionCloud, cloud: &twoTargets[0]},
			},
			namePrompter: &mockNamePrompter{name: "existing"},
			args:         []string{},
			wantContain:  []string{"already exists"},
			wantErr:      true,
		},
		{
			name: "no name - prompter error",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
					if csp == models.CSPAzure {
						return &models.EligibilityResponse{Response: twoTargets, Total: 2}, nil
					}
					return &models.EligibilityResponse{}, nil
				},
			},
			selector: &mockUnifiedSelector{
				item: &selectionItem{kind: selectionCloud, cloud: &twoTargets[0]},
			},
			namePrompter: &mockNamePrompter{promptErr: errors.New("user cancelled")},
			args:         []string{},
			wantContain:  []string{"failed to read favorite name"},
			wantErr:      true,
		},
		{
			name: "no name with flags - non-interactive requires name",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: nil,
			selector:   nil,
			args:       []string{"--target", "sub-123", "--role", "Contributor"},
			wantContain: []string{"name is required"},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			t.Setenv("GRANT_CONFIG", configPath)

			tt.setupConfig(configPath)

			rootCmd := newTestRootCommand()
			favCmd := NewFavoritesCommandWithAllDeps(tt.eligLister, tt.selector, tt.namePrompter, tt.groupsElig)
			rootCmd.AddCommand(favCmd)

			cmdArgs := append([]string{"favorites", "add"}, tt.args...)
			output, err := executeCommand(rootCmd, cmdArgs...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestFavoritesAddGroupFavorite(t *testing.T) {
	tests := []struct {
		name         string
		setupConfig  func(string)
		eligLister   eligibilityLister
		groupsElig   groupsEligibilityLister
		selector     unifiedSelector
		namePrompter namePrompter
		args         []string
		wantContain  []string
		wantErr      bool
	}{
		{
			name: "non-interactive - group via flags",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"my-grp", "--type", "groups", "--group", "Engineering"},
			wantContain: []string{"Added favorite", "my-grp", "groups/Engineering"},
			wantErr:     false,
		},
		{
			name: "non-interactive - requires name",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"--type", "groups", "--group", "Engineering"},
			wantContain: []string{"name is required"},
			wantErr:     true,
		},
		{
			name: "invalid type",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"test", "--type", "invalid"},
			wantContain: []string{"invalid --type"},
			wantErr:     true,
		},
		{
			name: "target flag with groups type - error",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"test", "--type", "groups", "--target", "sub-1", "--role", "Reader"},
			wantContain: []string{"--target and --role cannot be used with --type groups"},
			wantErr:     true,
		},
		{
			name: "group flag without type groups - error",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"test", "--group", "Engineering"},
			wantContain: []string{"--group requires --type groups"},
			wantErr:     true,
		},
		{
			name: "interactive - selects from eligible groups via unified selector",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				response: &models.EligibilityResponse{
					Response: []models.EligibleTarget{
						{
							WorkspaceID:   "dir-1",
							WorkspaceName: "CyberIAM Tech Labs",
							WorkspaceType: models.WorkspaceTypeDirectory,
						},
					},
				},
			},
			groupsElig: &mockGroupsEligibilityLister{
				response: &models.GroupsEligibilityResponse{
					Response: []models.GroupsEligibleTarget{
						{DirectoryID: "dir-1", GroupID: "grp-1", GroupName: "Engineering"},
					},
					Total: 1,
				},
			},
			selector: &mockUnifiedSelector{
				selectFunc: func(items []selectionItem) (*selectionItem, error) {
					// Verify only group items are present (--type groups)
					for _, item := range items {
						if item.kind != selectionGroup {
							return nil, errors.New("expected only group items for --type groups")
						}
					}
					// Verify directory name was enriched
					if items[0].group.DirectoryName != "CyberIAM Tech Labs" {
						return nil, errors.New("expected DirectoryName to be enriched")
					}
					return &items[0], nil
				},
			},
			args:        []string{"my-grp", "--type", "groups"},
			wantContain: []string{"Added favorite", "my-grp", "groups/Engineering"},
			wantErr:     false,
		},
		{
			name: "interactive - works without eligLister (no directory enrichment)",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			groupsElig: &mockGroupsEligibilityLister{
				response: &models.GroupsEligibilityResponse{
					Response: []models.GroupsEligibleTarget{
						{DirectoryID: "dir-1", GroupID: "grp-1", GroupName: "Engineering"},
					},
					Total: 1,
				},
			},
			selector: &mockUnifiedSelector{
				selectFunc: func(items []selectionItem) (*selectionItem, error) {
					// Directory name should be empty when no eligLister
					if items[0].group.DirectoryName != "" {
						return nil, errors.New("expected empty DirectoryName without eligLister")
					}
					return &items[0], nil
				},
			},
			args:        []string{"my-grp", "--type", "groups"},
			wantContain: []string{"Added favorite", "my-grp", "groups/Engineering"},
			wantErr:     false,
		},
		{
			name: "non-interactive - persists to disk",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:        []string{"grp-fav", "--type", "groups", "--group", "DevOps"},
			wantContain: []string{"Added favorite", "grp-fav", "groups/DevOps"},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			t.Setenv("GRANT_CONFIG", configPath)

			tt.setupConfig(configPath)

			rootCmd := newTestRootCommand()
			favCmd := NewFavoritesCommandWithAllDeps(tt.eligLister, tt.selector, tt.namePrompter, tt.groupsElig)
			rootCmd.AddCommand(favCmd)

			cmdArgs := append([]string{"favorites", "add"}, tt.args...)
			output, err := executeCommand(rootCmd, cmdArgs...)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v, output:\n%s", err, tt.wantErr, output)
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}

func TestFavoritesAddGroupPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	cfg := config.DefaultConfig()
	_ = config.Save(cfg, configPath)

	rootCmd := newTestRootCommand()
	favCmd := NewFavoritesCommandWithAllDeps(nil, nil, nil, nil)
	rootCmd.AddCommand(favCmd)

	_, err := executeCommand(rootCmd, "favorites", "add", "grp-fav", "--type", "groups", "--group", "DevOps")
	if err != nil {
		t.Fatalf("add group favorite failed: %v", err)
	}

	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("reload config failed: %v", err)
	}

	fav, err := config.GetFavorite(reloaded, "grp-fav")
	if err != nil {
		t.Fatalf("favorite not found: %v", err)
	}

	if fav.ResolvedType() != config.FavoriteTypeGroups {
		t.Errorf("ResolvedType() = %q, want %q", fav.ResolvedType(), config.FavoriteTypeGroups)
	}
	if fav.Group != "DevOps" {
		t.Errorf("Group = %q, want %q", fav.Group, "DevOps")
	}
	if fav.Provider != "azure" {
		t.Errorf("Provider = %q, want %q", fav.Provider, "azure")
	}
}

func TestFavoritesAdd_CachedEligibility(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)
	cfg := config.DefaultConfig()
	_ = config.Save(cfg, configPath)

	azureTargets := []models.EligibleTarget{
		{
			OrganizationID: "org-123",
			WorkspaceID:    "sub-456",
			WorkspaceName:  "Prod-EastUS",
			WorkspaceType:  models.WorkspaceTypeSubscription,
			RoleInfo:       models.RoleInfo{ID: "role-789", Name: "Contributor"},
		},
	}

	innerCloud := newCountingEligibilityLister(&mockEligibilityLister{
		listFunc: func(_ context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
			if csp == models.CSPAzure {
				return &models.EligibilityResponse{Response: azureTargets, Total: 1}, nil
			}
			return &models.EligibilityResponse{}, nil
		},
	})

	store := cache.NewStore(filepath.Join(tmpDir, "cache"), 4*time.Hour)
	cachedLister := cache.NewCachedEligibilityLister(innerCloud, nil, store, false, nil)

	selector := &mockUnifiedSelector{
		item: &selectionItem{kind: selectionCloud, cloud: &azureTargets[0]},
	}

	rootCmd := newTestRootCommand()
	favCmd := NewFavoritesCommandWithAllDeps(cachedLister, selector, nil, nil)
	rootCmd.AddCommand(favCmd)

	output, err := executeCommand(rootCmd, "favorites", "add", "myfav")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "Added favorite") {
		t.Errorf("output missing expected text, got:\n%s", output)
	}

	// fetchEligibility calls all CSPs when no provider specified
	if got := innerCloud.CallCount(models.CSPAzure); got != 1 {
		t.Errorf("Azure inner called %d times, want 1", got)
	}
	if got := innerCloud.CallCount(models.CSPAWS); got != 1 {
		t.Errorf("AWS inner called %d times, want 1", got)
	}
}

func TestFavoritesListWithGroupFavorites(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func(string)
		wantContain []string
	}{
		{
			name: "mixed cloud and group favorites",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "cloud-fav", config.Favorite{
					Provider: "azure",
					Target:   "sub-123",
					Role:     "Contributor",
				})
				_ = config.AddFavorite(cfg, "grp-fav", config.Favorite{
					Type:     config.FavoriteTypeGroups,
					Provider: "azure",
					Group:    "Engineering",
				})
				_ = config.Save(cfg, path)
			},
			wantContain: []string{
				"cloud-fav: azure/sub-123/Contributor",
				"grp-fav: groups/Engineering",
			},
		},
		{
			name: "only group favorites",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.AddFavorite(cfg, "eng", config.Favorite{
					Type:     config.FavoriteTypeGroups,
					Provider: "azure",
					Group:    "Engineering",
				})
				_ = config.Save(cfg, path)
			},
			wantContain: []string{
				"eng: groups/Engineering",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			t.Setenv("GRANT_CONFIG", configPath)

			tt.setupConfig(configPath)

			rootCmd := newTestRootCommand()
			favCmd := NewFavoritesCommand()
			rootCmd.AddCommand(favCmd)

			output, err := executeCommand(rootCmd, "favorites", "list")
			if err != nil {
				t.Fatalf("list failed: %v", err)
			}

			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
		})
	}
}
