package cmd

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

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
		selector     targetSelector
		namePrompter namePrompter
		args         []string
		wantContain  []string
		wantErr      bool
	}{
		{
			name: "success - selects target from eligibility",
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
			selector: &mockTargetSelector{
				target: &twoTargets[0],
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
			selector: &mockTargetSelector{
				target: &twoTargets[0],
			},
			args:        []string{"myfav", "--provider", "azure"},
			wantContain: []string{"Added favorite", "myfav", "azure/Prod-EastUS/Contributor"},
			wantErr:     false,
		},
		{
			name: "success - provider defaults from config",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				cfg.DefaultProvider = "azure"
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				response: &models.EligibilityResponse{
					Response: twoTargets,
					Total:    2,
				},
			},
			selector: &mockTargetSelector{
				target: &twoTargets[1],
			},
			args:        []string{"myfav"},
			wantContain: []string{"Added favorite", "myfav", "azure/Dev-WestEU/Reader"},
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
			selector:    &mockTargetSelector{},
			args:        []string{"myfav"},
			wantContain: []string{"failed to fetch eligible targets"},
			wantErr:     true,
		},
		{
			name: "no eligible targets",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			eligLister: &mockEligibilityLister{
				response: &models.EligibilityResponse{
					Response: []models.EligibleTarget{},
					Total:    0,
				},
			},
			selector:    &mockTargetSelector{},
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
				response: &models.EligibilityResponse{
					Response: twoTargets,
					Total:    2,
				},
			},
			selector: &mockTargetSelector{
				selectErr: errors.New("user cancelled"),
			},
			args:        []string{"myfav"},
			wantContain: []string{"target selection failed"},
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
				response: &models.EligibilityResponse{
					Response: twoTargets,
					Total:    2,
				},
			},
			selector: &mockTargetSelector{
				target: &twoTargets[0],
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
				response: &models.EligibilityResponse{
					Response: twoTargets,
					Total:    2,
				},
			},
			selector: &mockTargetSelector{
				target: &twoTargets[0],
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
				response: &models.EligibilityResponse{
					Response: twoTargets,
					Total:    2,
				},
			},
			selector: &mockTargetSelector{
				target: &twoTargets[0],
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
			favCmd := NewFavoritesCommandWithDeps(tt.eligLister, tt.selector, tt.namePrompter)
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
