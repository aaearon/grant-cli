package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/config"
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
			wantContain: []string{"No favorites saved"},
			wantErr:     false,
		},
		{
			name:        "list with no config file",
			setupConfig: func(path string) {},
			wantContain: []string{"No favorites saved"},
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
			rootCmd := NewRootCommand()
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
			args:    []string{},
			wantErr: true,
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
			rootCmd := NewRootCommand()
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
	}{
		{
			name: "add without name argument",
			setupConfig: func(path string) {
				cfg := config.DefaultConfig()
				_ = config.Save(cfg, path)
			},
			args:    []string{},
			wantErr: true,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup temp config
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			t.Setenv("GRANT_CONFIG", configPath)

			tt.setupConfig(configPath)

			// Execute command
			rootCmd := NewRootCommand()
			favCmd := NewFavoritesCommand()
			rootCmd.AddCommand(favCmd)

			cmdArgs := append([]string{"favorites", "add"}, tt.args...)
			_, err := executeCommand(rootCmd, cmdArgs...)

			// For add command, we expect errors based on missing args
			// The interactive prompts can't be tested without mocking survey
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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
	rootCmd := NewRootCommand()
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
