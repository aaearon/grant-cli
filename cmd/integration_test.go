//go:build integration

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain builds the binary before running integration tests
func TestMain(m *testing.M) {
	// Build the binary
	cmd := exec.Command("go", "build", "-o", "../grant-test", "../.")
	if err := cmd.Run(); err != nil {
		panic("Failed to build binary for integration tests: " + err.Error())
	}

	// Run tests
	code := m.Run()

	// Clean up
	os.Remove("../grant-test")

	os.Exit(code)
}

func getBinaryPath() string {
	return filepath.Join("..", "grant-test")
}

func TestIntegration_Help(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantText []string
	}{
		{
			name:     "root help",
			args:     []string{"--help"},
			wantText: []string{"grant", "Available Commands:", "configure", "login", "status"},
		},
		{
			name:     "short help flag",
			args:     []string{"-h"},
			wantText: []string{"grant", "Available Commands:"},
		},
		{
			name:     "help command",
			args:     []string{"help"},
			wantText: []string{"grant", "Available Commands:"},
		},
		{
			name:     "root elevation help",
			args:     []string{"--help"},
			wantText: []string{"--provider", "--target", "--role", "--favorite"},
		},
		{
			name:     "configure help",
			args:     []string{"configure", "--help"},
			wantText: []string{"configure", "tenant URL", "username"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(getBinaryPath(), tt.args...)
			output, err := cmd.CombinedOutput()
			if err != nil && !strings.Contains(string(output), "Usage:") {
				t.Fatalf("Command failed: %v\nOutput: %s", err, output)
			}

			outputStr := string(output)
			for _, want := range tt.wantText {
				if !strings.Contains(outputStr, want) {
					t.Errorf("Expected output to contain %q, got:\n%s", want, outputStr)
				}
			}
		})
	}
}

func TestIntegration_Version(t *testing.T) {
	cmd := exec.Command(getBinaryPath(), "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Version command failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	requiredFields := []string{"grant version", "commit:", "built:"}

	for _, field := range requiredFields {
		if !strings.Contains(outputStr, field) {
			t.Errorf("Expected output to contain %q, got:\n%s", field, outputStr)
		}
	}

	// Should contain at least one of the default values (dev build)
	if !strings.Contains(outputStr, "dev") && !strings.Contains(outputStr, "unknown") {
		t.Errorf("Expected version output to show dev build info, got:\n%s", outputStr)
	}
}

func TestIntegration_ElevateWithoutLogin(t *testing.T) {
	// Set a temporary config path to avoid interfering with real config
	tempDir := t.TempDir()

	cmd := exec.Command(getBinaryPath(), "--provider", "azure")
	cmd.Env = append(os.Environ(), "GRANT_CONFIG="+filepath.Join(tempDir, "config.yaml"))
	cmd.Env = append(cmd.Env, "HOME="+tempDir) // Isolate from real credentials

	output, err := cmd.CombinedOutput()

	// Command should fail when not authenticated
	if err == nil {
		t.Errorf("Expected elevation to fail without authentication, but it succeeded.\nOutput: %s", output)
	}

	outputStr := string(output)

	// Should contain an error message about authentication or configuration
	errorKeywords := []string{"error", "Error", "failed", "Failed", "not found", "authenticate"}
	foundError := false
	for _, keyword := range errorKeywords {
		if strings.Contains(outputStr, keyword) {
			foundError = true
			break
		}
	}

	if !foundError {
		t.Errorf("Expected error output when not authenticated, got:\n%s", outputStr)
	}
}

func TestIntegration_StatusWithoutLogin(t *testing.T) {
	// Set a temporary config path to avoid interfering with real config
	tempDir := t.TempDir()

	cmd := exec.Command(getBinaryPath(), "status")
	cmd.Env = append(os.Environ(), "GRANT_CONFIG="+filepath.Join(tempDir, "config.yaml"))
	cmd.Env = append(cmd.Env, "HOME="+tempDir) // Isolate from real credentials

	output, err := cmd.CombinedOutput()

	// Status command should run but show not authenticated
	outputStr := string(output)

	// Should indicate not authenticated state
	if !strings.Contains(outputStr, "Not authenticated") && !strings.Contains(outputStr, "not authenticated") {
		// If it doesn't explicitly say "not authenticated", it should at least not show a username
		if strings.Contains(outputStr, "Username:") && err == nil {
			t.Errorf("Expected status to show 'not authenticated', but it showed a username.\nOutput: %s", outputStr)
		}
	}
}

func TestIntegration_FavoritesList(t *testing.T) {
	// Set a temporary config path to avoid interfering with real config
	tempDir := t.TempDir()

	cmd := exec.Command(getBinaryPath(), "favorites", "list")
	cmd.Env = append(os.Environ(), "GRANT_CONFIG="+filepath.Join(tempDir, "config.yaml"))

	output, err := cmd.CombinedOutput()

	// Command should succeed (empty list is valid)
	if err != nil && !strings.Contains(string(output), "No favorites") {
		t.Fatalf("Favorites list command failed unexpectedly: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)

	// Should either show "No favorites" or be empty
	if !strings.Contains(outputStr, "No favorites") && strings.TrimSpace(outputStr) != "" {
		// If it's not empty and doesn't say "No favorites", it should at least be valid output
		t.Logf("Favorites list output: %s", outputStr)
	}
}

func TestIntegration_FavoritesAddWithFlags(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	env := append(os.Environ(), "GRANT_CONFIG="+configPath)

	// Add a favorite via flags
	cmd := exec.Command(getBinaryPath(), "favorites", "add", "test-fav", "--target", "sub-123", "--role", "Contributor")
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("favorites add with flags failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "Added favorite") {
		t.Errorf("expected output to contain 'Added favorite', got:\n%s", outputStr)
	}

	// Verify via favorites list
	cmd = exec.Command(getBinaryPath(), "favorites", "list")
	cmd.Env = env
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("favorites list failed: %v\nOutput: %s", err, output)
	}

	outputStr = string(output)
	for _, want := range []string{"test-fav", "azure/sub-123/Contributor"} {
		if !strings.Contains(outputStr, want) {
			t.Errorf("favorites list missing %q, got:\n%s", want, outputStr)
		}
	}
}

func TestIntegration_InvalidCommand(t *testing.T) {
	cmd := exec.Command(getBinaryPath(), "nonexistent-command")
	output, err := cmd.CombinedOutput()

	// Should fail for invalid command
	if err == nil {
		t.Errorf("Expected invalid command to fail, but it succeeded.\nOutput: %s", output)
	}

	outputStr := string(output)

	// Should show an error or help message
	if !strings.Contains(outputStr, "unknown command") &&
	   !strings.Contains(outputStr, "Error:") &&
	   !strings.Contains(outputStr, "Usage:") {
		t.Errorf("Expected error for invalid command, got:\n%s", outputStr)
	}
}
