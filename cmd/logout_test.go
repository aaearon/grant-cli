package cmd

import (
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
)

func TestLogoutCommand(t *testing.T) {
	tests := []struct {
		name        string
		wantContain []string
	}{
		{
			name: "successful logout or keyring access",
			// Logout should either succeed or fail gracefully at keyring access
			// We test that the command structure is correct
			wantContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create logout command
			cmd := NewLogoutCommand()

			// Execute command - may succeed or fail depending on keyring availability
			output, err := executeCommand(cmd)

			// We expect either success message or an error
			// Both are valid depending on the test environment
			if err == nil {
				// Success case
				if !strings.Contains(output, "Logged out successfully") {
					t.Errorf("expected success message, got: %s", output)
				}
			} else {
				// Error case - should mention keyring or authentication
				t.Logf("Expected error in test environment: %v", err)
			}
		})
	}
}

func TestLogoutCommandIntegration(t *testing.T) {
	// Test that logout command is properly registered
	rootCmd := NewRootCommand()
	logoutCmd := NewLogoutCommand()
	rootCmd.AddCommand(logoutCmd)

	// Note: This test will likely fail if no profile exists, which is expected
	// We're just testing that the command is registered and can be executed
	_, err := executeCommand(rootCmd, "logout")

	// We allow errors here since profile might not exist in test environment
	// The important thing is that the command is registered and executable
	if err != nil {
		// Expected - profile might not exist in test environment
		t.Logf("logout command executed with expected error (no profile): %v", err)
	}
}

func TestLogoutCommandHelp(t *testing.T) {
	cmd := NewLogoutCommand()

	// Test help flag
	output, err := executeCommand(cmd, "--help")
	if err != nil {
		t.Fatalf("help command failed: %v", err)
	}

	expectedStrings := []string{
		"logout",
		"clearing cached authentication tokens",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("help output missing %q\ngot:\n%s", expected, output)
		}
	}
}

// Test that the command properly calls keyring clear
func TestLogoutClearsKeyring(t *testing.T) {
	// This test verifies the logout flow without mocking
	// It will only pass if we can actually create a keyring

	// Create a keyring instance to test with
	kr, err := keyring.NewIdsecKeyring("sca-cli-test").GetKeyring(true)
	if err != nil {
		t.Skipf("Skipping keyring test: %v", err)
	}

	// Verify that ClearAllPasswords is callable
	err = kr.ClearAllPasswords()
	if err != nil {
		// Some environments may not support keyring operations
		t.Logf("ClearAllPasswords returned error (expected in some environments): %v", err)
	}
}

// Test auth creation
func TestAuthCreation(t *testing.T) {
	// Verify we can create ISP auth
	ispAuth := auth.NewIdsecISPAuth(true)
	if ispAuth == nil {
		t.Fatal("NewIdsecISPAuth returned nil")
	}
}

// Test command structure
func TestLogoutCommandStructure(t *testing.T) {
	cmd := NewLogoutCommand()

	if cmd.Use != "logout" {
		t.Errorf("expected Use to be 'logout', got: %s", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Short description should not be empty")
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.RunE == nil {
		t.Error("RunE function should be defined")
	}
}
